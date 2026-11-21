import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct Finding: Decodable, Identifiable {
    let id, code, category, severity, title, detail, action, source, confidence: String
}
struct Kext: Decodable, Identifiable {
    var id: String { path }
    let name, path, version: String
    let enabled, exists: Bool
}
struct Release: Decodable, Identifiable {
    var id: String { name }
    let name, installed, latest, url, note: String
}
struct Report: Decodable {
    let version, created: String
    let findings: [Finding]
    let kexts: [Kext]
    let releases: [Release]
}
struct EngineResult { let data: Data; let status: Int32 }
enum Engine {
    static func run(_ args: [String]) throws -> EngineResult {
        let fm = FileManager.default
        let python = ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"].first { fm.isExecutableFile(atPath: $0) }
        guard let python else { throw NSError(domain: "SYS-002", code: 2, userInfo: [NSLocalizedDescriptionKey: "Python 3 مطلوب. ثبّت Python 3.9 أو أحدث ثم أعد المحاولة."]) }
        guard let script = Bundle.main.url(forResource: "probe", withExtension: "py") else { throw NSError(domain: "SYS-003", code: 3) }
        let out = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        fm.createFile(atPath: out.path, contents: nil)
        let handle = try FileHandle(forWritingTo: out)
        defer { try? handle.close(); try? fm.removeItem(at: out) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = [script.path] + args
        process.standardOutput = handle
        process.standardError = handle
        try process.run(); process.waitUntilExit()
        return EngineResult(data: try Data(contentsOf: out), status: process.terminationStatus)
    }
}
@MainActor final class Model: ObservableObject {
    @Published var report: Report?
    @Published var raw = Data()
    @Published var inventory = "ابدأ الفحص لعرض المكونات التي يكشفها macOS."
    @Published var busy = false
    @Published var status = "جاهز للفحص • لا توجد تغييرات على النظام"
    @Published var efi: URL?
    @Published var workspace: URL?
    @Published var notice = ""
    @Published var showNotice = false
    func notify(_ message: String) { notice = message; showNotice = true }
    func task(_ args: [String], completion: @escaping (Data) throws -> Void) {
        guard !busy else { return }
        busy = true; status = "جارٍ العمل… قد يستغرق الفحص عدة دقائق"
        Task {
            do {
                let result = try await Task.detached(priority: .userInitiated) { try Engine.run(args) }.value
                guard result.status == 0 else { throw NSError(domain: "ENGINE", code: Int(result.status), userInfo: [NSLocalizedDescriptionKey: String(decoding: result.data, as: UTF8.self)]) }
                try completion(result.data)
                status = "اكتملت العملية • \(Date().formatted(date: .omitted, time: .shortened))"
            } catch { status = "تعذرت العملية"; notify(error.localizedDescription) }
            busy = false
        }
    }
    func scan(updates: Bool) {
        var args = ["scan"]
        if let efi { args += ["--efi", efi.path] }
        if updates { args += ["--updates"] }
        task(args) { [self] data in
            let parsed = try JSONDecoder().decode(Report.self, from: data)
            let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let pretty = try JSONSerialization.data(withJSONObject: object?["snapshot"] ?? [:], options: [.prettyPrinted, .sortedKeys])
            report = parsed; raw = data; inventory = String(decoding: pretty, as: UTF8.self)
        }
    }
    func chooseEFI() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.message = "اختر EFI أو OC أو المجلد الذي يحتوي EFI. لا يتم تركيب الأقراص تلقائياً."
        if panel.runModal() == .OK { efi = panel.url; report = nil; raw = Data() }
    }
    func createWorkspace() {
        guard let efi else { notify("اختر EFI أولاً."); return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = "Noor-Workspace-\(Int(Date().timeIntervalSince1970))"
        panel.message = "مجلد جديد لنسخة احتياطية ونسخة مرشحة؛ لن تتغير EFI الأصلية."
        if panel.runModal() == .OK, let url = panel.url {
            task(["workspace", efi.path, url.path]) { [self] _ in workspace = url; notify("تم إنشاء Backup وCandidate والتحقق من تطابق بصمات الملفات.") }
        }
    }
    func patch(_ layout: Int) {
        guard let workspace else { return }
        task(["layout", workspace.path, String(layout)]) { [self] data in notify(String(decoding: data, as: UTF8.self)) }
    }
    func export() {
        guard !raw.isEmpty else { return }
        let panel = NSSavePanel(); panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = "Noor-Diagnostic.json"
        panel.message = "التقرير يتضمن تفاصيل جهازك؛ راجعه قبل مشاركته. تُحذف مفاتيح هوية معروفة لكن الإخفاء ليس ضماناً شاملاً."
        if panel.runModal() == .OK, let url = panel.url {
            do { try raw.write(to: url, options: .atomic) } catch { notify(error.localizedDescription) }
        }
    }
}
struct IssueCard: View {
    let item: Finding
    var color: Color { item.severity == "error" ? .red : item.severity == "warning" ? .orange : .blue }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: item.severity == "error" ? "exclamationmark.octagon.fill" : "info.circle.fill").foregroundStyle(color)
                Text(item.title).font(.headline)
                Spacer()
                Text(item.code).font(.system(.caption, design: .monospaced)).padding(6).background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
            }
            Text(item.detail).foregroundStyle(.secondary)
            Text(item.action).font(.callout)
            HStack {
                Text(item.confidence == "manual" ? "يحتاج تجربة فعلية" : item.confidence == "likely" ? "استنتاج يحتاج تحقق" : "قاعدة أو ملاحظة مثبتة").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if let url = URL(string: item.source) { Link("التوثيق الأصلي ↗", destination: url).font(.caption) }
            }
        }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(.primary.opacity(0.06)))
    }
}
struct ContentView: View {
    @StateObject private var model = Model()
    @State private var page = "نظرة عامة"
    @State private var query = ""
    @State private var updates = false
    @State private var layout = ""
    @State private var confirm = false
    let pages = [("نظرة عامة", "square.grid.2x2"), ("المكونات", "cpu"), ("التشخيص", "stethoscope"), ("التعريفات", "shippingbox"), ("مساحة EFI", "externaldrive"), ("عن البرنامج", "info.circle")]
    var issues: [Finding] { (model.report?.findings ?? []).filter { query.isEmpty || ($0.title + $0.code + $0.category + $0.detail).localizedCaseInsensitiveContains(query) } }
    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 10) {
                    Image(systemName: "waveform.path.ecg").font(.title).foregroundStyle(.blue)
                    VStack(alignment: .leading) { Text("Noor Probe").font(.headline); Text("OPENCORE DIAGNOSTICS").font(.system(size: 8, weight: .semibold)).foregroundStyle(.secondary) }
                }.padding(.horizontal, 12).padding(.top, 22)
                List(selection: $page) {
                    ForEach(pages, id: \.0) { entry in Label(entry.0, systemImage: entry.1).tag(entry.0).padding(.vertical, 5) }
                }.listStyle(.sidebar)
                VStack(alignment: .leading, spacing: 8) {
                    Label("الإصدار 1.0 • تجريبي", systemImage: "circle.dotted")
                    Text("فحص محلي. المقارنة عبر الإنترنت اختيارية.")
                }.font(.caption).foregroundStyle(.secondary).padding(16)
            }.navigationSplitViewColumnWidth(min: 210, ideal: 230)
        } detail: {
            VStack(spacing: 0) {
                HStack {
                    VStack(alignment: .leading, spacing: 5) { Text(page).font(.title2.bold()); Text(model.status).font(.caption).foregroundStyle(.secondary) }
                    Spacer()
                    if model.busy { ProgressView().controlSize(.small) }
                    Button { model.scan(updates: updates) } label: { Label("فحص الجهاز", systemImage: "waveform.path.ecg") }.buttonStyle(.borderedProminent).disabled(model.busy)
                }.padding(24)
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) { content }.padding(28).frame(maxWidth: 1100, alignment: .leading).frame(maxWidth: .infinity)
                }.background(Color(nsColor: .windowBackgroundColor))
            }
        }.frame(minWidth: 940, minHeight: 680)
        .toolbar { ToolbarItemGroup { Button("اختيار EFI", systemImage: "folder") { model.chooseEFI() }.disabled(model.busy); Button("تصدير", systemImage: "square.and.arrow.up") { model.export() }.disabled(model.raw.isEmpty || model.busy) } }
        .alert("Noor Probe", isPresented: $model.showNotice) { Button("حسناً", role: .cancel) {} } message: { Text(model.notice) }
        .confirmationDialog("تأكيد تعديل النسخة المرشحة", isPresented: $confirm, titleVisibility: .visible) {
            Button("تطبيق alcid=\(layout) على Candidate") { if let value = Int(layout) { model.patch(value) } }
            Button("إلغاء", role: .cancel) {}
        } message: { Text("سيتم استبدال أي alcid في boot-args بالقيمة \(layout) داخل Candidate فقط. قيمة غير مطابقة للـCodec قد لا تحل الصوت. Backup والأصل لا يتغيران. راجع last-change.json بعد العملية.") }
    }
    @ViewBuilder var content: some View {
        switch page {
        case "نظرة عامة": overview
        case "المكونات":
            Text("المكونات التي يكشفها النظام").font(.title.bold())
            Text("يشمل المعالج والذاكرة والشاشة وPCI والشبكة والصوت وUSB والتخزين والطاقة. أجهزة أخفاها BIOS أو ACPI قد لا تظهر، واسم SMBIOS قد يكون مموهاً.").foregroundStyle(.secondary)
            Text(model.inventory).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(20).background(.background, in: RoundedRectangle(cornerRadius: 14)).environment(\.layoutDirection, .leftToRight)
        case "التشخيص":
            TextField("ابحث بالكود أو المشكلة أو المكوّن", text: $query).textFieldStyle(.roundedBorder)
            if model.report == nil { empty }
            ForEach(issues) { IssueCard(item: $0) }
        case "التعريفات": drivers
        case "مساحة EFI": workspaceView
        default:
            Text("مصمّم لفهم جهازك.").font(.largeTitle.bold())
            Text("Noor Probe 1.0\nتطبيق مستقل غير تابع لـApple. واجهة macOS أصلية باستخدام SwiftUI.").foregroundStyle(.secondary)
            Text("لا يثبت البرنامج تعريفات ولا يغيّر قسم الإقلاع. إصدار التجربة يجمع الأدلة ويفحص مراجع EFI ويقارن إصدارات معروفة وينشئ نسخاً منفصلة ويعدّل alcid في النسخة المرشحة فقط. لا يتضمن إصلاح ACPI تلقائياً أو دعم كل قطعة أو ضمان توافق تحديثات.")
            Text("التقرير محلي ولا يرسل تلقائياً. خيار التحديثات يتصل بـGitHub لاستعلام إصدارات المشاريع. لا يتم تنزيل برامج خارجية أو تشغيلها بالنيابة عنك.")
            Link("دليل OpenCore", destination: URL(string: "https://dortania.github.io/OpenCore-Install-Guide/")!)
        }
    }
    var empty: some View { Label("ابدأ فحص الجهاز لعرض النتائج الفعلية.", systemImage: "magnifyingglass").foregroundStyle(.secondary).padding(30) }
    var overview: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack(spacing: 24) {
                Image(systemName: "laptopcomputer").font(.system(size: 70, weight: .ultraLight)).foregroundStyle(.blue.gradient).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 10) { Text("جهازك، بصورة أوضح.").font(.system(size: 32, weight: .bold)); Text("افهم المكونات. راجع التوافق. اختبر الحل بثقة.").font(.title3).foregroundStyle(.secondary) }
            }.padding(28).frame(maxWidth: .infinity, alignment: .leading).background(.blue.opacity(0.06), in: RoundedRectangle(cornerRadius: 24))
            HStack(spacing: 16) {
                metric("ملاحظات الفحص", "\(model.report?.findings.count ?? 0)", "stethoscope", .blue)
                metric("أخطاء مؤكدة في الملفات", "\(model.report?.findings.filter { $0.severity == "error" }.count ?? 0)", "exclamationmark.triangle", .orange)
                metric("تعريفات EFI", "\(model.report?.kexts.count ?? 0)", "shippingbox", .purple)
            }
            GroupBox("مصدر EFI") {
                HStack { Text(model.efi?.path ?? "لم يتم الاختيار • الفحص متاح بدونه").textSelection(.enabled); Spacer(); Button("اختيار المجلد") { model.chooseEFI() }.disabled(model.busy) }.padding(10)
            }
            Toggle("استعلام إصدارات المشاريع من GitHub أثناء الفحص", isOn: $updates)
            Text("التحديث الأحدث ليس بالضرورة الأنسب. لا نحكم على توافق قطعة من اسمها فقط، ولا نعتبر غياب البيانات دليلاً على عدم الدعم.").font(.callout).foregroundStyle(.secondary)
            if let report = model.report { ForEach(Array(report.findings.filter { $0.severity == "error" }.prefix(3))) { IssueCard(item: $0) } } else { empty }
        }
    }
    func metric(_ title: String, _ value: String, _ symbol: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 12) { Image(systemName: symbol).foregroundStyle(color); Text(value).font(.largeTitle.bold()); Text(title).font(.caption).foregroundStyle(.secondary) }.frame(maxWidth: .infinity, alignment: .leading).padding(20).background(.background, in: RoundedRectangle(cornerRadius: 16))
    }
    var drivers: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("تعريفات الإقلاع").font(.title.bold())
            if model.report == nil { empty }
            ForEach(model.report?.kexts ?? []) { k in
                HStack { Image(systemName: k.exists ? "shippingbox.fill" : "exclamationmark.triangle.fill").foregroundStyle(k.exists ? Color.blue : Color.red); VStack(alignment: .leading) { Text(k.name).font(.headline); Text(k.version).font(.caption).foregroundStyle(.secondary) }; Spacer(); Text(k.enabled ? "مفعّل في config" : "معطّل").font(.caption) }.padding(16).background(.background, in: RoundedRectangle(cornerRadius: 12))
            }
            Text("مقارنة الإصدارات").font(.title2.bold())
            if model.report?.releases.isEmpty != false { Text("فعّل استعلام GitHub وأعد الفحص. هذه مقارنة إصدارات، وليست شهادة توافق.").foregroundStyle(.secondary) }
            ForEach(model.report?.releases ?? []) { r in
                GroupBox(r.name) { VStack(alignment: .leading, spacing: 8) { Text("الموجود: \(r.installed)  •  إصدار المصدر: \(r.latest)"); Text(r.note).font(.caption).foregroundStyle(.secondary); if let url = URL(string: r.url) { Link("مراجعة الإصدار والملاحظات ↗", destination: url) } }.frame(maxWidth: .infinity, alignment: .leading).padding(8) }
            }
        }
    }
    var workspaceView: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("مساحة آمنة لتجربة EFI").font(.title.bold())
            Text("ننسخ المصدر إلى Backup وCandidate، ونقارن SHA-256 لكل ملف. لا يُركّب البرنامج قسم EFI ولا يكتب عليه. اختبر Candidate على USB قابل للإقلاع بعد ocvalidate.").foregroundStyle(.secondary)
            Button("إنشاء نسخة احتياطية ومساحة عمل", systemImage: "externaldrive.badge.plus") { model.createWorkspace() }.disabled(model.efi == nil || model.busy)
            if let work = model.workspace {
                GroupBox("مساحة العمل الحالية") { HStack { Text(work.path).textSelection(.enabled); Spacer(); Button("فتح") { NSWorkspace.shared.open(work) } }.padding(10) }
                GroupBox("تعديل صوت تجريبي • AppleALC") {
                    VStack(alignment: .leading, spacing: 14) {
                        Text("أدخل layout-id الذي طابقته مع Codec جهازك. لا يختاره البرنامج بالتخمين.")
                        TextField("layout-id: 1…255", text: $layout).textFieldStyle(.roundedBorder).frame(width: 230)
                        Text("المعاينة: إزالة alcid القديم من boot-args وإضافة alcid=\(layout.isEmpty ? "…" : layout) داخل Candidate فقط.").font(.caption).foregroundStyle(.secondary)
                        Button("مراجعة وتأكيد التعديل") { confirm = true }.disabled(model.busy || !(1...255).contains(Int(layout) ?? 0))
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
            }
            Text("للتراجع عن التجربة: احتفظ بـBackup كما هي. لا يوجد زر تثبيت مباشر على EFI في هذا الإصدار. أدوات التحقق الخارجية وروابطها موضحة في Docs/TOOLS.md.").font(.callout).foregroundStyle(.secondary)
        }
    }
}
@main struct NoorProbeApp: App {
    var body: some Scene { WindowGroup { ContentView() }.windowStyle(.hiddenTitleBar).defaultSize(width: 1120, height: 760) }
}
