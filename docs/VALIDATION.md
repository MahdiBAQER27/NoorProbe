# Validation record — 2026-11-17 — 1.1

Environment: Linux, Python 3.12, Node.js. No Apple SDK or macOS runtime.

Executed successfully:
- `python3 -m unittest discover -s NoorProbe/tests -v`: 31 distinct tests.
- `node NoorProbe/tests/test_ui_logic.cjs`: six page routes, editor payload, import payload, HTML escaping with minimal DOM stubs. No native bridge or layout validation.
- `node --check NoorProbe/App/main.js`: JXA JavaScript syntax only. ObjC bindings cannot run on Linux.
- Python compilation and shell syntax checks.
- Archive structure, plist metadata, executable mode bits, packaged resource checks.

Engine cases include: root resolution, conflict and missing file diagnosis, dependency ordering/cycles, import Kext/AML/EFI registration, overwrite gate, rollback on invalid import, invalid XML rejection, config edits and undo, immutable original and Backup, checkpoint tampering rejection, workspace lock, validator-version match/mismatch, traversal and symlink rejection, known-key redaction, incomplete probe reporting. External validator tests use a harmless fixture shell script, not real ocvalidate.

A Playwright render attempt could not launch Chromium due to runtime socket restrictions. No screenshot of the actual running app or rendered UI was produced. The conversation image is generated design artwork, not a runtime screenshot.

Not executed: opening the .app in Finder, LaunchServices handling, JXA/Cocoa bridge execution, WKWebView native callbacks, live hardware probes, macOS Python discovery, real ocvalidate, real EFI boot or audio/network/display tests, VoiceOver and dark/RTL layout review.

Packaging: executable script-based .app using system osascript/JXA and local AppKit/WebKit; Python 3.9+ dependency. Not compiled Swift or a signed/notarized binary. .app packaging is complete as an artifact; runtime success is unverified.

## 1.2 update
43 distinct Python tests now pass. New tests cover PCI IDs and child-device attribution, recognized-but-inactive and active-but-not-default NICs, EFI list filtering, disk identifier validation, GitHub repo and redirect validation, ZIP traversal/symlink rejection, root kext enumeration, and digest mismatch cleanup. UI logic routes extended to nine. New macOS APIs and network downloads remain runtime-untested; downloader tests use mocks. Packaging includes advanced.py. No actual EFI was mounted or changed in this environment.
