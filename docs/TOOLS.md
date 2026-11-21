# الأدوات الأصلية والتوافق

لا يتم تنزيل أو تضمين كود خارجي آلياً. يمكن اختيار ocvalidate المحلي وتشغيله بعد تأكيد صريح داخل الواجهة؛ يجب أن يكون من المصدر الرسمي. لا نستخدم أدوات تغيّر EFI بصمت.

| الأداة | المصدر | الاستخدام |
|---|---|---|
| OpenCore + ocvalidate | https://github.com/acidanthera/OpenCorePkg/releases | خذ ocvalidate من حزمة نفس إصدار OpenCore المستخدم |
| Lilu | https://github.com/acidanthera/Lilu | اعتماد إضافات الصوت والشاشة |
| AppleALC | https://github.com/acidanthera/AppleALC/wiki/Installation-and-usage | مطابقة Codec وlayout-id |
| WhateverGreen | https://github.com/acidanthera/WhateverGreen | توثيق تعديلات الرسوم حسب المعالج والنظام |
| Intel Wi-Fi | https://openintelwireless.github.io/itlwm/Installation.html | لا تجمع itlwm وAirportItlwm؛ مطابقة النسخة مطلوبة |
| HeliPort | https://github.com/OpenIntelWireless/HeliPort | واجهة اتصال itlwm، تُثبّت يدوياً بعد مراجعة المشروع |
| VirtualSMC | https://github.com/acidanthera/VirtualSMC | SMC وإضافاته |
| OpenCore guide | https://dortania.github.io/OpenCore-Install-Guide/ | المكونات والقيود والفحص والتثبيت |

## ocvalidate

راجع تعليمات الحزمة: https://github.com/acidanthera/OpenCorePkg/tree/master/Utilities/ocvalidate

شغّل نسخة الأداة المطابقة لإصدار OpenCore، من Terminal (استبدل المسارات):

```bash
/path/to/ocvalidate --version
/path/to/ocvalidate /path/to/workspace/Candidate/OC/config.plist
```

إذا المصدر كان OC مباشرة يكون مسار المرشح Candidate/config.plist. لا تعتبر نجاح الفحص ضماناً لصحة ACPI أو توافق العتاد. لا تخلط إصدار الأداة مع إصدار OpenCore مختلف.

## لماذا لا نضمّن حزمة تعريفات عشوائية؟

كل kext له متطلبات ومصفوفة إصدارات وترخيص. دمج ملفات بلا تحديد جهاز/نظام قد يمنع الإقلاع. هذا الإصدار يدمج أدوات Apple المحلية ويفحص ملفاتك، ويعرض المصادر الأصلية للتحديثات. تضمين أدوات خارجية وتثبيت التعريفات يتطلبان تطويراً لاحقاً واختبارات macOS حقيقية، وليس ميزة منفذة حالياً.
