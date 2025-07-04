# دليل تثبيت وتشغيل Qu1cksc0pe

## المتطلبات الأساسية

قبل البدء في تثبيت Qu1cksc0pe، تأكد من توفر المتطلبات التالية:

1. **بايثون Python**: الإصدار 3.10 أو أحدث
2. مساحة كافية على القرص الصلب (حوالي 500 ميجابايت)
3. اتصال بالإنترنت للتثبيت (مطلوب فقط أثناء التثبيت)

## خطوات التثبيت

### 1. إعداد المجلد

1. قم بفك ضغط الملف المضغوط الذي استلمته في المجلد المطلوب
2. افتح PowerShell كمسؤول (Run as Administrator)
3. انتقل إلى مجلد البرنامج:
```powershell
cd مسار_المجلد\Qu1cksc0pe
```

### 2. تشغيل سكربت الإعداد

```powershell
# قم بتشغيل سكربت الإعداد
.\setup.ps1
```

سيقوم السكربت تلقائياً بـ:
- التحقق من وجود Python وتثبيت المكتبات المطلوبة
- إنشاء مجلد `sc0pe_Base` في مجلد المستخدم
- تثبيت Jadx لتحليل تطبيقات Android
- تثبيت أداة `file` في Windows
- تثبيت أداة `strings`
- تثبيت pyOneNote
- تثبيت Android Platform Tools

### 3. تثبيت متطلبات واجهة المستخدم الرسومية (اختياري)

إذا كنت ترغب في استخدام واجهة المستخدم الرسومية:

```powershell
pip install -r gui_requirements.txt
```

## طريقة التشغيل

### تشغيل النسخة النصية

```powershell
python qu1cksc0pe.py -h  # لعرض المساعدة والخيارات المتاحة
```

### تشغيل واجهة المستخدم الرسومية

```powershell
python QuickScope_GUI.py
```

## حل المشاكل الشائعة

1. **مشكلة في تثبيت المكتبات**:
   ```powershell
   # حاول تحديث pip أولاً
   python -m pip install --upgrade pip
   # ثم أعد تثبيت المتطلبات
   pip install -r requirements.txt
   ```

2. **خطأ في الوصول إلى الأدوات**:
   - تأكد من تشغيل PowerShell بصلاحيات المسؤول
   - تأكد من وجود المجلد `sc0pe_Base` في مجلد المستخدم

3. **مشاكل مع أدوات Android**:
   - تأكد من تثبيت Android Platform Tools بشكل صحيح
   - تحقق من تكوين مسار ADB في ملف `Systems/Windows/windows.conf`

## ملاحظات هامة

- تأكد من تشغيل البرنامج بصلاحيات المسؤول للحصول على كامل الوظائف
- احتفظ بنسخة احتياطية من ملفات التكوين
- لا تقم بحذف أي ملفات من المجلد الرئيسي للبرنامج
- تأكد من عدم تغيير أسماء الملفات أو المجلدات

## الدعم الفني

في حالة وجود أي مشاكل:
1. تأكد من اتباع جميع خطوات التثبيت بدقة
2. تحقق من توافق نظام التشغيل مع المتطلبات
3. تواصل مع الدعم الفني المرفق مع البرنامج 