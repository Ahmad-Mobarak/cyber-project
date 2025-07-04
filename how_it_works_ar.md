# آلية عمل برنامج Qu1cksc0pe

<div dir="rtl">

## المقدمة 🚀

هذا المستند يشرح آلية عمل برنامج Qu1cksc0pe بالتفصيل من الناحية التقنية والبرمجية. تم إعداد هذا التوثيق خصيصاً للطلاب والمبتدئين في مجال تحليل البرمجيات الخبيثة والأمن السيبراني.

## الهيكل العام للبرنامج 🏗️

### 1. هيكل الملفات

البرنامج مبني بلغة Python ويستخدم هيكل ملفات منظم:

```
Qu1cksc0pe/
├── QuickScope_GUI.py     # الملف الرئيسي للتطبيق
├── gui/                  # حزمة واجهة المستخدم الرسومية
│   ├── home_tab.py       # الصفحة الرئيسية
│   ├── analyzer_tab.py   # تبويب التحليل الثابت
│   ├── dynamic_tab.py    # تبويب التحليل الديناميكي
│   ├── document_tab.py   # تبويب تحليل المستندات
│   ├── utils_tab.py      # تبويب الأدوات المساعدة
│   ├── settings_tab.py   # تبويب الإعدادات
│   └── style.py          # تعريفات الأنماط والألوان
├── icons/                # الأيقونات والصور
├── scripts/              # نصوص برمجية للتحليل
└── docs/                 # ملفات التوثيق
```

### 2. الأساس البرمجي

- **لغة البرمجة**: Python 3
- **إطار العمل للواجهة**: PyQt5
- **المكتبات الرئيسية المستخدمة**: 
  - `os`, `sys` للتعامل مع نظام التشغيل
  - `subprocess` لتنفيذ الأوامر الخارجية
  - `hashlib` لحساب التجزئات الرقمية
  - `datetime` للتعامل مع التاريخ والوقت
  - `PyQt5` لبناء واجهة المستخدم الرسومية

## تدفق العمل في البرنامج 🔄

### 1. بدء التشغيل

عند بدء تشغيل البرنامج، يحدث ما يلي:

1. يتم تنفيذ ملف `QuickScope_GUI.py`
2. يتم إنشاء كائن من فئة `QApplication`
3. يتم إنشاء كائن من فئة `MainWindow`
4. يتم إعداد البيئة وتهيئة المتغيرات
5. يتم إنشاء وعرض التبويبات المختلفة

```python
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
```

### 2. الصفحة الرئيسية (HomeTab)

تتكون الصفحة الرئيسية من عدة أجزاء:

1. **شريط الترحيب**: يعرض شعار البرنامج وعنوانه ووصفه
2. **الإجراءات السريعة**: أزرار للوصول السريع للوظائف الأساسية
3. **قسم الميزات**: يعرض الميزات الرئيسية للبرنامج
4. **الملفات الحديثة**: يعرض الملفات التي تم تحليلها مؤخراً

عند النقر على زر "تحليل ملف"، يتم استدعاء الدالة `select_file_for_analysis()` التي تعمل على:
- فتح مربع حوار لاختيار ملف
- حفظ مسار الملف المختار
- تبديل التبويب إلى تبويب التحليل
- بدء تحليل الملف

### 3. آلية التحليل الثابت

آلية التحليل الثابت تعمل كالتالي:

1. استلام مسار الملف المراد تحليله
2. تحديد نوع الملف (PE, ELF, PDF, الخ)
3. حساب التجزئات الرقمية (MD5, SHA1, SHA256)
4. استخراج النصوص (Strings) من الملف
5. تحليل الترويسات والشفرات البرمجية
6. البحث عن أنماط معروفة للبرمجيات الخبيثة
7. عرض النتائج في واجهة مستخدم منظمة

**مثال على آلية استخراج النصوص**:
```python
def extract_strings(file_path, min_length=4):
    strings_output = []
    
    # باستخدام أداة strings أو تنفيذ عملية استخراج مخصصة
    if sys.platform == "win32":
        cmd = f"strings.exe -{self.strings_param} {file_path}"
    else:
        cmd = f"strings -{self.strings_param} {file_path}"
    
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, _ = process.communicate()
    
    # معالجة المخرجات
    for line in output.decode('utf-8', errors='ignore').splitlines():
        if len(line) >= min_length:
            strings_output.append(line)
    
    return strings_output
```

### 4. آلية التحليل الديناميكي

تتضمن عملية التحليل الديناميكي:

1. إنشاء بيئة معزولة للتنفيذ (Sandbox)
2. تنفيذ البرنامج المراد تحليله في البيئة المعزولة
3. مراقبة:
   - استدعاءات النظام
   - اتصالات الشبكة
   - عمليات القراءة والكتابة في الملفات
   - تعديلات سجل النظام
4. تسجيل كافة النشاطات وتحليلها
5. إنشاء تقرير مفصل بالنتائج

### 5. تحليل المستندات

يختص هذا القسم بتحليل المستندات مثل ملفات PDF وOffice:

1. استخراج المحتوى المضمن في المستند
2. تحليل الماكروز والتعليمات البرمجية
3. الكشف عن روابط خارجية مشبوهة
4. تحليل الملفات المضمنة أو الكائنات المخفية
5. التعرف على تقنيات الإخفاء المستخدمة

### 6. الأدوات المساعدة

تشمل مجموعة من الأدوات المفيدة:

1. **وحدة التحكم**: واجهة أوامر لتنفيذ عمليات متقدمة
2. **محلل الشبكة**: لمراقبة وتحليل حركة الشبكة
3. **مدير البصمات**: لإدارة وتحديث قاعدة بيانات البصمات
4. **مولد التقارير**: لإنشاء تقارير متنوعة بالنتائج

## تفاصيل تنفيذ الواجهة الرسومية 🎨

### 1. نظام التبويبات

تستخدم واجهة البرنامج نظام تبويبات `QTabWidget` للتنقل بين الوظائف المختلفة:

```python
# إنشاء التبويبات
self.tabs = QTabWidget()

# إضافة التبويبات
self.home_tab = HomeTab(self)
self.analyzer_tab = AnalyzerTab(self)
self.dynamic_tab = DynamicTab(self)
self.document_tab = DocumentTab(self)
self.utils_tab = UtilsTab(self)
self.settings_tab = SettingsTab(self)

# إضافة التبويبات إلى واجهة المستخدم
self.tabs.addTab(self.home_tab, "Home")
self.tabs.addTab(self.analyzer_tab, "Static Analysis")
# ... إلخ
```

### 2. تصميم العناصر المخصصة

البرنامج يستخدم عناصر واجهة مخصصة مثل:

- **CardWidget**: بطاقات ذات زوايا مدورة وتأثيرات حركية
- **ActionButton**: أزرار مخصصة تحتوي على أيقونات ونص

```python
class CardWidget(QFrame):
    """بطاقة عصرية ذات زوايا مدورة وتأثيرات عند التحويم"""
    def __init__(self, title, description, icon_name=None, parent=None):
        super().__init__(parent)
        self.setObjectName("card_widget")
        # ... تفاصيل التنفيذ
```

## آلية تحليل الملفات 🔍

### 1. التعرف على نوع الملف

يتم تحديد نوع الملف باستخدام:

- **فحص السحري (Magic Bytes)**: قراءة البايتات الأولى من الملف
- **فحص الامتداد**: التحقق من امتداد الملف
- **التحليل الهيكلي**: فحص بنية الملف الداخلية

### 2. تحليل الملفات التنفيذية (PE/ELF)

الخطوات الرئيسية في تحليل الملفات التنفيذية:

1. **قراءة الترويسة**: استخراج معلومات مثل تاريخ التجميع، المجمع المستخدم، إلخ
2. **تحليل الأقسام والقطاعات**: فحص أقسام الملف وخصائصها
3. **فحص الاستيراد والتصدير**: تحليل المكتبات والدوال المستوردة/المصدرة
4. **تحليل الموارد**: فحص الموارد المضمنة (أيقونات، صور، إلخ)
5. **الكشف عن التشويش وحماية الملف**: تحديد تقنيات التشويش المستخدمة

### 3. المقارنة مع قاعدة البيانات

يتم مقارنة نتائج التحليل مع:

- قواعد YARA المخصصة لكشف الأنماط المعروفة
- قاعدة بيانات البصمات للبرمجيات الخبيثة المعروفة
- قواعد السلوك المشبوه

## تطوير وتوسيع البرنامج 🛠️

### 1. إضافة قواعد YARA جديدة

لإضافة قواعد كشف جديدة:

1. قم بإنشاء ملف YARA جديد في مجلد `rules/`
2. اكتب قاعدة تحدد النمط المراد الكشف عنه
3. قم بتحديث قائمة القواعد المستخدمة في البرنامج

### 2. إضافة وحدات تحليل جديدة

لإضافة نوع جديد من التحليل:

1. قم بإنشاء ملف Python جديد في المجلد المناسب
2. قم بتنفيذ فئة التحليل المطلوبة
3. قم بتكامل الفئة الجديدة مع واجهة المستخدم

### 3. تخصيص التقارير

يمكن تخصيص شكل ومحتوى التقارير من خلال:

1. تعديل قوالب التقارير في مجلد `templates/`
2. تغيير تنسيق الإخراج (HTML، PDF، JSON، إلخ)
3. إضافة أقسام جديدة للتقارير

## معالجة الأخطاء واستكشافها 🔧

### 1. آليات التسجيل

يستخدم البرنامج آليات تسجيل متعددة:

```python
# مثال على آلية التسجيل
def log_error(self, message):
    # تسجيل الخطأ في ملف
    with open("error.log", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] ERROR: {message}\n")
    
    # عرض رسالة للمستخدم
    self.status_bar.showMessage(f"Error: {message}", 5000)
```

### 2. التعامل مع الاستثناءات

يتم التعامل مع الأخطاء المحتملة باستخدام بلوكات try/except:

```python
try:
    # محاولة تنفيذ العملية
    result = self.analyze_file(file_path)
except FileNotFoundError:
    self.log_error(f"الملف غير موجود: {file_path}")
except PermissionError:
    self.log_error("ليس لديك صلاحيات كافية لقراءة الملف")
except Exception as e:
    self.log_error(f"خطأ غير متوقع: {str(e)}")
```

## الخلاصة 📝

برنامج Qu1cksc0pe هو أداة متطورة ومرنة لتحليل البرمجيات الخبيثة، تم تصميمه باستخدام تقنيات برمجية حديثة. يوفر البرنامج واجهة مستخدم سهلة الاستخدام مع قدرات تحليلية قوية، مما يجعله أداة قيمة للباحثين في مجال الأمن السيبراني والطلاب المهتمين بتعلم تقنيات تحليل البرمجيات الخبيثة.

هذا التوثيق يهدف إلى تقديم فهم عميق لآلية عمل البرنامج، مما يسمح للمستخدمين بالاستفادة الكاملة من قدراته وإمكانية تخصيصه وتوسيعه لتلبية احتياجاتهم الخاصة.

</div> 