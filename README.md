<!-- PhoneGuard README -->

<div align="center">

```
  ██████╗ ██╗  ██╗ ██████╗ ███╗  ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██╔═══██╗████╗ ██║██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║   ██║██╔██╗██║█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║██║   ██║██║╚████║██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║  ██║╚██████╔╝██║ ╚███║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

# PhoneGuard v5.0
### ⚡ Android Adware & Malware Scanner
### ماسح البرمجيات الخبيثة والإعلانات لأندرويد

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-5.0-purple?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-green?style=flat-square)
![ADB](https://img.shields.io/badge/ADB-Required-orange?style=flat-square&logo=android&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-teal?style=flat-square)
![Lang](https://img.shields.io/badge/Language-EN%20%7C%20AR-red?style=flat-square)

</div>

---

## 📖 About · نبذة عن الأداة

| 🇬🇧 English | 🇸🇦 العربية |
|---|---|
| PhoneGuard is a powerful Python CLI tool that connects to your Android device via ADB to detect adware, malware, suspicious permissions, and harmful background processes — then helps you remove them instantly. | PhoneGuard هي أداة Python قوية تعمل من سطر الأوامر، تتصل بجهازك الأندرويد عبر ADB للكشف عن برامج الإعلانات والبرمجيات الخبيثة والصلاحيات المشبوهة والعمليات الضارة في الخلفية، وتساعدك على إزالتها فوراً. |

---

## ✨ Features · المميزات

| # | 🇬🇧 Feature | 🇸🇦 الميزة | Description · الوصف |
|---|---|---|---|
| 1 | 🔍 Smart Full Scan | فحص ذكي شامل | Fast & accurate — recommended for daily use |
| 2 | 🧬 Deep Behavioral Scan | فحص سلوكي عميق | Behavioral pattern analysis while app is running |
| 3 | 🌐 Network Traffic Analysis | تحليل حركة الشبكة | Detects connections to known ad servers |
| 4 | 📡 Real-Time Ad Monitor | مراقبة الإعلانات لحظياً | Live 60-second passive monitoring |
| 5 | 🔄 Background Apps Manager | إدارة تطبيقات الخلفية | Kill or uninstall background processes |
| 6 | 🔓 High Permissions Apps | تطبيقات الصلاحيات العالية | Detect & revoke dangerous permissions |
| 7 | 🗑️ Smart Uninstall | إزالة ذكية للتطبيقات | Remove apps by name, number, or partial match |
| 8 | 📄 Scan Reports | تقارير الفحص | Auto-saved Markdown reports with full details |
| 9 | 🌍 Bilingual UI | واجهة ثنائية اللغة | Full English & Arabic interface support |

---

## 🚦 Risk Levels · مستويات الخطر

Every scanned app receives a risk score from **0 to 100**:

| Level | Score | Meaning · المعنى |
|---|---|---|
| 🔴 **CRITICAL** · خطير | 75–100 | Immediate action required — immediate uninstall recommended |
| 🟠 **HIGH** · مرتفع | 50–74 | Highly suspicious — strong indicators of malicious behavior |
| 🟡 **MEDIUM** · متوسط | 25–49 | Suspicious patterns found — review recommended |
| 🟢 **LOW** · منخفض | 0–24 | Minimal risk — likely safe |

### What PhoneGuard detects · ما تكشفه الأداة

- ✅ Dangerous permissions (CAMERA, RECORD_AUDIO, SEND_SMS, READ_CONTACTS, etc.)
- ✅ Known ad libraries embedded in apps
- ✅ Boot receivers (apps that auto-start with system)
- ✅ Accessibility service abuse
- ✅ Behavioral patterns via Quark Engine
- ✅ Connections to known ad/malware servers

---

## ⚙️ Requirements · المتطلبات

| Requirement | Details | المتطلب |
|---|---|---|
| 🐍 Python | 3.8 or newer | بايثون 3.8 أو أحدث |
| 📱 ADB | Android Debug Bridge installed | ADB مثبت |
| 🎨 rich | `pip3 install rich` | مكتبة rich |
| 🔓 USB Debugging | Enabled on Android device | تصحيح USB مفعّل |
| 💻 OS | Windows / macOS / Linux | أي نظام تشغيل |

---

## 🚀 Installation · التثبيت

### Step 1 — Clone the repository · استنساخ المستودع

```bash
git clone https://github.com/ibrahimmustafacv/PhoneGuard
cd PhoneGuard
```

### Step 2 — Install dependencies · تثبيت المكتبات

```bash
pip3 install -r requirements.txt
```

### Step 3 — Enable USB Debugging on your Android device

```
Settings → Developer Options → USB Debugging → Enable
الإعدادات ← خيارات المطورين ← تصحيح USB ← تفعيل
```

> If Developer Options is not visible:  
> **Settings → About Phone → tap "Build Number" 7 times**  
> الإعدادات ← حول الهاتف ← اضغط "رقم البناء" 7 مرات

### Step 4 — Connect your phone via USB and run

```bash
python3 main.py
```

---

## 🖥️ Main Menu · القائمة الرئيسية

```
╔══════════════════════════════════════════════════════════════════╗
║                        MAIN MENU                                 ║
╠══════════════════════════════════════════════════════════════════╣
║  [1]  🔍  Smart Full Scan          فحص ذكي شامل                 ║
║  [2]  🧬  Deep Behavioral Scan     فحص سلوكي عميق               ║
║  [3]  🌐  Network Traffic Analysis  تحليل حركة الشبكة            ║
║  [4]  📄  View Last Report         عرض آخر تقرير                 ║
║  [5]  🗑️  Uninstall App            إزالة تطبيق                   ║
║  [6]  📡  Real-Time Ad Monitor     مراقبة الإعلانات لحظياً       ║
║  [7]  🔄  Background Apps Manager  إدارة التطبيقات في الخلفية    ║
║  [8]  🔓  High Permissions Apps    التطبيقات ذات الصلاحيات العالية║
║  [9]  🚪  Exit                     خروج                          ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 📁 Project Structure · هيكل المشروع

```
PhoneGuard/
├── main.py           # Entry point — واجهة المستخدم الرئيسية
├── adb_controller.py # ADB communication layer
├── analyzer.py       # Malware analysis engine
├── report.py         # Report generation module
├── requirements.txt  # Python dependencies
└── logs/             # Auto-generated scan reports (Markdown)
```

---

## 💡 Usage Tips · نصائح الاستخدام

| 🇬🇧 English | 🇸🇦 العربية |
|---|---|
| Start with **Smart Full Scan** for a quick overview | ابدأ بـ **الفحص الذكي الشامل** للحصول على نظرة سريعة |
| Use **Real-Time Ad Monitor** while browsing or using apps | استخدم **مراقبة الإعلانات** أثناء التصفح |
| Check **High Permissions Apps** regularly | تفقّد **تطبيقات الصلاحيات العالية** بانتظام |
| Reports are saved in the `logs/` folder | التقارير تُحفظ تلقائياً في مجلد `logs/` |
| You can uninstall by number, name, or partial match | يمكنك الإزالة برقم التطبيق أو الاسم أو جزء منه |

---

## 🤝 Contributing · المساهمة

Contributions, issues, and feature requests are welcome!  
المساهمات والتقارير وطلبات الميزات مرحب بها!

1. Fork the repo · قم بعمل Fork للمستودع
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request · افتح Pull Request

---

## 📜 License · الترخيص

Distributed under the **MIT License**. See `LICENSE` for more information.  
موزع تحت رخصة **MIT**. راجع ملف `LICENSE` للمزيد.

---

<div align="center">

## 👨‍💻 Developer · المطور

**Ibrahim Mustafa · إبراهيم مصطفى**

[![GitHub](https://img.shields.io/badge/GitHub-ibrahimmustafacv-181717?style=flat-square&logo=github)](https://github.com/ibrahimmustafacv)

---

*Made with ❤️ and Python · صُنع بالشغف والبايثون*

**⭐ If PhoneGuard helped you, please star the repo! · إذا أفادتك الأداة، لا تنسَ النجمة! ⭐**

👋 **Stay secure! · ابقَ آمناً!**

</div>
