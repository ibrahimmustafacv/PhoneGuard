#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════╗
# ║         PhoneGuard v5.0  –  Android Malware Scanner     ║
# ║              Developed by Ibrahim Mustafa               ║
# ╚══════════════════════════════════════════════════════════╝

import sys
import os
import time
import threading
import re
from datetime import datetime
from adb_controller import ADBController
from analyzer import Analyzer
from report import Report

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.markdown import Markdown
    from rich.text import Text
    from rich import box
    from rich.live import Live
    from rich.layout import Layout
    from rich.rule import Rule
    from rich.align import Align
    from rich.style import Style
    from rich.padding import Padding
    from rich.columns import Columns
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ──────────────────────────────────────────────────────────────
#  THEME
# ──────────────────────────────────────────────────────────────
THEME = {
    "primary":    "#00D4FF",
    "secondary":  "#7B2FBE",
    "accent":     "#FF4C6A",
    "success":    "#00E676",
    "warning":    "#FFD600",
    "muted":      "#4A5568",
    "border":     "#1E2A3A",
    "text":       "#E2E8F0",
}

console = Console(highlight=False)

# ──────────────────────────────────────────────────────────────
#  LOGO
# ──────────────────────────────────────────────────────────────
LOGO = r"""
  ██████╗ ██╗  ██╗ ██████╗ ███╗  ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██╔═══██╗████╗ ██║██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║   ██║██╔██╗██║█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║██║   ██║██║╚████║██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║  ██║╚██████╔╝██║ ╚███║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

# ──────────────────────────────────────────────────────────────
#  الترجمة (Localization) – محدثة
# ──────────────────────────────────────────────────────────────
L10N = {
    "en": {
        "app_title": "⚡  Android Adware & Malware Scanner",
        "version": "v5.0  |  2025",
        "developer": "✦  Ibrahim Mustafa",
        "select_lang": "Select Language / اختر اللغة [1/2]: ",
        "main_menu": "MAIN MENU",
        "menu_1": "Smart Full Scan",
        "menu_1_desc": "Recommended — fast & accurate",
        "menu_2": "Deep Behavioral Scan",
        "menu_2_desc": "Requires app running on device",
        "menu_3": "Network Traffic Analysis",
        "menu_3_desc": "Inspect ad-server connections",
        "menu_4": "View Last Report",
        "menu_4_desc": "Open the most recent scan report",
        "menu_5": "Uninstall App",
        "menu_5_desc": "Remove a package by name",
        "menu_6": "Real-Time Ad Monitor",
        "menu_6_desc": "Passive live monitoring (60s)",
        "menu_7": "Background Apps Manager",
        "menu_7_desc": "Show/Manage running background processes",
        "menu_8": "High Permissions Apps",
        "menu_8_desc": "Show apps with critical permissions",
        "menu_9": "Exit",
        "menu_9_desc": "Close PhoneGuard",
        "select_option": "▶  Select option",
        "no_rich": "[!] Install rich for best experience: pip3 install rich",
        "fetching_packages": "Fetching Packages",
        "no_packages": "✘  No packages found.",
        "found_packages": "✔  Found [bold]{count}[/bold] packages",
        "scanning_packages": "Scanning packages…",
        "scanning": "Scanning:",
        "no_suspicious": "✅  No suspicious apps found — your device is clean!",
        "report_saved": "✔  Report saved.",
        "press_enter": "  Press Enter to return to menu…",
        "uninstall_confirm": "⚠  Uninstall [bold]{pkg}[/bold]?",
        "uninstall_any": "  Uninstall any of these apps?",
        "enter_numbers": "  Enter numbers (comma-separated, e.g. 1,3)",
        "enter_package": "Enter package name",
        "analyzing_traffic": "⏳  Analyzing traffic for [bold]{pkg}[/bold]…",
        "ad_connections_detected": "⚠  Ad-server connections detected:",
        "no_ad_connections": "✔  No ad-server connections detected.",
        "no_reports": "⚠  No reports found yet.",
        "reports_dir_not_found": "⚠  Reports directory not found.",
        "manual_uninstall_title": "Manual Uninstall",
        "no_user_packages": "ℹ  No user-installed packages found.",
        "user_packages_title": "User-Installed Packages",
        "package_name_col": "Package Name",
        "enter_num_or_partial": "Enter number(s) (e.g., 1,3) OR type a partial app name (e.g., 'whatsapp')",
        "invalid_index": "✘  Invalid index: {idx}",
        "no_match_package": "✘  No packages found containing '{term}'.",
        "multiple_matches": "Multiple packages found containing '{term}':",
        "enter_number_choice": "Enter the number of the package to uninstall",
        "invalid_selection": "✘  Invalid selection.",
        "invalid_input": "✘  Invalid input.",
        "uninstalling": "⏳  Uninstalling [bold]{pkg}[/bold]…",
        "uninstall_success": "✔  {pkg} removed successfully.",
        "uninstall_fail": "✘  Failed to remove {pkg}.",
        "skipped": "⏭  Skipped {pkg}.",
        "no_packages_selected": "No packages selected for uninstall.",
        "invalid_option": "✘  Invalid option. Please choose 1–9.",
        "goodbye": "👋  Thank you for using PhoneGuard. Stay secure!",
        "goodbye_ctrl_c": "👋 Thank you for using PhoneGuard. Share it with your friends and follow us for more tools!",
        "risk_critical": "CRITICAL",
        "risk_high": "HIGH",
        "risk_medium": "MEDIUM",
        "risk_low": "LOW",
        "yes": "Yes",
        "no": "No",
        "col_hash": "#",
        "col_package": "Package",
        "col_risk": "Risk Score",
        "col_suspicious": "Suspicious",
        "col_dangerous": "Dangerous",
        "col_boot": "Boot",
        "col_accessibility": "Accessibility",
        "dangerous_none": "None",
        "suspicious_reason_perms": "Has {count} dangerous permissions: {perms}",
        "suspicious_reason_boot": "Starts automatically with system (Boot Receiver)",
        "suspicious_reason_accessibility": "Uses Accessibility Service (often abused by malware)",
        "suspicious_reason_ads": "Contains ad libraries: {libs}",
        "suspicious_reason_quark": "Quark detected {count} suspicious behavioral patterns",
        "suspicious_reason_connections": "Connects to {count} known ad servers: {servers}",
        "suspicious_reason_behavioral": "Behavioral analysis: {indicators}",
        "ad_monitor_title": "📡 Real-Time Ad Monitor",
        "ad_monitor_desc": "⚡  Monitoring popup ads for [bold]60 seconds[/bold].",
        "ad_monitor_instruction": "Use your phone normally. Press Ctrl+C to stop early.",
        "ad_monitor_remaining": "📡 Live Ad Monitor — {time}s remaining",
        "ad_monitor_no_ads": "No ads detected yet — continue using your phone.",
        "ad_monitor_stopped": "⚠  Monitoring stopped by user.",
        "ad_monitor_final": "Final Ad Monitor Report",
        "ad_monitor_clean": "✔  No ads detected. Device appears clean.",
        "ad_monitor_summary": "Ad Detection Summary — {total} total",
        "ad_monitor_total_events": "Total ad events: [bold]{total}[/bold]",
        "ad_monitor_uninstall_any": "  Uninstall any of these apps?",
        "ad_monitor_enter_numbers": "  Enter numbers to uninstall (comma-separated, e.g. 1,3)",
        # Background Manager
        "bg_title": "🔄 Background Running Apps",
        "bg_found": "✔  Found [bold]{count}[/bold] running user apps.",
        "bg_no_apps": "ℹ  No background user apps found.",
        "bg_options": "Options: [K] Kill selected, [U] Uninstall selected, [A] Kill All, [D] Uninstall All, [B] Back",
        "bg_enter_numbers": "Enter numbers (comma-separated, e.g. 1,3):",
        "bg_confirm_kill_all": "Are you sure you want to STOP all [bold]{count}[/bold] background apps? (y/n)",
        "bg_confirm_uninstall_all": "Are you sure you want to UNINSTALL all [bold]{count}[/bold] apps? Type 'yes' to confirm:",
        "bg_killing": "⏳  Stopping [bold]{pkg}[/bold]…",
        "bg_kill_success": "✔  Stopped [bold]{pkg}[/bold].",
        "bg_kill_fail": "✘  Failed to stop [bold]{pkg}[/bold].",
        "bg_uninstalling": "⏳  Uninstalling [bold]{pkg}[/bold]…",
        "bg_uninstall_success": "✔  Uninstalled [bold]{pkg}[/bold].",
        "bg_uninstall_fail": "✘  Failed to uninstall [bold]{pkg}[/bold].",
        "bg_back": "↩  Returning to main menu.",
        # High Permissions Manager
        "hp_title": "🔓 Apps with High Permissions",
        "hp_found": "✔  Found [bold]{count}[/bold] apps with critical permissions.",
        "hp_no_apps": "ℹ  No apps with high permissions found.",
        "hp_options": "Options: [U] Uninstall selected, [R] Revoke permissions selected, [A] Uninstall All, [D] Revoke All, [B] Back",
        "hp_enter_numbers": "Enter numbers (comma-separated, e.g. 1,3):",
        "hp_confirm_uninstall_all": "Are you sure you want to UNINSTALL all [bold]{count}[/bold] apps? Type 'yes' to confirm:",
        "hp_confirm_revoke_all": "Are you sure you want to REVOKE ALL permissions for [bold]{count}[/bold] apps? Type 'yes' to confirm:",
        "hp_revoking": "⏳  Revoking permissions for [bold]{pkg}[/bold]…",
        "hp_revoke_success": "✔  Revoked permissions for [bold]{pkg}[/bold].",
        "hp_revoke_fail": "✘  Failed to revoke permissions for [bold]{pkg}[/bold].",
        "hp_uninstalling": "⏳  Uninstalling [bold]{pkg}[/bold]…",
        "hp_uninstall_success": "✔  Uninstalled [bold]{pkg}[/bold].",
        "hp_uninstall_fail": "✘  Failed to uninstall [bold]{pkg}[/bold].",
        "hp_skipped": "⏭  Skipped {pkg}.",
        "hp_back": "↩  Returning to main menu.",
        "hp_col_perms": "Dangerous Perms",
    },
    "ar": {
        "app_title": "⚡  ماسح البرمجيات الخبيثة والإعلانات لأندرويد",
        "version": "الإصدار 5.0  |  2025",
        "developer": "✦  إبراهيم مصطفى",
        "select_lang": "Select Language / اختر اللغة [1/2]: ",
        "main_menu": "القائمة الرئيسية",
        "menu_1": "فحص ذكي شامل",
        "menu_1_desc": "موصى به — سريع ودقيق",
        "menu_2": "فحص سلوكي عميق",
        "menu_2_desc": "يتطلب تشغيل التطبيق على الجهاز",
        "menu_3": "تحليل حركة الشبكة",
        "menu_3_desc": "فحص اتصالات خوادم الإعلانات",
        "menu_4": "عرض آخر تقرير",
        "menu_4_desc": "فتح أحدث تقرير فحص",
        "menu_5": "إزالة تطبيق",
        "menu_5_desc": "إزالة حزمة بالاسم",
        "menu_6": "مراقبة الإعلانات لحظياً",
        "menu_6_desc": "مراقبة حية سلبية (60 ثانية)",
        "menu_7": "إدارة التطبيقات في الخلفية",
        "menu_7_desc": "عرض/إدارة العمليات الخلفية",
        "menu_8": "التطبيقات ذات الصلاحيات العالية",
        "menu_8_desc": "عرض التطبيقات التي لديها صلاحيات خطيرة",
        "menu_9": "خروج",
        "menu_9_desc": "إغلاق PhoneGuard",
        "select_option": "▶  اختر الخيار",
        "no_rich": "[!] قم بتثبيت rich للحصول على أفضل تجربة: pip3 install rich",
        "fetching_packages": "جلب الحزم",
        "no_packages": "✘  لم يتم العثور على حزم.",
        "found_packages": "✔  تم العثور على [bold]{count}[/bold] حزمة",
        "scanning_packages": "فحص الحزم…",
        "scanning": "فحص:",
        "no_suspicious": "✅  لم يتم العثور على تطبيقات مشبوهة — جهازك نظيف!",
        "report_saved": "✔  تم حفظ التقرير.",
        "press_enter": "  اضغط Enter للعودة إلى القائمة…",
        "uninstall_confirm": "⚠  إزالة [bold]{pkg}[/bold]؟",
        "uninstall_any": "  إزالة أي من هذه التطبيقات؟",
        "enter_numbers": "  أدخل الأرقام (مفصولة بفواصل، مثل 1,3)",
        "enter_package": "أدخل اسم الحزمة",
        "analyzing_traffic": "⏳  تحليل حركة الشبكة لـ [bold]{pkg}[/bold]…",
        "ad_connections_detected": "⚠  تم اكتشاف اتصالات بخوادم إعلانية:",
        "no_ad_connections": "✔  لم يتم اكتشاف اتصالات بخوادم إعلانية.",
        "no_reports": "⚠  لم يتم العثور على تقارير بعد.",
        "reports_dir_not_found": "⚠  مجلد التقارير غير موجود.",
        "manual_uninstall_title": "إزالة تطبيق يدوياً",
        "no_user_packages": "ℹ  لم يتم العثور على حزم مثبتة من قبل المستخدم.",
        "user_packages_title": "الحزم المثبتة من قبل المستخدم",
        "package_name_col": "اسم الحزمة",
        "enter_num_or_partial": "أدخل رقم (أرقام) (مثل 1,3) أو اكتب جزءاً من اسم التطبيق (مثل 'whatsapp')",
        "invalid_index": "✘  رقم غير صحيح: {idx}",
        "no_match_package": "✘  لم يتم العثور على حزم تحتوي على '{term}'.",
        "multiple_matches": "تم العثور على عدة حزم تحتوي على '{term}':",
        "enter_number_choice": "أدخل رقم الحزمة المراد إزالتها",
        "invalid_selection": "✘  اختيار غير صحيح.",
        "invalid_input": "✘  إدخال غير صحيح.",
        "uninstalling": "⏳  جاري إزالة [bold]{pkg}[/bold]…",
        "uninstall_success": "✔  تمت إزالة {pkg} بنجاح.",
        "uninstall_fail": "✘  فشلت إزالة {pkg}.",
        "skipped": "⏭  تم تخطي {pkg}.",
        "no_packages_selected": "لم يتم اختيار أي حزمة للإزالة.",
        "invalid_option": "✘  خيار غير صحيح. الرجاء الاختيار من 1 إلى 9.",
        "goodbye": "👋  شكراً لاستخدامك PhoneGuard. ابقَ آمناً!",
        "goodbye_ctrl_c": "👋 شكراً لاستخدامك PhoneGuard. شاركها مع أصدقائك وتابعنا للمزيد من الأدوات!",
        "risk_critical": "خطير",
        "risk_high": "مرتفع",
        "risk_medium": "متوسط",
        "risk_low": "منخفض",
        "yes": "نعم",
        "no": "لا",
        "col_hash": "#",
        "col_package": "الحزمة",
        "col_risk": "نسبة الخطورة",
        "col_suspicious": "مشبوه",
        "col_dangerous": "خطير",
        "col_boot": "بدء تشغيل",
        "col_accessibility": "إمكانية الوصول",
        "dangerous_none": "لا يوجد",
        "suspicious_reason_perms": "لديه {count} صلاحية خطيرة: {perms}",
        "suspicious_reason_boot": "يبدأ تلقائياً مع النظام (مستقبل الإقلاع)",
        "suspicious_reason_accessibility": "يستخدم خدمة إمكانية الوصول (غالباً ما يساء استخدامها)",
        "suspicious_reason_ads": "يحتوي على مكتبات إعلانية: {libs}",
        "suspicious_reason_quark": "اكتشف Quark عدد {count} نمط سلوكي مشبوه",
        "suspicious_reason_connections": "يتصل بـ {count} خادم إعلانات معروف: {servers}",
        "suspicious_reason_behavioral": "التحليل السلوكي: {indicators}",
        "ad_monitor_title": "📡 مراقبة الإعلانات لحظياً",
        "ad_monitor_desc": "⚡  مراقبة الإعلانات المنبثقة لمدة [bold]60 ثانية[/bold].",
        "ad_monitor_instruction": "استخدم هاتفك بشكل طبيعي. اضغط Ctrl+C للإيقاف المبكر.",
        "ad_monitor_remaining": "📡 مراقبة الإعلانات الحية — متبقي {time} ثانية",
        "ad_monitor_no_ads": "لم يتم اكتشاف إعلانات حتى الآن — استمر في استخدام هاتفك.",
        "ad_monitor_stopped": "⚠  تم إيقاف المراقبة بواسطة المستخدم.",
        "ad_monitor_final": "التقرير النهائي لمراقبة الإعلانات",
        "ad_monitor_clean": "✔  لم يتم اكتشاف إعلانات. الجهاز يبدو نظيفاً.",
        "ad_monitor_summary": "ملخص اكتشاف الإعلانات — إجمالي {total}",
        "ad_monitor_total_events": "إجمالي أحداث الإعلانات: [bold]{total}[/bold]",
        "ad_monitor_uninstall_any": "  إزالة أي من هذه التطبيقات؟",
        "ad_monitor_enter_numbers": "  أدخل الأرقام للإزالة (مفصولة بفواصل، مثل 1,3)",
        # Background Manager
        "bg_title": "🔄 التطبيقات العاملة في الخلفية",
        "bg_found": "✔  تم العثور على [bold]{count}[/bold] تطبيق يعمل في الخلفية.",
        "bg_no_apps": "ℹ  لا توجد تطبيقات خلفية.",
        "bg_options": "الخيارات: [K] إيقاف مختارة، [U] إلغاء تثبيت مختارة، [A] إيقاف الكل، [D] إلغاء تثبيت الكل، [B] رجوع",
        "bg_enter_numbers": "أدخل الأرقام (مفصولة بفواصل، مثل 1,3):",
        "bg_confirm_kill_all": "هل أنت متأكد من إيقاف جميع التطبيقات الخلفية [bold]{count}[/bold]؟ (y/n)",
        "bg_confirm_uninstall_all": "هل أنت متأكد من إلغاء تثبيت جميع التطبيقات [bold]{count}[/bold]؟ اكتب 'yes' للتأكيد:",
        "bg_killing": "⏳  جاري إيقاف [bold]{pkg}[/bold]…",
        "bg_kill_success": "✔  تم إيقاف [bold]{pkg}[/bold].",
        "bg_kill_fail": "✘  فشل إيقاف [bold]{pkg}[/bold].",
        "bg_uninstalling": "⏳  جاري إزالة [bold]{pkg}[/bold]…",
        "bg_uninstall_success": "✔  تمت إزالة [bold]{pkg}[/bold].",
        "bg_uninstall_fail": "✘  فشلت إزالة [bold]{pkg}[/bold].",
        "bg_back": "↩  العودة إلى القائمة الرئيسية.",
        # High Permissions Manager
        "hp_title": "🔓 التطبيقات ذات الصلاحيات العالية",
        "hp_found": "✔  تم العثور على [bold]{count}[/bold] تطبيق بصلاحيات خطيرة.",
        "hp_no_apps": "ℹ  لا توجد تطبيقات بصلاحيات عالية.",
        "hp_options": "الخيارات: [U] إلغاء تثبيت مختارة، [R] إلغاء صلاحيات مختارة، [A] إلغاء تثبيت الكل، [D] إلغاء صلاحيات الكل، [B] رجوع",
        "hp_enter_numbers": "أدخل الأرقام (مفصولة بفواصل، مثل 1,3):",
        "hp_confirm_uninstall_all": "هل أنت متأكد من إلغاء تثبيت جميع التطبيقات [bold]{count}[/bold]؟ اكتب 'yes' للتأكيد:",
        "hp_confirm_revoke_all": "هل أنت متأكد من إلغاء جميع الصلاحيات لـ [bold]{count}[/bold] تطبيق؟ اكتب 'yes' للتأكيد:",
        "hp_revoking": "⏳  جاري إلغاء صلاحيات [bold]{pkg}[/bold]…",
        "hp_revoke_success": "✔  تم إلغاء صلاحيات [bold]{pkg}[/bold].",
        "hp_revoke_fail": "✘  فشل إلغاء صلاحيات [bold]{pkg}[/bold].",
        "hp_uninstalling": "⏳  جاري إزالة [bold]{pkg}[/bold]…",
        "hp_uninstall_success": "✔  تمت إزالة [bold]{pkg}[/bold].",
        "hp_uninstall_fail": "✘  فشلت إزالة [bold]{pkg}[/bold].",
        "hp_skipped": "⏭  تم تخطي {pkg}.",
        "hp_back": "↩  العودة إلى القائمة الرئيسية.",
        "hp_col_perms": "الصلاحيات الخطيرة",
    }
}

TEXTS = L10N["en"]

# ──────────────────────────────────────────────────────────────
#  BANNER
# ──────────────────────────────────────────────────────────────
def print_banner():
    if not RICH_AVAILABLE:
        print(LOGO)
        print("  PhoneGuard v5.0 – Android Malware Scanner")
        print("  ─" * 40)
        return

    console.print()
    logo_text = Text(LOGO, style=f"bold {THEME['primary']}")
    console.print(Align.center(logo_text))

    info_text = f"{TEXTS['app_title']}    {TEXTS['version']}    {TEXTS['developer']}"
    console.print(Panel(info_text, border_style=THEME['secondary'], padding=(1, 2)))
    console.print()

# ──────────────────────────────────────────────────────────────
#  MENU (محدث)
# ──────────────────────────────────────────────────────────────
def print_menu():
    if not RICH_AVAILABLE:
        print("\n  ┌─────────────────────────────────────┐")
        print("  │           MAIN MENU                 │")
        print("  ├─────────────────────────────────────┤")
        print("  │  [1]  Smart Full Scan               │")
        print("  │  [2]  Deep Behavioral Scan          │")
        print("  │  [3]  Network Traffic Analysis      │")
        print("  │  [4]  View Last Report              │")
        print("  │  [5]  Uninstall App                 │")
        print("  │  [6]  Real-Time Ad Monitor          │")
        print("  │  [7]  Background Apps Manager       │")
        print("  │  [8]  High Permissions Apps         │")
        print("  │  [9]  Exit                          │")
        print("  └─────────────────────────────────────┘\n")
        return

    menu_items = [
        ("1", "🔍", TEXTS["menu_1"], TEXTS["menu_1_desc"], THEME['success']),
        ("2", "🧬", TEXTS["menu_2"], TEXTS["menu_2_desc"], THEME['primary']),
        ("3", "🌐", TEXTS["menu_3"], TEXTS["menu_3_desc"], THEME['warning']),
        ("4", "📄", TEXTS["menu_4"], TEXTS["menu_4_desc"], THEME['secondary']),
        ("5", "🗑️", TEXTS["menu_5"], TEXTS["menu_5_desc"], THEME['accent']),
        ("6", "📡", TEXTS["menu_6"], TEXTS["menu_6_desc"], THEME['primary']),
        ("7", "🔄", TEXTS["menu_7"], TEXTS["menu_7_desc"], THEME['primary']),
        ("8", "🔓", TEXTS["menu_8"], TEXTS["menu_8_desc"], THEME['accent']),
        ("9", "🚪", TEXTS["menu_9"], TEXTS["menu_9_desc"], THEME['muted']),
    ]

    table = Table(
        box=box.ROUNDED,
        border_style=THEME['border'],
        header_style=f"bold {THEME['primary']}",
        show_header=True,
        title=f"[bold {THEME['text']}]{TEXTS['main_menu']}[/]",
        title_style=f"bold {THEME['text']}",
        padding=(0, 2),
        expand=False,
        min_width=65,
    )
    table.add_column("  #", style=f"bold {THEME['primary']}", width=4, justify="center")
    table.add_column("", width=3)
    table.add_column("Option",       style=f"bold {THEME['text']}", width=28)
    table.add_column("Description",  style=f"dim {THEME['muted']}", width=40)

    for num, icon, title, desc, color in menu_items:
        table.add_row(
            f"[{color}]{num}[/]",
            icon,
            f"[{color}]{title}[/]",
            desc,
        )

    console.print(Align.center(table))
    console.print()

def get_user_choice():
    if RICH_AVAILABLE:
        choice_str = Prompt.ask(
            f"  [{THEME['primary']}]{TEXTS['select_option']}[/]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
            show_choices=True,
        )
        return int(choice_str)
    else:
        try:
            return int(input(f"  {TEXTS['select_option']}: ").strip())
        except Exception:
            return 0

# ──────────────────────────────────────────────────────────────
#  RISK BADGE
# ──────────────────────────────────────────────────────────────
def risk_badge(score: int) -> str:
    if score >= 8:
        return f"[bold {THEME['accent']}] {score}/10 ▲ {TEXTS['risk_critical']} [/]"
    elif score >= 5:
        return f"[bold {THEME['warning']}] {score}/10 ● {TEXTS['risk_high']}    [/]"
    elif score >= 3:
        return f"[bold {THEME['primary']}] {score}/10 ◆ {TEXTS['risk_medium']}  [/]"
    else:
        return f"[bold {THEME['success']}] {score}/10 ✔ {TEXTS['risk_low']}     [/]"

# ──────────────────────────────────────────────────────────────
#  APP DETAILS TABLE ROW
# ──────────────────────────────────────────────────────────────
def display_app_details(pkg, data, index, table=None):
    if RICH_AVAILABLE and table is not None:
        yesno = lambda v: (
            f"[bold {THEME['accent']}]✘ {TEXTS['yes']}[/]" if v
            else f"[dim {THEME['success']}]✔ {TEXTS['no']}[/]"
        )
        dangerous_str = (
            f"[{THEME['warning']}]{', '.join(data['dangerous'][:3])}{'…' if len(data['dangerous'])>3 else ''}[/]"
            if data.get('dangerous') else f"[dim {THEME['success']}]{TEXTS['dangerous_none']}[/]"
        )
        table.add_row(
            f"[bold {THEME['primary']}]{index}[/]",
            f"[{THEME['text']}]{pkg}[/]",
            risk_badge(data['score']),
            yesno(data.get('suspicious', False)),
            dangerous_str,
            yesno(data.get('boot', False)),
            yesno(data.get('accessibility', False)),
        )
        return

    # Fallback plain
    print(f"\n  [{index}] Package: {pkg}")
    print(f"      Risk Score       : {data['score']}/10")
    print(f"      Dangerous Perms  : {', '.join(data['dangerous']) if data['dangerous'] else TEXTS['dangerous_none']}")
    print(f"      Boot Receiver    : {'Yes' if data.get('boot') else 'No'}")
    print(f"      Ads Libraries    : {', '.join(data.get('ads', [])) or TEXTS['dangerous_none']}")
    print(f"      Accessibility    : {'Yes' if data.get('accessibility') else 'No'}")

    if data.get('quark_results'):
        print("      Quark Analysis   :")
        for qr in data['quark_results']:
            if isinstance(qr, dict):
                print(f"         – {qr.get('rule','?')}  (Confidence: {qr.get('confidence','N/A')}%)")
    if data.get('ad_connections'):
        print("      Ad Connections   :")
        for c in data['ad_connections']:
            print(f"         – {c}")
    if data.get('behavioral_indicators'):
        print("      Behavioral       :")
        for b in data['behavioral_indicators']:
            print(f"         – {b}")
    if data.get('suspicious_reasons'):
        print("      Suspicious Reasons:")
        for r in data['suspicious_reasons']:
            print(f"         – {r}")

def confirm_uninstall(pkg):
    if RICH_AVAILABLE:
        return Confirm.ask(
            f"\n  [{THEME['warning']}]{TEXTS['uninstall_confirm'].format(pkg=pkg)}[/]"
        )
    return input(f"\n  Uninstall '{pkg}'? (y/n): ").strip().lower() == 'y'

# ──────────────────────────────────────────────────────────────
#  SCAN
# ──────────────────────────────────────────────────────────────
def perform_scan(adb, scan_type):
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['fetching_packages']} [/]", style=THEME['border']))

    packages = adb.list_packages()
    if not packages:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['no_packages']}[/]\n")
        return [], {}

    console.print(
        f"\n  [{THEME['success']}]{TEXTS['found_packages'].format(count=len(packages))}[/] — starting analysis…\n"
    )

    suspicious_list = []
    packages_data   = {}

    with Progress(
        SpinnerColumn(style=f"bold {THEME['primary']}"),
        TextColumn("[progress.description]{task.description}", style=THEME['text']),
        BarColumn(bar_width=38, style=THEME['secondary'], complete_style=THEME['primary']),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%", style=THEME['primary']),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"[{THEME['primary']}]{TEXTS['scanning_packages']}[/]", total=len(packages))

        for pkg in packages:
            progress.update(task, description=f"[{THEME['muted']}]{TEXTS['scanning']} [bold]{pkg[:40]}[/]")

            if Analyzer.is_system_package(pkg):
                progress.advance(task)
                continue
            if Analyzer.is_trusted_app(pkg):
                progress.advance(task)
                continue

            perms   = adb.get_package_permissions(pkg)
            dangerous = Analyzer.analyze_permissions(perms)

            boot = False; ads_libs = []; accessibility = False
            quark_results = []; ad_connections = []; behavioral_indicators = []
            suspicious_reasons = []

            apk_path = adb.pull_apk(pkg)
            if apk_path:
                manifest    = Analyzer.parse_manifest(apk_path)
                boot        = Analyzer.check_boot_receiver(manifest)
                accessibility = Analyzer.check_accessibility_service(manifest)
                ads_libs    = Analyzer.check_ads_libraries(apk_path)
                quark_results = Analyzer.run_quark_analysis(apk_path)

            if scan_type == 2:
                ad_connections       = Analyzer.analyze_network_traffic(pkg)
                behavioral_indicators = Analyzer.monitor_ad_behavior(pkg)

            score    = Analyzer.get_risk_score(dangerous, quark_results, ad_connections, behavioral_indicators)
            suspicious = Analyzer.is_suspicious(score, dangerous, quark_results, ad_connections, behavioral_indicators, pkg)

            if dangerous:
                suspicious_reasons.append(TEXTS['suspicious_reason_perms'].format(count=len(dangerous), perms=', '.join(dangerous)))
            if boot:
                suspicious_reasons.append(TEXTS['suspicious_reason_boot'])
            if accessibility:
                suspicious_reasons.append(TEXTS['suspicious_reason_accessibility'])
            if ads_libs:
                suspicious_reasons.append(TEXTS['suspicious_reason_ads'].format(libs=', '.join(ads_libs)))
            if quark_results:
                suspicious_reasons.append(TEXTS['suspicious_reason_quark'].format(count=len(quark_results)))
            if ad_connections:
                suspicious_reasons.append(TEXTS['suspicious_reason_connections'].format(count=len(ad_connections), servers=', '.join(ad_connections)))
            if behavioral_indicators:
                suspicious_reasons.append(TEXTS['suspicious_reason_behavioral'].format(indicators=', '.join(behavioral_indicators)))

            is_target = suspicious if scan_type == 1 else (suspicious or quark_results or ad_connections or behavioral_indicators)

            if is_target:
                packages_data[pkg] = {
                    "dangerous": dangerous, "score": score, "suspicious": suspicious,
                    "boot": boot, "ads": ads_libs, "accessibility": accessibility,
                    "quark_results": quark_results, "ad_connections": ad_connections,
                    "behavioral_indicators": behavioral_indicators,
                    "suspicious_reasons": suspicious_reasons,
                }
                suspicious_list.append(pkg)

            progress.advance(task)

    return suspicious_list, packages_data

# ──────────────────────────────────────────────────────────────
#  BACKGROUND APPS MANAGER
# ──────────────────────────────────────────────────────────────
def manage_background_apps(adb):
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['bg_title']} [/]", style=THEME['border']))

    all_packages = adb.list_packages()
    if not all_packages:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['no_packages']}[/]")
        return

    user_packages = [p for p in all_packages if not Analyzer.is_system_package(p)]

    ps_output = adb.run_adb("shell ps -A -o NAME")
    running_set = set()
    for line in ps_output.splitlines():
        line = line.strip()
        if line and line != "NAME" and line != "name" and '.' in line:
            if not line.startswith('[') and not line.startswith('kworker') and not line.startswith('sh '):
                running_set.add(line)

    background_apps = [p for p in user_packages if p in running_set]

    if not background_apps:
        console.print(f"\n  [{THEME['warning']}]{TEXTS['bg_no_apps']}[/]")
        return

    console.print(f"\n  [{THEME['success']}]{TEXTS['bg_found'].format(count=len(background_apps))}[/]\n")

    if RICH_AVAILABLE:
        table = Table(box=box.ROUNDED, border_style=THEME['border'], header_style=f"bold {THEME['primary']}")
        table.add_column(TEXTS['col_hash'], style=f"bold {THEME['primary']}", width=4, justify="center")
        table.add_column(TEXTS['col_package'], style=THEME['text'], width=55)
        for idx, pkg in enumerate(background_apps, 1):
            table.add_row(str(idx), pkg)
        console.print(table)
    else:
        print(f"\n  {TEXTS['bg_title']}:")
        for idx, pkg in enumerate(background_apps, 1):
            print(f"    [{idx}] {pkg}")

    while True:
        console.print(f"\n  [{THEME['primary']}]{TEXTS['bg_options']}[/]")
        if RICH_AVAILABLE:
            action = Prompt.ask("  >", choices=["K", "U", "A", "D", "B"], default="B")
        else:
            action = input("  > ").strip().upper()
            if action not in ["K", "U", "A", "D", "B"]:
                action = "B"

        if action == "B":
            console.print(f"\n  [{THEME['muted']}]{TEXTS['bg_back']}[/]")
            break

        if action == "K" or action == "U":
            if RICH_AVAILABLE:
                selected_str = Prompt.ask(f"  [{THEME['primary']}]{TEXTS['bg_enter_numbers']}[/]")
            else:
                selected_str = input(f"  {TEXTS['bg_enter_numbers']}: ")

            indices = []
            try:
                for part in selected_str.split(','):
                    part = part.strip()
                    if part.isdigit():
                        idx = int(part) - 1
                        if 0 <= idx < len(background_apps):
                            indices.append(idx)
                        else:
                            console.print(f"  [{THEME['accent']}]✘  رقم {part} غير صحيح (يجب أن يكون بين 1 و {len(background_apps)}).[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]✘  '{part}' ليس رقماً صحيحاً.[/]")
            except:
                pass

            if not indices:
                console.print(f"  [{THEME['accent']}]✘  لم يتم اختيار أي تطبيق صحيح. الرجاء المحاولة مرة أخرى.[/]")
                continue

            for idx in indices:
                pkg = background_apps[idx]
                if action == "K":
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['bg_killing'].format(pkg=pkg)}[/]")
                    result = adb.run_adb(f"shell am force-stop {pkg}")
                    if "Error" not in result and "Exception" not in result:
                        console.print(f"  [{THEME['success']}]{TEXTS['bg_kill_success'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]{TEXTS['bg_kill_fail'].format(pkg=pkg)}[/]")
                else:
                    if confirm_uninstall(pkg):
                        console.print(f"\n  [{THEME['warning']}]{TEXTS['bg_uninstalling'].format(pkg=pkg)}[/]")
                        success = adb.uninstall_package(pkg)
                        if success:
                            console.print(f"  [{THEME['success']}]{TEXTS['bg_uninstall_success'].format(pkg=pkg)}[/]")
                        else:
                            console.print(f"  [{THEME['accent']}]{TEXTS['bg_uninstall_fail'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['muted']}]{TEXTS['skipped'].format(pkg=pkg)}[/]")
            continue

        if action == "A":
            if Confirm.ask(f"\n  [{THEME['warning']}]{TEXTS['bg_confirm_kill_all'].format(count=len(background_apps))}[/]"):
                for pkg in background_apps:
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['bg_killing'].format(pkg=pkg)}[/]")
                    result = adb.run_adb(f"shell am force-stop {pkg}")
                    if "Error" not in result and "Exception" not in result:
                        console.print(f"  [{THEME['success']}]{TEXTS['bg_kill_success'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]{TEXTS['bg_kill_fail'].format(pkg=pkg)}[/]")
            continue

        if action == "D":
            if RICH_AVAILABLE:
                confirm_text = Prompt.ask(f"\n  [{THEME['accent']}]{TEXTS['bg_confirm_uninstall_all'].format(count=len(background_apps))}[/]")
            else:
                confirm_text = input(f"\n  {TEXTS['bg_confirm_uninstall_all'].format(count=len(background_apps))}: ")

            if confirm_text.lower() == "yes":
                for pkg in background_apps:
                    if confirm_uninstall(pkg):
                        console.print(f"\n  [{THEME['warning']}]{TEXTS['bg_uninstalling'].format(pkg=pkg)}[/]")
                        success = adb.uninstall_package(pkg)
                        if success:
                            console.print(f"  [{THEME['success']}]{TEXTS['bg_uninstall_success'].format(pkg=pkg)}[/]")
                        else:
                            console.print(f"  [{THEME['accent']}]{TEXTS['bg_uninstall_fail'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['muted']}]{TEXTS['skipped'].format(pkg=pkg)}[/]")
            else:
                console.print(f"  [{THEME['muted']}]Cancelled.[/]")
            continue

# ──────────────────────────────────────────────────────────────
#  HIGH PERMISSIONS MANAGER (الخيار الجديد)
# ──────────────────────────────────────────────────────────────
def manage_high_permission_apps(adb):
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['hp_title']} [/]", style=THEME['border']))

    all_packages = adb.list_packages()
    if not all_packages:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['no_packages']}[/]")
        return

    # تجميع التطبيقات التي لديها 5 صلاحيات خطيرة أو أكثر
    high_perm_apps = []
    for pkg in all_packages:
        if Analyzer.is_system_package(pkg) or Analyzer.is_trusted_app(pkg):
            continue
        perms = adb.get_package_permissions(pkg)
        dangerous = Analyzer.analyze_permissions(perms)
        if len(dangerous) >= 5:  # عتبة الصلاحيات العالية
            high_perm_apps.append((pkg, dangerous))

    if not high_perm_apps:
        console.print(f"\n  [{THEME['warning']}]{TEXTS['hp_no_apps']}[/]")
        return

    console.print(f"\n  [{THEME['success']}]{TEXTS['hp_found'].format(count=len(high_perm_apps))}[/]\n")

    if RICH_AVAILABLE:
        table = Table(box=box.ROUNDED, border_style=THEME['border'], header_style=f"bold {THEME['primary']}")
        table.add_column(TEXTS['col_hash'], style=f"bold {THEME['primary']}", width=4, justify="center")
        table.add_column(TEXTS['col_package'], style=THEME['text'], width=40)
        table.add_column(TEXTS['hp_col_perms'], style=THEME['warning'], width=30)
        for idx, (pkg, perms) in enumerate(high_perm_apps, 1):
            table.add_row(str(idx), pkg, ", ".join(perms[:5]) + ("…" if len(perms)>5 else ""))
        console.print(table)
    else:
        print(f"\n  {TEXTS['hp_title']}:")
        for idx, (pkg, perms) in enumerate(high_perm_apps, 1):
            print(f"    [{idx}] {pkg} ({len(perms)} dangerous permissions)")

    while True:
        console.print(f"\n  [{THEME['primary']}]{TEXTS['hp_options']}[/]")
        if RICH_AVAILABLE:
            action = Prompt.ask("  >", choices=["U", "R", "A", "D", "B"], default="B")
        else:
            action = input("  > ").strip().upper()
            if action not in ["U", "R", "A", "D", "B"]:
                action = "B"

        if action == "B":
            console.print(f"\n  [{THEME['muted']}]{TEXTS['hp_back']}[/]")
            break

        if action == "U" or action == "R":
            if action == "U":
                console.print(f"\n  [{THEME['primary']}]أدخل أرقام التطبيقات التي تريد إلغاء تثبيتها (مثال: 1,3)[/]")
            else:
                console.print(f"\n  [{THEME['primary']}]أدخل أرقام التطبيقات التي تريد إلغاء صلاحياتها (مثال: 1,3)[/]")

            if RICH_AVAILABLE:
                selected_str = Prompt.ask(f"  [{THEME['primary']}]{TEXTS['hp_enter_numbers']}[/]")
            else:
                selected_str = input(f"  {TEXTS['hp_enter_numbers']}: ")

            indices = []
            try:
                for part in selected_str.split(','):
                    part = part.strip()
                    if part.isdigit():
                        idx = int(part) - 1
                        if 0 <= idx < len(high_perm_apps):
                            indices.append(idx)
                        else:
                            console.print(f"  [{THEME['accent']}]✘  رقم {part} غير صحيح (يجب أن يكون بين 1 و {len(high_perm_apps)}).[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]✘  '{part}' ليس رقماً صحيحاً.[/]")
            except:
                pass

            if not indices:
                console.print(f"  [{THEME['accent']}]✘  لم يتم اختيار أي تطبيق صحيح. الرجاء المحاولة مرة أخرى.[/]")
                continue

            for idx in indices:
                pkg, perms = high_perm_apps[idx]
                if action == "U":
                    if confirm_uninstall(pkg):
                        console.print(f"\n  [{THEME['warning']}]{TEXTS['hp_uninstalling'].format(pkg=pkg)}[/]")
                        success = adb.uninstall_package(pkg)
                        if success:
                            console.print(f"  [{THEME['success']}]{TEXTS['hp_uninstall_success'].format(pkg=pkg)}[/]")
                        else:
                            console.print(f"  [{THEME['accent']}]{TEXTS['hp_uninstall_fail'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['muted']}]{TEXTS['hp_skipped'].format(pkg=pkg)}[/]")
                else:  # R
                    # إلغاء جميع الصلاحيات الخطيرة
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['hp_revoking'].format(pkg=pkg)}[/]")
                    failed = False
                    for perm in perms:
                        result = adb.run_adb(f"shell pm revoke {pkg} {perm}")
                        if "not revoke" in result or "not granted" in result or "Exception" in result:
                            console.print(f"    [{THEME['accent']}]✘  فشل إلغاء صلاحية {perm}.[/]")
                            failed = True
                    if not failed:
                        console.print(f"  [{THEME['success']}]{TEXTS['hp_revoke_success'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]{TEXTS['hp_revoke_fail'].format(pkg=pkg)}[/]")
            continue

        if action == "A":
            if Confirm.ask(f"\n  [{THEME['warning']}]{TEXTS['hp_confirm_uninstall_all'].format(count=len(high_perm_apps))}[/]"):
                for pkg, _ in high_perm_apps:
                    if confirm_uninstall(pkg):
                        console.print(f"\n  [{THEME['warning']}]{TEXTS['hp_uninstalling'].format(pkg=pkg)}[/]")
                        success = adb.uninstall_package(pkg)
                        if success:
                            console.print(f"  [{THEME['success']}]{TEXTS['hp_uninstall_success'].format(pkg=pkg)}[/]")
                        else:
                            console.print(f"  [{THEME['accent']}]{TEXTS['hp_uninstall_fail'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['muted']}]{TEXTS['hp_skipped'].format(pkg=pkg)}[/]")
            continue

        if action == "D":
            if RICH_AVAILABLE:
                confirm_text = Prompt.ask(f"\n  [{THEME['accent']}]{TEXTS['hp_confirm_revoke_all'].format(count=len(high_perm_apps))}[/]")
            else:
                confirm_text = input(f"\n  {TEXTS['hp_confirm_revoke_all'].format(count=len(high_perm_apps))}: ")

            if confirm_text.lower() == "yes":
                for pkg, perms in high_perm_apps:
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['hp_revoking'].format(pkg=pkg)}[/]")
                    failed = False
                    for perm in perms:
                        result = adb.run_adb(f"shell pm revoke {pkg} {perm}")
                        if "not revoke" in result or "not granted" in result or "Exception" in result:
                            console.print(f"    [{THEME['accent']}]✘  فشل إلغاء صلاحية {perm}.[/]")
                            failed = True
                    if not failed:
                        console.print(f"  [{THEME['success']}]{TEXTS['hp_revoke_success'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]{TEXTS['hp_revoke_fail'].format(pkg=pkg)}[/]")
            else:
                console.print(f"  [{THEME['muted']}]Cancelled.[/]")
            continue

# ──────────────────────────────────────────────────────────────
#  AD MONITOR
# ──────────────────────────────────────────────────────────────
def monitor_ads_passive(adb):
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['ad_monitor_title']} [/]", style=THEME['border']))
    console.print(
        f"\n  [{THEME['warning']}]{TEXTS['ad_monitor_desc']}[/]\n"
        f"  [{THEME['muted']}]{TEXTS['ad_monitor_instruction']}[/]\n"
    )

    adb.run_adb("logcat -c")

    ad_data = {}; total_ads = 0
    start_time = time.time(); last_update = 0

    ad_patterns = [
        r"WindowManager.*addView", r"AlertDialog", r"PopupWindow",
        r"Toast.*show", r"AdView.*loadAd", r"InterstitialAd",
        r"RewardedAd", r"openAd", r"showAd",
    ]

    try:
        while time.time() - start_time < 60:
            output = adb.run_adb("logcat -d -t 2 -v brief")
            if output:
                for line in output.split("\n"):
                    if any(re.search(p, line, re.IGNORECASE) for p in ad_patterns):
                        pkg_match = re.search(r"\(([^)]+)\)", line)
                        pkg = pkg_match.group(1) if pkg_match else "Unknown"
                        ad_type = "Popup"
                        if "Toast" in line:            ad_type = "Toast"
                        elif "InterstitialAd" in line: ad_type = "Interstitial"
                        elif "RewardedAd" in line:     ad_type = "Rewarded"
                        elif "AdView" in line:         ad_type = "Banner"
                        if pkg not in ad_data:
                            ad_data[pkg] = {"count": 0, "types": {}, "last_seen": ""}
                        ad_data[pkg]["count"] += 1
                        ad_data[pkg]["types"][ad_type] = ad_data[pkg]["types"].get(ad_type, 0) + 1
                        ad_data[pkg]["last_seen"] = datetime.now().strftime("%H:%M:%S")
                        total_ads += 1

            if time.time() - last_update > 3:
                last_update = time.time()
                clear_screen()
                print_banner()

                elapsed = int(time.time() - start_time)
                remaining = 60 - elapsed
                console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['ad_monitor_remaining'].format(time=remaining)} [/]", style=THEME['border']))

                if ad_data and RICH_AVAILABLE:
                    t = Table(
                        title=f"[bold {THEME['accent']}]🛑 {total_ads} Ad Events Detected[/]",
                        box=box.ROUNDED, border_style=THEME['border'],
                        header_style=f"bold {THEME['primary']}",
                        show_lines=True,
                    )
                    t.add_column("#",        style=f"bold {THEME['primary']}", width=4, justify="center")
                    t.add_column("Package",  style=THEME['text'],              width=38)
                    t.add_column("Count",    style=f"bold {THEME['accent']}",  width=7,  justify="right")
                    t.add_column("Types",    style=THEME['warning'],           width=28)
                    t.add_column("Last Seen",style=THEME['muted'],             width=10)
                    for i, (p, d) in enumerate(sorted(ad_data.items(), key=lambda x: x[1]['count'], reverse=True), 1):
                        t.add_row(str(i), p, str(d['count']),
                                  ", ".join(f"{k}×{v}" for k,v in d['types'].items()), d['last_seen'])
                    console.print(t)
                else:
                    console.print(f"  [{THEME['muted']}]{TEXTS['ad_monitor_no_ads']}[/]")

            time.sleep(0.5)

    except KeyboardInterrupt:
        console.print(f"\n  [{THEME['warning']}]{TEXTS['ad_monitor_stopped']}[/]")

    # Final report
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['ad_monitor_final']} [/]", style=THEME['border']))

    if not ad_data:
        console.print(f"\n  [{THEME['success']}]{TEXTS['ad_monitor_clean']}[/]\n")
        return

    if RICH_AVAILABLE:
        t = Table(
            title=f"[bold {THEME['accent']}]{TEXTS['ad_monitor_summary'].format(total=total_ads)}[/]",
            box=box.ROUNDED, border_style=THEME['border'],
            header_style=f"bold {THEME['primary']}", show_lines=True,
        )
        t.add_column("#",         style=f"bold {THEME['primary']}", width=4,  justify="center")
        t.add_column("Package",   style=THEME['text'],              width=38)
        t.add_column("Count",     style=f"bold {THEME['accent']}",  width=7,  justify="right")
        t.add_column("Types",     style=THEME['warning'],           width=28)
        t.add_column("Last Seen", style=THEME['muted'],             width=10)
        for i, (p, d) in enumerate(sorted(ad_data.items(), key=lambda x: x[1]['count'], reverse=True), 1):
            t.add_row(str(i), p, str(d['count']),
                      ", ".join(f"{k}×{v}" for k,v in d['types'].items()), d['last_seen'])
        console.print(t)
    else:
        for i, (p, d) in enumerate(ad_data.items(), 1):
            print(f"  [{i}] {p}: {d['count']} ads")

    console.print(f"\n  [{THEME['primary']}]{TEXTS['ad_monitor_total_events'].format(total=total_ads)}[/]\n")

    if ad_data and RICH_AVAILABLE:
        if Confirm.ask(f"  [{THEME['warning']}]  {TEXTS['ad_monitor_uninstall_any']}[/]"):
            selected = Prompt.ask(f"  {TEXTS['ad_monitor_enter_numbers']}")
            _bulk_uninstall(adb, list(ad_data.keys()), selected)

# ──────────────────────────────────────────────────────────────
#  BULK UNINSTALL HELPER
# ──────────────────────────────────────────────────────────────
def _bulk_uninstall(adb, pkg_list, selected_str):
    try:
        indices = [int(x.strip())-1 for x in selected_str.split(',') if x.strip().isdigit()]
        for idx in indices:
            if 0 <= idx < len(pkg_list):
                pkg = pkg_list[idx]
                if confirm_uninstall(pkg):
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['uninstalling'].format(pkg=pkg)}[/]")
                    success = adb.uninstall_package(pkg)
                    if success:
                        console.print(f"  [{THEME['success']}]{TEXTS['uninstall_success'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]{TEXTS['uninstall_fail'].format(pkg=pkg)}[/]")
                else:
                    console.print(f"  [{THEME['muted']}]{TEXTS['skipped'].format(pkg=pkg)}[/]")
    except Exception as e:
        console.print(f"  [{THEME['accent']}]✘  Invalid input. Skipping uninstall. ({e})[/]")

# ──────────────────────────────────────────────────────────────
#  SCAN RESULTS TABLE
# ──────────────────────────────────────────────────────────────
def _build_results_table(suspicious_list, packages_data, scan_name):
    table = Table(
        title=f"[bold {THEME['accent']}]🛑 {scan_name} — {len(suspicious_list)} Suspicious App{'s' if len(suspicious_list)!=1 else ''} Found[/]",
        box=box.ROUNDED,
        border_style=THEME['border'],
        header_style=f"bold {THEME['primary']}",
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column(TEXTS['col_hash'],            style=f"bold {THEME['primary']}", width=4,  justify="center")
    table.add_column(TEXTS['col_package'],      style=THEME['text'],              width=38)
    table.add_column(TEXTS['col_risk'],   style="",                         width=18, justify="center")
    table.add_column(TEXTS['col_suspicious'],   style="",                         width=11, justify="center")
    table.add_column(TEXTS['col_dangerous'],    style=THEME['warning'],           width=22)
    table.add_column(TEXTS['col_boot'],         style="",                         width=8,  justify="center")
    table.add_column(TEXTS['col_accessibility'],style="",                         width=13, justify="center")

    for idx, pkg in enumerate(suspicious_list, 1):
        data = packages_data[pkg]
        display_app_details(pkg, data, idx, table)

    return table

# ──────────────────────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────────────────────
def main():
    global TEXTS

    clear_screen()
    print_banner()

    if RICH_AVAILABLE:
        console.print(f"[bold yellow]{L10N['en']['select_lang']}[/bold yellow]")
        console.print("  1. العربية")
        console.print("  2. English")
        lang_choice = Prompt.ask("  >", choices=["1", "2"], default="1")
    else:
        print(L10N['en']['select_lang'])
        print("  1. العربية")
        print("  2. English")
        lang_choice = input("  > ").strip()
        if lang_choice not in ["1", "2"]:
            lang_choice = "1"

    if lang_choice == "1":
        TEXTS = L10N["ar"]
    else:
        TEXTS = L10N["en"]

    clear_screen()
    print_banner()

    if not RICH_AVAILABLE:
        print(TEXTS["no_rich"] + "\n")

    adb = ADBController()
    if not adb.check_adb():
        sys.exit(1)
    if not adb.select_device():
        sys.exit(1)

    try:
        while True:
            clear_screen()
            print_banner()
            print_menu()

            choice = get_user_choice()

            if choice == 9:
                console.print()
                console.print(Rule(style=THEME['muted']))
                console.print(Align.center(Text(TEXTS["goodbye"], style=f"bold {THEME['success']}")))
                console.print(Rule(style=THEME['muted']))
                console.print()
                break

            elif choice == 8:
                clear_screen()
                print_banner()
                manage_high_permission_apps(adb)
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 7:
                clear_screen()
                print_banner()
                manage_background_apps(adb)
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 6:
                clear_screen()
                print_banner()
                monitor_ads_passive(adb)
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice in [1, 2]:
                clear_screen()
                print_banner()
                scan_names = {1: TEXTS["menu_1"], 2: TEXTS["menu_2"]}
                suspicious_list, packages_data = perform_scan(adb, choice)

                clear_screen()
                print_banner()
                console.print()

                if not suspicious_list:
                    console.print(Panel(
                        Text(TEXTS["no_suspicious"], justify="center",
                             style=f"bold {THEME['success']}"),
                        border_style=THEME['success'], padding=(1, 4),
                    ))
                    input(f"\n  {TEXTS['press_enter']}")
                    continue

                if RICH_AVAILABLE:
                    console.print(_build_results_table(suspicious_list, packages_data, scan_names[choice]))
                else:
                    for idx, pkg in enumerate(suspicious_list, 1):
                        display_app_details(pkg, packages_data[pkg], idx)

                console.print()
                if RICH_AVAILABLE and Confirm.ask(f"  [{THEME['warning']}]  {TEXTS['uninstall_any']}[/]"):
                    selected = Prompt.ask(f"  {TEXTS['enter_numbers']}")
                    _bulk_uninstall(adb, suspicious_list, selected)

                report = Report()
                report.generate_report(packages_data)
                console.print(f"\n  [{THEME['success']}]{TEXTS['report_saved']}[/]")
                input(f"\n  {TEXTS['press_enter']}")

            elif choice == 3:
                clear_screen()
                print_banner()
                console.print()
                console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['menu_3']} [/]", style=THEME['border']))
                pkg = (Prompt.ask(f"\n  [{THEME['primary']}]{TEXTS['enter_package']}[/]") if RICH_AVAILABLE
                       else input(f"  {TEXTS['enter_package']}: ").strip())
                if pkg:
                    console.print(f"\n  [{THEME['primary']}]{TEXTS['analyzing_traffic'].format(pkg=pkg)}[/]\n")
                    connections = Analyzer.analyze_network_traffic(pkg)
                    if connections:
                        console.print(f"  [{THEME['accent']}]{TEXTS['ad_connections_detected']}[/]")
                        for c in connections:
                            console.print(f"    [{THEME['warning']}]–  {c}[/]")
                    else:
                        console.print(f"  [{THEME['success']}]{TEXTS['no_ad_connections']}[/]")
                input(f"\n  {TEXTS['press_enter']}")

            elif choice == 4:
                clear_screen()
                print_banner()
                console.print()
                report_dir = "logs"
                if os.path.exists(report_dir):
                    reports = sorted(
                        [f for f in os.listdir(report_dir) if f.startswith("report_")], reverse=True
                    )
                    if reports:
                        latest = reports[0]
                        console.print()
                        console.print(Rule(f"[bold {THEME['primary']}] {latest} [/]", style=THEME['border']))
                        with open(f"{report_dir}/{latest}", "r") as f:
                            console.print(Markdown(f.read()))
                    else:
                        console.print(f"\n  [{THEME['warning']}]{TEXTS['no_reports']}[/]")
                else:
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['reports_dir_not_found']}[/]")
                input(f"\n  {TEXTS['press_enter']}")

            elif choice == 5:
                clear_screen()
                print_banner()
                console.print()
                console.print(Rule(f"[bold {THEME['accent']}] {TEXTS['manual_uninstall_title']} [/]", style=THEME['border']))

                all_packages = adb.list_packages()
                if not all_packages:
                    console.print(f"\n  [{THEME['accent']}]{TEXTS['no_packages']}[/]")
                    input(f"\n  {TEXTS['press_enter']}")
                    continue

                user_packages = [pkg for pkg in all_packages if not Analyzer.is_system_package(pkg)]
                if not user_packages:
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['no_user_packages']}[/]")
                    input(f"\n  {TEXTS['press_enter']}")
                    continue

                if RICH_AVAILABLE:
                    table = Table(
                        title=f"[bold]{TEXTS['user_packages_title']}[/]",
                        box=box.ROUNDED,
                        border_style=THEME['border'],
                        header_style=f"bold {THEME['primary']}",
                    )
                    table.add_column(TEXTS['col_hash'], style=f"bold {THEME['primary']}", width=4, justify="center")
                    table.add_column(TEXTS['package_name_col'], style=THEME['text'])
                    for idx, pkg in enumerate(user_packages, 1):
                        table.add_row(str(idx), pkg)
                    console.print(table)
                else:
                    print(f"\n  {TEXTS['user_packages_title']}:")
                    for idx, pkg in enumerate(user_packages, 1):
                        print(f"    [{idx}] {pkg}")

                if RICH_AVAILABLE:
                    raw_input = Prompt.ask(
                        f"\n  [{THEME['primary']}]{TEXTS['enter_num_or_partial']}[/]"
                    )
                else:
                    raw_input = input(f"\n  {TEXTS['enter_num_or_partial']}: ").strip()

                raw_input = raw_input.strip()
                selected_packages = []

                if raw_input.replace(',', '').replace(' ', '').isdigit():
                    indices = [int(x.strip()) - 1 for x in raw_input.split(',') if x.strip().isdigit()]
                    for idx in indices:
                        if 0 <= idx < len(user_packages):
                            selected_packages.append(user_packages[idx])
                        else:
                            console.print(f"  [{THEME['accent']}]{TEXTS['invalid_index'].format(idx=idx+1)}[/]")
                else:
                    search_term = raw_input.lower()
                    matches = [pkg for pkg in user_packages if search_term in pkg.lower()]
                    if not matches:
                        console.print(f"  [{THEME['accent']}]{TEXTS['no_match_package'].format(term=raw_input)}[/]")
                    elif len(matches) == 1:
                        selected_packages.append(matches[0])
                    else:
                        console.print(f"\n  [{THEME['warning']}]{TEXTS['multiple_matches'].format(term=raw_input)}[/]")
                        if RICH_AVAILABLE:
                            t = Table(box=box.SIMPLE, border_style=THEME['border'])
                            t.add_column(TEXTS['col_hash'], style=f"bold {THEME['primary']}", width=4)
                            t.add_column(TEXTS['package_name_col'], style=THEME['text'])
                            for idx, pkg in enumerate(matches, 1):
                                t.add_row(str(idx), pkg)
                            console.print(t)
                        else:
                            for idx, pkg in enumerate(matches, 1):
                                print(f"    [{idx}] {pkg}")

                        if RICH_AVAILABLE:
                            choice_idx = Prompt.ask(f"\n  [{THEME['primary']}]{TEXTS['enter_number_choice']}[/]")
                        else:
                            choice_idx = input(f"\n  {TEXTS['enter_number_choice']}: ").strip()

                        if choice_idx.isdigit():
                            idx = int(choice_idx) - 1
                            if 0 <= idx < len(matches):
                                selected_packages.append(matches[idx])
                            else:
                                console.print(f"  [{THEME['accent']}]{TEXTS['invalid_selection']}[/]")
                        else:
                            console.print(f"  [{THEME['accent']}]{TEXTS['invalid_input']}[/]")

                if selected_packages:
                    for pkg in selected_packages:
                        if confirm_uninstall(pkg):
                            console.print(f"\n  [{THEME['warning']}]{TEXTS['uninstalling'].format(pkg=pkg)}[/]")
                            success = adb.uninstall_package(pkg)
                            if success:
                                console.print(f"  [{THEME['success']}]{TEXTS['uninstall_success'].format(pkg=pkg)}[/]")
                            else:
                                console.print(f"  [{THEME['accent']}]{TEXTS['uninstall_fail'].format(pkg=pkg)}[/]")
                        else:
                            console.print(f"  [{THEME['muted']}]{TEXTS['skipped'].format(pkg=pkg)}[/]")
                else:
                    console.print(f"\n  [{THEME['muted']}]{TEXTS['no_packages_selected']}[/]")

                input(f"\n  {TEXTS['press_enter']}")

            else:
                console.print(f"\n  [{THEME['accent']}]{TEXTS['invalid_option']}[/]")
                time.sleep(1)

    except KeyboardInterrupt:
        console.print()
        console.print(Rule(style=THEME['muted']))
        console.print(Align.center(Text(TEXTS["goodbye_ctrl_c"], style=f"bold {THEME['success']}")))
        console.print(Rule(style=THEME['muted']))
        console.print()
        sys.exit(0)

if __name__ == "__main__":
    main()