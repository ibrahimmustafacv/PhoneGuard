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
import hashlib
import requests
import json
import subprocess
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
        "menu_2": "Deep Behavioral Scan (Fast)",
        "menu_2_desc": "Advanced behavior analysis in seconds",
        "menu_3": "Network Traffic Analysis",
        "menu_3_desc": "Inspect ad-server connections",
        "menu_4": "Uninstall App",
        "menu_4_desc": "Remove a package by name",
        "menu_5": "Real-Time Ad Monitor",
        "menu_5_desc": "Passive live monitoring (60s)",
        "menu_6": "Background Apps Manager",
        "menu_6_desc": "Show/Manage running background processes",
        "menu_7": "High Permissions Apps",
        "menu_7_desc": "Show apps with critical permissions",
        "menu_8": "Privacy Scan",
        "menu_8_desc": "Analyze apps accessing sensitive data",
        "menu_9": "VirusTotal Scan",
        "menu_9_desc": "Scan APK with VirusTotal API",
        "menu_10": "Local APK Analysis",
        "menu_10_desc": "Analyze an APK file from local storage",
        "menu_11": "Install APK",
        "menu_11_desc": "Install an APK file to the connected device",
        "menu_12": "View Last Report",
        "menu_12_desc": "Open the most recent scan report",
        "menu_13": "Exit",
        "menu_13_desc": "Close PhoneGuard",
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
        "invalid_option": "✘  Invalid option. Please choose 1–13.",
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
        # Privacy Scan
        "ps_title": "🔒 Privacy Scan",
        "ps_found": "✔  Found [bold]{count}[/bold] apps accessing sensitive data.",
        "ps_no_apps": "ℹ  No apps with privacy permissions found.",
        "ps_options": "Options: [U] Uninstall selected, [R] Revoke permissions selected, [A] Uninstall All, [D] Revoke All, [B] Back",
        "ps_enter_numbers": "Enter numbers (comma-separated, e.g. 1,3):",
        "ps_confirm_uninstall_all": "Are you sure you want to UNINSTALL all [bold]{count}[/bold] apps? Type 'yes' to confirm:",
        "ps_confirm_revoke_all": "Are you sure you want to REVOKE ALL permissions for [bold]{count}[/bold] apps? Type 'yes' to confirm:",
        "ps_revoking": "⏳  Revoking permissions for [bold]{pkg}[/bold]…",
        "ps_revoke_success": "✔  Revoked permissions for [bold]{pkg}[/bold].",
        "ps_revoke_fail": "✘  Failed to revoke permissions for [bold]{pkg}[/bold].",
        "ps_uninstalling": "⏳  Uninstalling [bold]{pkg}[/bold]…",
        "ps_uninstall_success": "✔  Uninstalled [bold]{pkg}[/bold].",
        "ps_uninstall_fail": "✘  Failed to uninstall [bold]{pkg}[/bold].",
        "ps_skipped": "⏭  Skipped {pkg}.",
        "ps_back": "↩  Returning to main menu.",
        "ps_col_perms": "Privacy Permissions",
        # VirusTotal
        "vt_title": "🛡️ VirusTotal Scan",
        "vt_enter_package": "Enter package name",
        "vt_pulling": "⏳  Pulling APK from device...",
        "vt_analyzing": "🔍  Checking file on VirusTotal...",
        "vt_not_found": "⚠  File not found in VirusTotal database. Uploading...",
        "vt_uploading": "✅  Uploaded successfully. Waiting for results...",
        "vt_timeout": "✘  Timeout. Please check the result manually later.",
        "vt_error": "✘  VirusTotal error: {error}",
        "vt_rate_limit": "✘  VirusTotal rate limit exceeded. Try again tomorrow.",
        "vt_unknown_error": "✘  Unexpected error: {error}",
        "vt_result_clean": "✅  No engines detected this file as malicious.",
        "vt_result_malicious": "🛑  {count} engine(s) detected this file as malicious!",
        "vt_stats": "📊  Statistics:\n"
                    "  ─────────────────────\n"
                    "  • Total engines : {total}\n"
                    "  • Malicious     : {malicious}\n"
                    "  • Suspicious    : {suspicious}\n"
                    "  • Undetected    : {undetected}\n"
                    "  • Harmless      : {harmless}\n"
                    "  🔗  Report link: {link}",
        # Install APK
        "install_title": "📲 Install APK",
        "install_enter_path": "Enter full path to APK file",
        "install_copying": "⏳  Copying file to device...",
        "install_installing": "⏳  Installing APK on device...",
        "install_success": "✅  APK installed successfully!",
        "install_fail": "✘  Installation failed: {error}",
        "install_file_not_found": "✘  File not found or not entered.",
        "install_confirm_unknown": "⚠  Installation from unknown sources must be enabled on the device.",
        "install_confirm_exists": "ℹ  App already exists. Installing with -r (replace) option.",
        # Deep Scan new columns
        "col_ads": "Ads Detected",
        "col_network": "Network Req.",
        "col_memory": "Memory (KB)",
        "skip_android": "⏭  Skipping system framework (android)",
    },
    "ar": {
        "app_title": "⚡  ماسح البرمجيات الخبيثة والإعلانات لأندرويد",
        "version": "الإصدار 5.0  |  2025",
        "developer": "✦  إبراهيم مصطفى",
        "select_lang": "Select Language / اختر اللغة [1/2]: ",
        "main_menu": "القائمة الرئيسية",
        "menu_1": "فحص ذكي شامل",
        "menu_1_desc": "موصى به — سريع ودقيق",
        "menu_2": "فحص سلوكي عميق (سريع)",
        "menu_2_desc": "تحليل سلوكي متقدم في ثوانٍ",
        "menu_3": "تحليل حركة الشبكة",
        "menu_3_desc": "فحص اتصالات خوادم الإعلانات",
        "menu_4": "إزالة تطبيق",
        "menu_4_desc": "إزالة حزمة بالاسم",
        "menu_5": "مراقبة الإعلانات لحظياً",
        "menu_5_desc": "مراقبة حية سلبية (60 ثانية)",
        "menu_6": "إدارة التطبيقات في الخلفية",
        "menu_6_desc": "عرض/إدارة العمليات الخلفية",
        "menu_7": "التطبيقات ذات الصلاحيات العالية",
        "menu_7_desc": "عرض التطبيقات التي لديها صلاحيات خطيرة",
        "menu_8": "تحليل الخصوصية",
        "menu_8_desc": "تحليل التطبيقات التي تصل إلى بيانات حساسة",
        "menu_9": "فحص VirusTotal",
        "menu_9_desc": "فحص APK باستخدام VirusTotal API",
        "menu_10": "تحليل APK محلي",
        "menu_10_desc": "تحليل ملف APK من المجلد المحلي",
        "menu_11": "تثبيت APK",
        "menu_11_desc": "تثبيت ملف APK على الجهاز المتصل",
        "menu_12": "عرض آخر تقرير",
        "menu_12_desc": "فتح أحدث تقرير فحص",
        "menu_13": "خروج",
        "menu_13_desc": "إغلاق PhoneGuard",
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
        "invalid_option": "✘  خيار غير صحيح. الرجاء الاختيار من 1 إلى 13.",
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
        # Privacy Scan
        "ps_title": "🔒 تحليل الخصوصية",
        "ps_found": "✔  تم العثور على [bold]{count}[/bold] تطبيق يصل إلى بيانات حساسة.",
        "ps_no_apps": "ℹ  لا توجد تطبيقات بصلاحيات خصوصية.",
        "ps_options": "الخيارات: [U] إلغاء تثبيت مختارة، [R] إلغاء صلاحيات مختارة، [A] إلغاء تثبيت الكل، [D] إلغاء صلاحيات الكل، [B] رجوع",
        "ps_enter_numbers": "أدخل الأرقام (مفصولة بفواصل، مثل 1,3):",
        "ps_confirm_uninstall_all": "هل أنت متأكد من إلغاء تثبيت جميع التطبيقات [bold]{count}[/bold]؟ اكتب 'yes' للتأكيد:",
        "ps_confirm_revoke_all": "هل أنت متأكد من إلغاء جميع صلاحيات الخصوصية لـ [bold]{count}[/bold] تطبيق؟ اكتب 'yes' للتأكيد:",
        "ps_revoking": "⏳  جاري إلغاء صلاحيات [bold]{pkg}[/bold]…",
        "ps_revoke_success": "✔  تم إلغاء صلاحيات [bold]{pkg}[/bold].",
        "ps_revoke_fail": "✘  فشل إلغاء صلاحيات [bold]{pkg}[/bold].",
        "ps_uninstalling": "⏳  جاري إزالة [bold]{pkg}[/bold]…",
        "ps_uninstall_success": "✔  تمت إزالة [bold]{pkg}[/bold].",
        "ps_uninstall_fail": "✘  فشلت إزالة [bold]{pkg}[/bold].",
        "ps_skipped": "⏭  تم تخطي {pkg}.",
        "ps_back": "↩  العودة إلى القائمة الرئيسية.",
        "ps_col_perms": "صلاحيات الخصوصية",
        # VirusTotal
        "vt_title": "🛡️ فحص VirusTotal",
        "vt_enter_package": "أدخل اسم الحزمة",
        "vt_pulling": "⏳  جاري سحب ملف APK من الجهاز...",
        "vt_analyzing": "🔍  جاري التحقق من الملف على VirusTotal...",
        "vt_not_found": "⚠  الملف غير موجود في قاعدة بيانات VirusTotal. جاري الرفع...",
        "vt_uploading": "✅  تم الرفع بنجاح. في انتظار النتيجة...",
        "vt_timeout": "✘  انتهى وقت الانتظار. حاول التحقق يدوياً لاحقاً.",
        "vt_error": "✘  خطأ في VirusTotal: {error}",
        "vt_rate_limit": "✘  تم تجاوز حد الاستخدام اليومي لـ VirusTotal. حاول غداً.",
        "vt_unknown_error": "✘  خطأ غير متوقع: {error}",
        "vt_result_clean": "✅  لم يتم اكتشاف هذا الملف بواسطة أي محرك مضاد للفيروسات.",
        "vt_result_malicious": "🛑  تم اكتشاف {count} محرك/محركات ضارة!",
        "vt_stats": "📊  الإحصائيات:\n"
                    "  ─────────────────────\n"
                    "  • إجمالي المحركات : {total}\n"
                    "  • ضارة           : {malicious}\n"
                    "  • مشبوهة         : {suspicious}\n"
                    "  • غير مكتشفة     : {undetected}\n"
                    "  • آمنة           : {harmless}\n"
                    "  🔗  رابط التقرير: {link}",
        # Install APK
        "install_title": "📲 تثبيت APK",
        "install_enter_path": "أدخل المسار الكامل لملف APK",
        "install_copying": "⏳  جاري نسخ الملف إلى الجهاز...",
        "install_installing": "⏳  جاري تثبيت APK على الجهاز...",
        "install_success": "✅  تم تثبيت APK بنجاح!",
        "install_fail": "✘  فشل التثبيت: {error}",
        "install_file_not_found": "✘  الملف غير موجود أو لم يتم إدخاله.",
        "install_confirm_unknown": "⚠  يجب تفعيل التثبيت من مصادر غير معروفة على الجهاز.",
        "install_confirm_exists": "ℹ  التطبيق موجود بالفعل. جاري التثبيت مع خيار -r (استبدال).",
        # Deep Scan new columns
        "col_ads": "الإعلانات",
        "col_network": "طلبات الشبكة",
        "col_memory": "الذاكرة (ك.ب)",
        "skip_android": "⏭  تخطي إطار النظام (android)",
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
#  MENU (محدث حتى 13)
# ──────────────────────────────────────────────────────────────
def print_menu():
    if not RICH_AVAILABLE:
        print("\n  ┌─────────────────────────────────────┐")
        print("  │           MAIN MENU                 │")
        print("  ├─────────────────────────────────────┤")
        print("  │  [1]  Smart Full Scan               │")
        print("  │  [2]  Deep Behavioral Scan (Fast)   │")
        print("  │  [3]  Network Traffic Analysis      │")
        print("  │  [4]  Uninstall App                 │")
        print("  │  [5]  Real-Time Ad Monitor          │")
        print("  │  [6]  Background Apps Manager       │")
        print("  │  [7]  High Permissions Apps         │")
        print("  │  [8]  Privacy Scan                  │")
        print("  │  [9]  VirusTotal Scan               │")
        print("  │  [10] Local APK Analysis            │")
        print("  │  [11] Install APK                   │")
        print("  │  [12] View Last Report              │")
        print("  │  [13] Exit                          │")
        print("  └─────────────────────────────────────┘\n")
        return

    menu_items = [
        ("1", "🔍", TEXTS["menu_1"], TEXTS["menu_1_desc"], THEME['success']),
        ("2", "🧬", TEXTS["menu_2"], TEXTS["menu_2_desc"], THEME['primary']),
        ("3", "🌐", TEXTS["menu_3"], TEXTS["menu_3_desc"], THEME['warning']),
        ("4", "🗑️", TEXTS["menu_4"], TEXTS["menu_4_desc"], THEME['accent']),
        ("5", "📡", TEXTS["menu_5"], TEXTS["menu_5_desc"], THEME['primary']),
        ("6", "🔄", TEXTS["menu_6"], TEXTS["menu_6_desc"], THEME['primary']),
        ("7", "🔓", TEXTS["menu_7"], TEXTS["menu_7_desc"], THEME['accent']),
        ("8", "🔒", TEXTS["menu_8"], TEXTS["menu_8_desc"], THEME['secondary']),
        ("9", "🛡️", TEXTS["menu_9"], TEXTS["menu_9_desc"], THEME['warning']),
        ("10", "📁", TEXTS["menu_10"], TEXTS["menu_10_desc"], THEME['secondary']),
        ("11", "📲", TEXTS["menu_11"], TEXTS["menu_11_desc"], THEME['success']),
        ("12", "📄", TEXTS["menu_12"], TEXTS["menu_12_desc"], THEME['secondary']),
        ("13", "🚪", TEXTS["menu_13"], TEXTS["menu_13_desc"], THEME['muted']),
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
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"],
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
        ads_detected = str(data.get('ads_detected', 0))
        network_req = str(data.get('network_requests', 0))
        memory_kb = str(data.get('memory_kb', 0)) if data.get('memory_kb', 0) > 0 else "N/A"
        table.add_row(
            f"[bold {THEME['primary']}]{index}[/]",
            f"[{THEME['text']}]{pkg}[/]",
            risk_badge(data['score']),
            yesno(data.get('suspicious', False)),
            dangerous_str,
            yesno(data.get('boot', False)),
            yesno(data.get('accessibility', False)),
            ads_detected,
            network_req,
            memory_kb,
        )
        return

    # Fallback plain
    print(f"\n  [{index}] Package: {pkg}")
    print(f"      Risk Score       : {data['score']}/10")
    print(f"      Dangerous Perms  : {', '.join(data['dangerous']) if data['dangerous'] else TEXTS['dangerous_none']}")
    print(f"      Boot Receiver    : {'Yes' if data.get('boot') else 'No'}")
    print(f"      Ads Libraries    : {', '.join(data.get('ads', [])) or TEXTS['dangerous_none']}")
    print(f"      Accessibility    : {'Yes' if data.get('accessibility') else 'No'}")
    print(f"      Ads Detected     : {data.get('ads_detected', 0)}")
    print(f"      Network Requests : {data.get('network_requests', 0)}")
    print(f"      Memory Usage     : {data.get('memory_kb', 0)} KB")

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
#  SCAN (محسن للسرعة مع الفحص العميق السريع)
# ──────────────────────────────────────────────────────────────
def perform_scan(adb, scan_type):
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['fetching_packages']} [/]", style=THEME['border']))

    raw_packages = adb.list_packages()
    if not raw_packages:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['no_packages']}[/]\n")
        return [], {}

    # إزالة التكرار وحزمة "android"
    packages_set = set(raw_packages)
    if "android" in packages_set:
        packages_set.remove("android")
        console.print(f"  [{THEME['muted']}]{TEXTS['skip_android']}[/]")

    packages = list(packages_set)

    if scan_type == 2:
        console.print(f"\n  [{THEME['warning']}]⚡  Fast Deep Scan: Analyzing all packages with light behavioral checks.[/]")
        console.print(f"  [{THEME['muted']}]ℹ  Network and behavior analysis will take ~5-10 seconds per app.[/]\n")

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

            if scan_type == 1:
                if Analyzer.is_system_package(pkg) or Analyzer.is_trusted_app(pkg):
                    progress.advance(task)
                    continue

            # جلب الصلاحيات
            perms   = adb.get_package_permissions(pkg)
            dangerous = Analyzer.analyze_permissions(perms)

            boot = False; ads_libs = []; accessibility = False
            quark_results = []; suspicious_reasons = []
            ad_connections = []; behavioral_indicators = []
            ads_detected = 0
            network_requests = 0
            memory_kb = 0

            apk_path = adb.pull_apk(pkg)
            if apk_path:
                manifest    = Analyzer.parse_manifest(apk_path)
                boot        = Analyzer.check_boot_receiver(manifest)
                accessibility = Analyzer.check_accessibility_service(manifest)
                ads_libs    = Analyzer.check_ads_libraries(apk_path)
                quark_results = Analyzer.run_quark_analysis(apk_path)

            # الفحص العميق السريع
            if scan_type == 2:
                console.print(f"  [{THEME['muted']}]⏳  Quick analysis for {pkg}...[/]")
                # تحليل الشبكة (مدة 5 ثوانٍ)
                net_result = Analyzer.analyze_network_traffic(pkg, duration=5)
                if isinstance(net_result, dict):
                    ad_connections = net_result.get('connections', [])
                    network_requests = net_result.get('requests_count', 0)
                else:
                    ad_connections = net_result if isinstance(net_result, list) else []

                # تحليل السلوك (مدة 10 ثوانٍ)
                behavior = Analyzer.monitor_ad_behavior(pkg, duration=10)
                if isinstance(behavior, dict):
                    behavioral_indicators = behavior.get('indicators', [])
                    ads_detected = behavior.get('ad_count', 0)
                    memory_kb = behavior.get('memory_kb', 0)
                else:
                    behavioral_indicators = behavior if isinstance(behavior, list) else []

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
            if scan_type == 2 and memory_kb > 150000:
                suspicious_reasons.append(f"High memory usage: {memory_kb} KB")

            is_target = suspicious if scan_type == 1 else (suspicious or quark_results or ad_connections or behavioral_indicators or ads_detected > 5 or memory_kb > 150000)

            if is_target:
                packages_data[pkg] = {
                    "dangerous": dangerous,
                    "score": score,
                    "suspicious": suspicious,
                    "boot": boot,
                    "ads": ads_libs,
                    "accessibility": accessibility,
                    "quark_results": quark_results,
                    "ad_connections": ad_connections,
                    "behavioral_indicators": behavioral_indicators,
                    "suspicious_reasons": suspicious_reasons,
                    "ads_detected": ads_detected,
                    "network_requests": network_requests,
                    "memory_kb": memory_kb,
                }
                suspicious_list.append(pkg)

            progress.advance(task)

    return suspicious_list, packages_data

# ──────────────────────────────────────────────────────────────
#  SCAN RESULTS TABLE (محدثة بأعمدة جديدة)
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
    table.add_column(TEXTS['col_hash'], style=f"bold {THEME['primary']}", width=4, justify="center")
    table.add_column(TEXTS['col_package'], style=THEME['text'], width=30)
    table.add_column(TEXTS['col_risk'], style="", width=16, justify="center")
    table.add_column(TEXTS['col_suspicious'], style="", width=11, justify="center")
    table.add_column(TEXTS['col_dangerous'], style=THEME['warning'], width=18)
    table.add_column(TEXTS['col_boot'], style="", width=8, justify="center")
    table.add_column(TEXTS['col_accessibility'], style="", width=13, justify="center")
    table.add_column(TEXTS['col_ads'], style=THEME['warning'], width=12, justify="center")
    table.add_column(TEXTS['col_network'], style=THEME['primary'], width=12, justify="center")
    table.add_column(TEXTS['col_memory'], style=THEME['muted'], width=12, justify="center")

    for idx, pkg in enumerate(suspicious_list, 1):
        data = packages_data[pkg]
        display_app_details(pkg, data, idx, table)

    return table

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

    running_set = set()
    ps_output = None

    try:
        ps_output = adb.run_adb("shell ps -A -o NAME,STATE")
        if ps_output:
            for line in ps_output.splitlines():
                line = line.strip()
                if line and line != "NAME STATE" and line != "NAME" and line != "name" and '.' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        name = parts[0]
                        if not name.startswith('[') and not name.startswith('kworker') and not name.startswith('sh '):
                            running_set.add(name)
    except:
        pass

    if not running_set:
        try:
            ps_output = adb.run_adb("shell ps -A -o NAME")
            if ps_output:
                for line in ps_output.splitlines():
                    line = line.strip()
                    if line and line != "NAME" and line != "name" and '.' in line:
                        if not line.startswith('[') and not line.startswith('kworker') and not line.startswith('sh '):
                            running_set.add(line)
        except:
            pass

    if not running_set:
        try:
            ps_output = adb.run_adb("shell ps -A")
            if ps_output:
                lines = ps_output.splitlines()
                if lines:
                    for line in lines[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 9:
                            name = parts[-1]
                            if '.' in name and not name.startswith('[') and not name.startswith('kworker') and not name.startswith('sh '):
                                running_set.add(name)
        except:
            pass

    if not running_set:
        try:
            ps_output = adb.run_adb("shell ps")
            if ps_output:
                lines = ps_output.splitlines()
                if lines:
                    for line in lines[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 9:
                            name = parts[-1]
                            if '.' in name and not name.startswith('[') and not name.startswith('kworker') and not name.startswith('sh '):
                                running_set.add(name)
        except:
            pass

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
#  HIGH PERMISSIONS MANAGER
# ──────────────────────────────────────────────────────────────
def manage_high_permission_apps(adb):
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['hp_title']} [/]", style=THEME['border']))

    all_packages = adb.list_packages()
    if not all_packages:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['no_packages']}[/]")
        return

    high_perm_apps = []
    for pkg in all_packages:
        if Analyzer.is_system_package(pkg) or Analyzer.is_trusted_app(pkg):
            continue
        perms = adb.get_package_permissions(pkg)
        dangerous = Analyzer.analyze_permissions(perms)
        if len(dangerous) >= 5:
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
                else:
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
                        console.print(f"  [{THEME['muted']}]ℹ  Some permissions could not be revoked. This may happen on some devices.[/]")
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
                        console.print(f"  [{THEME['muted']}]ℹ  Some permissions could not be revoked. This may happen on some devices.[/]")
            else:
                console.print(f"  [{THEME['muted']}]Cancelled.[/]")
            continue

# ──────────────────────────────────────────────────────────────
#  PRIVACY SCAN
# ──────────────────────────────────────────────────────────────
def manage_privacy_scan(adb):
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['ps_title']} [/]", style=THEME['border']))

    PRIVACY_PERMS = [
        "CAMERA",
        "RECORD_AUDIO",
        "ACCESS_FINE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "READ_SMS",
        "SEND_SMS",
        "RECEIVE_SMS",
        "READ_PHONE_STATE",
        "READ_CALL_LOG",
        "WRITE_CALL_LOG",
        "GET_ACCOUNTS",
        "BODY_SENSORS",
        "ACTIVITY_RECOGNITION",
        "PROCESS_OUTGOING_CALLS"
    ]

    all_packages = adb.list_packages()
    if not all_packages:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['no_packages']}[/]")
        return

    privacy_apps = []
    for pkg in all_packages:
        if Analyzer.is_system_package(pkg) or Analyzer.is_trusted_app(pkg):
            continue
        perms = adb.get_package_permissions(pkg)
        dangerous = Analyzer.analyze_permissions(perms)
        privacy_perms = [p for p in dangerous if p in PRIVACY_PERMS]
        if privacy_perms:
            privacy_apps.append((pkg, privacy_perms))

    if not privacy_apps:
        console.print(f"\n  [{THEME['warning']}]{TEXTS['ps_no_apps']}[/]")
        return

    console.print(f"\n  [{THEME['success']}]{TEXTS['ps_found'].format(count=len(privacy_apps))}[/]\n")

    if RICH_AVAILABLE:
        table = Table(box=box.ROUNDED, border_style=THEME['border'], header_style=f"bold {THEME['primary']}")
        table.add_column(TEXTS['col_hash'], style=f"bold {THEME['primary']}", width=4, justify="center")
        table.add_column(TEXTS['col_package'], style=THEME['text'], width=40)
        table.add_column(TEXTS['ps_col_perms'], style=THEME['warning'], width=30)
        for idx, (pkg, perms) in enumerate(privacy_apps, 1):
            table.add_row(str(idx), pkg, ", ".join(perms[:3]) + ("…" if len(perms)>3 else ""))
        console.print(table)
    else:
        print(f"\n  {TEXTS['ps_title']}:")
        for idx, (pkg, perms) in enumerate(privacy_apps, 1):
            print(f"    [{idx}] {pkg} ({len(perms)} privacy permissions)")

    while True:
        console.print(f"\n  [{THEME['primary']}]{TEXTS['ps_options']}[/]")
        if RICH_AVAILABLE:
            action = Prompt.ask("  >", choices=["U", "R", "A", "D", "B"], default="B")
        else:
            action = input("  > ").strip().upper()
            if action not in ["U", "R", "A", "D", "B"]:
                action = "B"

        if action == "B":
            console.print(f"\n  [{THEME['muted']}]{TEXTS['ps_back']}[/]")
            break

        if action == "U" or action == "R":
            if action == "U":
                console.print(f"\n  [{THEME['primary']}]أدخل أرقام التطبيقات التي تريد إلغاء تثبيتها (مثال: 1,3)[/]")
            else:
                console.print(f"\n  [{THEME['primary']}]أدخل أرقام التطبيقات التي تريد إلغاء صلاحياتها (مثال: 1,3)[/]")

            if RICH_AVAILABLE:
                selected_str = Prompt.ask(f"  [{THEME['primary']}]{TEXTS['ps_enter_numbers']}[/]")
            else:
                selected_str = input(f"  {TEXTS['ps_enter_numbers']}: ")

            indices = []
            try:
                for part in selected_str.split(','):
                    part = part.strip()
                    if part.isdigit():
                        idx = int(part) - 1
                        if 0 <= idx < len(privacy_apps):
                            indices.append(idx)
                        else:
                            console.print(f"  [{THEME['accent']}]✘  رقم {part} غير صحيح (يجب أن يكون بين 1 و {len(privacy_apps)}).[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]✘  '{part}' ليس رقماً صحيحاً.[/]")
            except:
                pass

            if not indices:
                console.print(f"  [{THEME['accent']}]✘  لم يتم اختيار أي تطبيق صحيح. الرجاء المحاولة مرة أخرى.[/]")
                continue

            for idx in indices:
                pkg, perms = privacy_apps[idx]
                if action == "U":
                    if confirm_uninstall(pkg):
                        console.print(f"\n  [{THEME['warning']}]{TEXTS['ps_uninstalling'].format(pkg=pkg)}[/]")
                        success = adb.uninstall_package(pkg)
                        if success:
                            console.print(f"  [{THEME['success']}]{TEXTS['ps_uninstall_success'].format(pkg=pkg)}[/]")
                        else:
                            console.print(f"  [{THEME['accent']}]{TEXTS['ps_uninstall_fail'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['muted']}]{TEXTS['ps_skipped'].format(pkg=pkg)}[/]")
                else:
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['ps_revoking'].format(pkg=pkg)}[/]")
                    failed = False
                    for perm in perms:
                        result = adb.run_adb(f"shell pm revoke {pkg} {perm}")
                        if "not revoke" in result or "not granted" in result or "Exception" in result:
                            console.print(f"    [{THEME['accent']}]✘  فشل إلغاء صلاحية {perm}.[/]")
                            failed = True
                    if not failed:
                        console.print(f"  [{THEME['success']}]{TEXTS['ps_revoke_success'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]{TEXTS['ps_revoke_fail'].format(pkg=pkg)}[/]")
                        console.print(f"  [{THEME['muted']}]ℹ  Some permissions could not be revoked. This may happen on some devices.[/]")
            continue

        if action == "A":
            if Confirm.ask(f"\n  [{THEME['warning']}]{TEXTS['ps_confirm_uninstall_all'].format(count=len(privacy_apps))}[/]"):
                for pkg, _ in privacy_apps:
                    if confirm_uninstall(pkg):
                        console.print(f"\n  [{THEME['warning']}]{TEXTS['ps_uninstalling'].format(pkg=pkg)}[/]")
                        success = adb.uninstall_package(pkg)
                        if success:
                            console.print(f"  [{THEME['success']}]{TEXTS['ps_uninstall_success'].format(pkg=pkg)}[/]")
                        else:
                            console.print(f"  [{THEME['accent']}]{TEXTS['ps_uninstall_fail'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['muted']}]{TEXTS['ps_skipped'].format(pkg=pkg)}[/]")
            continue

        if action == "D":
            if RICH_AVAILABLE:
                confirm_text = Prompt.ask(f"\n  [{THEME['accent']}]{TEXTS['ps_confirm_revoke_all'].format(count=len(privacy_apps))}[/]")
            else:
                confirm_text = input(f"\n  {TEXTS['ps_confirm_revoke_all'].format(count=len(privacy_apps))}: ")

            if confirm_text.lower() == "yes":
                for pkg, perms in privacy_apps:
                    console.print(f"\n  [{THEME['warning']}]{TEXTS['ps_revoking'].format(pkg=pkg)}[/]")
                    failed = False
                    for perm in perms:
                        result = adb.run_adb(f"shell pm revoke {pkg} {perm}")
                        if "not revoke" in result or "not granted" in result or "Exception" in result:
                            console.print(f"    [{THEME['accent']}]✘  فشل إلغاء صلاحية {perm}.[/]")
                            failed = True
                    if not failed:
                        console.print(f"  [{THEME['success']}]{TEXTS['ps_revoke_success'].format(pkg=pkg)}[/]")
                    else:
                        console.print(f"  [{THEME['accent']}]{TEXTS['ps_revoke_fail'].format(pkg=pkg)}[/]")
                        console.print(f"  [{THEME['muted']}]ℹ  Some permissions could not be revoked. This may happen on some devices.[/]")
            else:
                console.print(f"  [{THEME['muted']}]Cancelled.[/]")
            continue

# ──────────────────────────────────────────────────────────────
#  VIRUSTOTAL SCAN
# ──────────────────────────────────────────────────────────────
def scan_with_virustotal(adb):
    import hashlib
    import requests
    import json
    import time

    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['vt_title']} [/]", style=THEME['border']))

    if RICH_AVAILABLE:
        pkg = Prompt.ask(f"\n  [{THEME['primary']}]{TEXTS['vt_enter_package']}[/]")
    else:
        pkg = input(f"\n  {TEXTS['vt_enter_package']}: ").strip()

    if not pkg:
        console.print(f"\n  [{THEME['accent']}]✘  No package entered.[/]")
        return

    console.print(f"\n  [{THEME['primary']}]{TEXTS['vt_pulling']}[/]")
    apk_path = adb.pull_apk(pkg)
    if not apk_path or not os.path.exists(apk_path):
        console.print(f"\n  [{THEME['accent']}]✘  Failed to pull APK for {pkg}.[/]")
        return

    if RICH_AVAILABLE:
        api_key = Prompt.ask(f"\n  [{THEME['primary']}]أدخل مفتاح API الخاص بـ VirusTotal (اتركه فارغاً للتخطي)[/]", default="")
    else:
        api_key = input("\n  Enter VirusTotal API key (leave empty to skip): ").strip()

    if not api_key:
        console.print(f"\n  [{THEME['warning']}]⚠  تم التخطي (لم يتم إدخال مفتاح API).[/]")
        return

    try:
        with open(apk_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        console.print(f"\n  [{THEME['accent']}]✘  Failed to compute SHA-256: {e}[/]")
        return

    console.print(f"\n  [{THEME['primary']}]{TEXTS['vt_analyzing']}[/]")

    report_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(report_url, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            total = stats.get('total', 0)
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            harmless = stats.get('harmless', 0)

            if malicious > 0:
                result_text = f"[bold {THEME['accent']}]🛑  تم اكتشاف {str(malicious)} محرك/محركات ضارة![/]"
            else:
                result_text = f"[bold {THEME['success']}]✅  لم يتم اكتشاف هذا الملف بواسطة أي محرك مضاد للفيروسات.[/]"

            console.print()
            console.print(Panel(
                f"{result_text}\n\n"
                f"  📊  الإحصائيات:\n"
                f"  ─────────────────────\n"
                f"  • إجمالي المحركات : {str(total)}\n"
                f"  • ضارة           : {str(malicious)}\n"
                f"  • مشبوهة         : {str(suspicious)}\n"
                f"  • غير مكتشفة     : {str(undetected)}\n"
                f"  • آمنة           : {str(harmless)}\n"
                f"  🔗  رابط التقرير: https://www.virustotal.com/gui/file/{file_hash}",
                border_style=THEME['primary'],
                title="🛡️  نتائج VirusTotal",
                padding=(1, 2)
            ))
            return

        elif response.status_code == 404:
            console.print(f"\n  [{THEME['warning']}]{TEXTS['vt_not_found']}[/]")

            upload_url = "https://www.virustotal.com/api/v3/files"
            with open(apk_path, 'rb') as f:
                files = {'file': (f"{pkg}.apk", f)}
                upload_response = requests.post(upload_url, headers=headers, files=files, timeout=60)

            if upload_response.status_code == 200:
                upload_data = upload_response.json()
                analysis_id = upload_data.get('data', {}).get('id')
                if analysis_id:
                    console.print(f"\n  [{THEME['success']}]{TEXTS['vt_uploading']}[/]")

                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    for i in range(10):
                        time.sleep(3)
                        analysis_response = requests.get(analysis_url, headers=headers, timeout=30)
                        if analysis_response.status_code == 200:
                            analysis_data = analysis_response.json()
                            status = analysis_data.get('data', {}).get('attributes', {}).get('status')
                            if status == 'completed':
                                final_response = requests.get(report_url, headers=headers, timeout=30)
                                if final_response.status_code == 200:
                                    final_data = final_response.json()
                                    attributes = final_data.get('data', {}).get('attributes', {})
                                    stats = attributes.get('last_analysis_stats', {})
                                    total = stats.get('total', 0)
                                    malicious = stats.get('malicious', 0)
                                    suspicious = stats.get('suspicious', 0)
                                    undetected = stats.get('undetected', 0)
                                    harmless = stats.get('harmless', 0)

                                    if malicious > 0:
                                        result_text = f"[bold {THEME['accent']}]🛑  تم اكتشاف {str(malicious)} محرك/محركات ضارة![/]"
                                    else:
                                        result_text = f"[bold {THEME['success']}]✅  لم يتم اكتشاف هذا الملف بواسطة أي محرك مضاد للفيروسات.[/]"

                                    console.print()
                                    console.print(Panel(
                                        f"{result_text}\n\n"
                                        f"  📊  الإحصائيات:\n"
                                        f"  ─────────────────────\n"
                                        f"  • إجمالي المحركات : {str(total)}\n"
                                        f"  • ضارة           : {str(malicious)}\n"
                                        f"  • مشبوهة         : {str(suspicious)}\n"
                                        f"  • غير مكتشفة     : {str(undetected)}\n"
                                        f"  • آمنة           : {str(harmless)}\n"
                                        f"  🔗  رابط التقرير: https://www.virustotal.com/gui/file/{file_hash}",
                                        border_style=THEME['primary'],
                                        title="🛡️  نتائج VirusTotal (تم الرفع)",
                                        padding=(1, 2)
                                    ))
                                    return
                                break
                        time.sleep(1)
                    console.print(f"\n  [{THEME['accent']}]{TEXTS['vt_timeout']}[/]")
                else:
                    console.print(f"\n  [{THEME['accent']}]✘  فشل رفع الملف: لم يتم استلام معرف التحليل.[/]")
            else:
                console.print(f"\n  [{THEME['accent']}]✘  فشل رفع الملف: {upload_response.status_code} - {upload_response.text[:200]}[/]")

        elif response.status_code == 429:
            console.print(f"\n  [{THEME['accent']}]{TEXTS['vt_rate_limit']}[/]")
        else:
            console.print(f"\n  [{THEME['accent']}]{TEXTS['vt_error'].format(error=f'{response.status_code} - {response.text[:200]}')}[/]")

    except requests.exceptions.Timeout:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['vt_timeout']}[/]")
    except Exception as e:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['vt_unknown_error'].format(error=str(e))}[/]")

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
#  ANALYZE LOCAL APK
# ──────────────────────────────────────────────────────────────
def analyze_local_apk():
    import os
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] 📁 {TEXTS['menu_10']} [/]", style=THEME['border']))

    if RICH_AVAILABLE:
        apk_path = Prompt.ask(f"\n  [{THEME['primary']}]{TEXTS['install_enter_path']}[/]")
    else:
        apk_path = input(f"\n  {TEXTS['install_enter_path']}: ").strip()

    if not apk_path or not os.path.exists(apk_path):
        console.print(f"\n  [{THEME['accent']}]{TEXTS['install_file_not_found']}[/]")
        return

    console.print(f"\n  [{THEME['primary']}]⏳  جاري تحليل الملف...[/]")
    data = Analyzer.analyze_apk_file(apk_path)

    if "error" in data:
        console.print(f"\n  [{THEME['accent']}]✘  فشل التحليل: {data['error']}[/]")
        return

    if RICH_AVAILABLE:
        table = Table(title=f"[bold]نتائج تحليل {os.path.basename(apk_path)}[/]", box=box.ROUNDED, border_style=THEME['border'])
        table.add_column("الميزة", style=f"bold {THEME['primary']}")
        table.add_column("القيمة", style=THEME['text'])
        table.add_row("نسبة الخطورة", risk_badge(data['score']))
        table.add_row("مشبوه", "✘ نعم" if data.get('suspicious') else "✔ لا")
        table.add_row("بدء تشغيل تلقائي", "✘ نعم" if data.get('boot') else "✔ لا")
        table.add_row("خدمة إمكانية الوصول", "✘ نعم" if data.get('accessibility') else "✔ لا")
        table.add_row("الصلاحيات الخطيرة", ", ".join(data.get('dangerous', [])) or "لا يوجد")
        table.add_row("مكتبات الإعلانات", ", ".join(data.get('ads', [])) or "لا يوجد")
        table.add_row("نتائج Quark", f"{len(data.get('quark_results', []))} نمط/أنماط مشبوهة")
        if data.get('suspicious_reasons'):
            reasons = "\n".join([f"• {r}" for r in data['suspicious_reasons']])
            table.add_row("أسباب الاشتباه", reasons)
        console.print(table)
    else:
        print(f"\n  نتائج تحليل {os.path.basename(apk_path)}:")
        print(f"  نسبة الخطورة: {data['score']}/10")
        print(f"  مشبوه: {'نعم' if data['suspicious'] else 'لا'}")
        print(f"  بدء تشغيل تلقائي: {'نعم' if data['boot'] else 'لا'}")
        print(f"  خدمة إمكانية الوصول: {'نعم' if data['accessibility'] else 'لا'}")
        print(f"  الصلاحيات الخطيرة: {', '.join(data['dangerous']) if data['dangerous'] else 'لا يوجد'}")
        print(f"  مكتبات الإعلانات: {', '.join(data['ads']) if data['ads'] else 'لا يوجد'}")
        print(f"  نتائج Quark: {len(data['quark_results'])} نمط/أنماط مشبوهة")
        if data.get('suspicious_reasons'):
            print("  أسباب الاشتباه:")
            for r in data['suspicious_reasons']:
                print(f"    - {r}")

# ──────────────────────────────────────────────────────────────
#  INSTALL APK
# ──────────────────────────────────────────────────────────────
def install_apk(adb):
    import os
    import subprocess

    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['install_title']} [/]", style=THEME['border']))

    if RICH_AVAILABLE:
        apk_path = Prompt.ask(f"\n  [{THEME['primary']}]{TEXTS['install_enter_path']}[/]")
    else:
        apk_path = input(f"\n  {TEXTS['install_enter_path']}: ").strip()

    if not apk_path or not os.path.exists(apk_path):
        console.print(f"\n  [{THEME['accent']}]{TEXTS['install_file_not_found']}[/]")
        return

    console.print(f"\n  [{THEME['primary']}]{TEXTS['install_installing']}[/]")

    cmd = ["adb", "-s", adb.device_serial, "install", "-r", "-t", apk_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout.strip() + result.stderr.strip()
    except subprocess.TimeoutExpired:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['install_fail'].format(error='Timeout')}[/]")
        return
    except Exception as e:
        console.print(f"\n  [{THEME['accent']}]{TEXTS['install_fail'].format(error=str(e))}[/]")
        return

    if "Success" in output:
        console.print(f"\n  [{THEME['success']}]{TEXTS['install_success']}[/]")
        return

    if "INSTALL_FAILED_ALREADY_EXISTS" in output:
        console.print(f"\n  [{THEME['warning']}]{TEXTS['install_confirm_exists']}[/]")
        console.print(f"\n  [{THEME['primary']}]⏳  محاولة التثبيت بدون خيارات إضافية...[/]")
        cmd2 = ["adb", "-s", adb.device_serial, "install", apk_path]
        try:
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=60)
            output2 = result2.stdout.strip() + result2.stderr.strip()
            if "Success" in output2:
                console.print(f"\n  [{THEME['success']}]{TEXTS['install_success']}[/]")
                return
            else:
                console.print(f"\n  [{THEME['accent']}]{TEXTS['install_fail'].format(error=output2 or 'Unknown error')}[/]")
        except Exception as e:
            console.print(f"\n  [{THEME['accent']}]{TEXTS['install_fail'].format(error=str(e))}[/]")
        return

    if "INSTALL_FAILED_USER_RESTRICTED" in output or "INSTALL_FAILED_INVALID_URI" in output:
        console.print(f"\n  [{THEME['warning']}]{TEXTS['install_confirm_unknown']}[/]")
        console.print(f"\n  [{THEME['accent']}]{TEXTS['install_fail'].format(error=output)}[/]")
        return

    console.print(f"\n  [{THEME['accent']}]{TEXTS['install_fail'].format(error=output or 'Unknown error (no output from adb)')}[/]")

# ──────────────────────────────────────────────────────────────
#  VIEW LAST REPORT
# ──────────────────────────────────────────────────────────────
def view_last_report():
    console.print()
    console.print(Rule(f"[bold {THEME['primary']}] {TEXTS['menu_12']} [/]", style=THEME['border']))
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

            if choice == 13:
                console.print()
                console.print(Rule(style=THEME['muted']))
                console.print(Align.center(Text(TEXTS["goodbye"], style=f"bold {THEME['success']}")))
                console.print(Rule(style=THEME['muted']))
                console.print()
                break

            elif choice == 12:
                clear_screen()
                print_banner()
                view_last_report()
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 11:
                clear_screen()
                print_banner()
                install_apk(adb)
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 10:
                clear_screen()
                print_banner()
                analyze_local_apk()
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 9:
                clear_screen()
                print_banner()
                scan_with_virustotal(adb)
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 8:
                clear_screen()
                print_banner()
                manage_privacy_scan(adb)
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 7:
                clear_screen()
                print_banner()
                manage_high_permission_apps(adb)
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 6:
                clear_screen()
                print_banner()
                manage_background_apps(adb)
                input(f"\n  {TEXTS['press_enter']}")
                continue

            elif choice == 5:
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
                    net_result = Analyzer.analyze_network_traffic(pkg)
                    if isinstance(net_result, dict):
                        connections = net_result.get('connections', [])
                        requests = net_result.get('requests_count', 0)
                        domains = net_result.get('domains_found', [])
                        if connections:
                            console.print(f"  [{THEME['accent']}]{TEXTS['ad_connections_detected']}[/]")
                            for c in connections:
                                console.print(f"    [{THEME['warning']}]–  {c}[/]")
                            console.print(f"\n  [{THEME['muted']}]ℹ  Total network requests: {requests}, Domains: {len(domains)}[/]")
                        else:
                            console.print(f"  [{THEME['success']}]{TEXTS['no_ad_connections']}[/]")
                    else:
                        connections = net_result if isinstance(net_result, list) else []
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
                console.print(Rule(f"[bold {THEME['accent']}] {TEXTS['menu_4']} [/]", style=THEME['border']))

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