# analyzer.py
import os
import zipfile
import time
import subprocess
import re
from config import DANGEROUS_PERMISSIONS, AD_LIBRARIES, AD_SERVERS, SYSTEM_PACKAGES, TRUSTED_APPS, QUARK_RULES

class Analyzer:
    @staticmethod
    def is_system_package(package):
        return any(package.startswith(pkg) or package == pkg for pkg in SYSTEM_PACKAGES)

    @staticmethod
    def is_trusted_app(package):
        return any(package.startswith(pkg) or package == pkg for pkg in TRUSTED_APPS)

    @staticmethod
    def analyze_permissions(permissions):
        return [p for p in permissions if p in DANGEROUS_PERMISSIONS]

    @staticmethod
    def get_risk_score(dangerous_perms, quark_results, ad_network_connections, behavioral_indicators):
        score = 0
        score += len(dangerous_perms) * 2
        if quark_results:
            for result in quark_results:
                if result.get('confidence', 0) > 70:
                    score += 2
                elif result.get('confidence', 0) > 50:
                    score += 1
        if ad_network_connections:
            if dangerous_perms or quark_results:
                score += min(len(ad_network_connections) * 2, 6)
            else:
                score += min(len(ad_network_connections), 3)
        if behavioral_indicators:
            if "Popup window detected" in behavioral_indicators:
                score += 3
            if "Ad-related activity detected" in behavioral_indicators and "Toast notification" in behavioral_indicators:
                score += 2
            if "High memory usage" in behavioral_indicators:
                score += 2
            if "Frequent ads detected" in behavioral_indicators:
                score += 1
        return min(score, 10)

    @staticmethod
    def is_suspicious(score, dangerous_perms, quark_results, ad_network_connections, behavioral_indicators, package):
        if score >= 3:
            return True
        if len(dangerous_perms) >= 2 and quark_results:
            return True
        if behavioral_indicators:
            if "Popup window detected" in behavioral_indicators:
                return True
            if "Ad-related activity detected" in behavioral_indicators and "Toast notification" in behavioral_indicators:
                return True
            if "Frequent ads detected" in behavioral_indicators:
                return True
            if "High memory usage" in behavioral_indicators and dangerous_perms:
                return True
        if ad_network_connections and dangerous_perms:
            return True
        return False

    @staticmethod
    def parse_manifest(apk_path):
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                with zf.open('AndroidManifest.xml') as f:
                    return f.read().decode('utf-8', errors='ignore')
        except:
            return ""

    @staticmethod
    def check_boot_receiver(manifest_str):
        if not manifest_str:
            return False
        return "android.intent.action.BOOT_COMPLETED" in manifest_str

    @staticmethod
    def check_accessibility_service(manifest_str):
        if not manifest_str:
            return False
        return "BIND_ACCESSIBILITY_SERVICE" in manifest_str

    @staticmethod
    def check_ads_libraries(apk_path):
        try:
            from androguard.core.bytecodes.apk import APK
            from androguard.core.bytecodes.dvm import DalvikVMFormat
            a = APK(apk_path)
            dex = DalvikVMFormat(a.get_dex())
            classes = [c.get_name() for c in dex.get_classes()]
            return [lib for lib in AD_LIBRARIES if any(lib in c for c in classes)]
        except:
            return []

    @staticmethod
    def run_quark_analysis(apk_path):
        try:
            import quark
            from quark.quark import Quark
            q = Quark(apk_path)
            rules = q.run()
            results = []
            for rule in rules:
                rule_name = rule.rule_name
                confidence = rule.confidence
                description = rule.description
                for custom_rule in QUARK_RULES:
                    if custom_rule['pattern'] in rule_name or custom_rule['pattern'] in description:
                        confidence = max(confidence, custom_rule['confidence'])
                        description = custom_rule['description']
                        break
                results.append({
                    "rule": rule_name,
                    "confidence": min(confidence, 100),
                    "description": description
                })
            return results
        except Exception as e:
            return [{"error": f"Quark analysis failed: {str(e)}"}]

    # ─────────── تحليل الشبكة السريع (مدة 5 ثوانٍ) ───────────
    @staticmethod
    def analyze_network_traffic(package, duration=5):
        """
        تحليل حركة الشبكة للتطبيق للكشف عن اتصالات بخوادم إعلانية.
        يعتمد على logcat بشكل أساسي ليكون سريعاً، مع استخدام netstat كدعم.
        """
        try:
            connections = []
            domains_found = set()
            network_requests = 0

            # 1. استخدام netstat لرصد الاتصالات الحية (سريع)
            netstat_cmd = f"adb shell netstat -tupn 2>/dev/null | grep {package}"
            try:
                netstat_result = subprocess.run(netstat_cmd, shell=True, capture_output=True, text=True, timeout=3)
                if netstat_result.stdout:
                    for line in netstat_result.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 6:
                            remote = parts[4]
                            if ':' in remote:
                                ip, port = remote.split(':')
                                if ip and ip != '0.0.0.0' and ip != '127.0.0.1':
                                    network_requests += 1
            except:
                pass

            # 2. استخدام logcat لجلب النطاقات خلال 5 ثوانٍ
            subprocess.run("adb logcat -c", shell=True)
            # تشغيل التطبيق (محاكاة بسيطة)
            subprocess.run(f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1", shell=True)
            time.sleep(2)  # ننتظر 2 ثانية فقط
            # نأخذ سجلات الـ 3 ثواني الأخيرة
            result = subprocess.run("adb logcat -d -t 3", shell=True, capture_output=True, text=False)
            try:
                log = result.stdout.decode('utf-8', errors='ignore')
            except:
                log = result.stdout.decode('latin-1', errors='ignore')

            patterns = [
                re.compile(r'https?://([a-zA-Z0-9.-]+)'),
                re.compile(r'Host:\s*([a-zA-Z0-9.-]+)'),
                re.compile(r'dns=([a-zA-Z0-9.-]+)'),
                re.compile(r'query\(([a-zA-Z0-9.-]+)\)'),
                re.compile(r'->\s*([a-zA-Z0-9.-]+)/'),
            ]
            lines = log.split('\n')
            for line in lines:
                if package in line:
                    for pat in patterns:
                        matches = pat.findall(line)
                        for m in matches:
                            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', m) and '.' in m:
                                domains_found.add(m)
                                network_requests += 1

            # مقارنة النطاقات مع خوادم الإعلانات
            ad_connections = []
            for domain in domains_found:
                for ad in AD_SERVERS:
                    if ad in domain or domain in ad:
                        ad_connections.append(domain)
                        break

            # إيقاف التطبيق
            subprocess.run(f"adb shell am force-stop {package}", shell=True)

            return {
                "connections": list(set(ad_connections)),
                "requests_count": network_requests,
                "domains_found": list(domains_found)
            }

        except Exception as e:
            return {"error": str(e), "connections": [], "requests_count": 0}

    # ─────────── تحليل السلوك السريع (مدة 10 ثوانٍ) ───────────
    @staticmethod
    def monitor_ad_behavior(package, duration=10):
        """
        مراقبة سريعة للسلوك: محاكاة تفاعل بسيطة، قراءة logcat، ومراقبة الذاكرة.
        """
        try:
            indicators = []
            ad_count = 0
            popup_count = 0
            memory_kb = 0

            # تشغيل التطبيق
            subprocess.run(f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1", shell=True)
            time.sleep(2)

            # محاكاة تفاعل بسيطة (تمريرين فقط)
            for _ in range(2):
                subprocess.run("adb shell input swipe 500 1000 500 300", shell=True)
                time.sleep(0.5)
                subprocess.run("adb shell input tap 500 800", shell=True)
                time.sleep(0.5)

            # جمع السجلات
            cmd = f"adb logcat -d -t {duration} | grep -E 'AlertDialog|WindowManager|Toast|AdView|InterstitialAd|RewardedAd|PopupWindow'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=duration+2)
            output = result.stdout

            if "AlertDialog" in output or "WindowManager" in output or "PopupWindow" in output:
                indicators.append("Popup window detected")
                popup_count += output.count("AlertDialog") + output.count("WindowManager") + output.count("PopupWindow")
                ad_count += popup_count

            if "AdView" in output or "InterstitialAd" in output or "RewardedAd" in output:
                indicators.append("Ad-related activity detected")
                ad_count += output.count("AdView") + output.count("InterstitialAd") + output.count("RewardedAd")

            if "Toast" in output:
                indicators.append("Toast notification detected")
                ad_count += output.count("Toast")

            # مراقبة الذاكرة بسرعة
            try:
                mem_result = subprocess.run(f"adb shell dumpsys meminfo {package}", shell=True, capture_output=True, text=True, timeout=5)
                if mem_result.stdout:
                    mem_match = re.search(r'TOTAL\s+(\d+)', mem_result.stdout)
                    if mem_match:
                        memory_kb = int(mem_match.group(1))
                        if memory_kb > 150000:
                            indicators.append("High memory usage")
            except:
                pass

            # إيقاف التطبيق
            subprocess.run(f"adb shell am force-stop {package}", shell=True)

            if ad_count > 5:
                indicators.append(f"Frequent ads detected ({ad_count} events)")

            return {
                "indicators": list(set(indicators)),
                "ad_count": ad_count,
                "popup_count": popup_count,
                "memory_kb": memory_kb
            }

        except Exception as e:
            return {"error": str(e), "indicators": [f"Behavioral analysis error: {str(e)}"], "ad_count": 0, "popup_count": 0, "memory_kb": 0}

    # ─────────── تحليل APK محلي (بدون تغيير) ───────────
    @staticmethod
    def analyze_apk_file(apk_path):
        if not os.path.exists(apk_path):
            return {"error": "File not found"}

        result = {
            "dangerous": [],
            "score": 0,
            "suspicious": False,
            "boot": False,
            "ads": [],
            "accessibility": False,
            "quark_results": [],
            "ad_connections": [],
            "behavioral_indicators": [],
            "suspicious_reasons": []
        }

        manifest = Analyzer.parse_manifest(apk_path)
        result["boot"] = Analyzer.check_boot_receiver(manifest)
        result["accessibility"] = Analyzer.check_accessibility_service(manifest)

        try:
            from androguard.core.bytecodes.apk import APK
            a = APK(apk_path)
            permissions = a.get_permissions()
            perm_names = [p.split('.')[-1] for p in permissions]
            result["dangerous"] = [p for p in perm_names if p in DANGEROUS_PERMISSIONS]
        except:
            dangerous_from_manifest = []
            for perm in DANGEROUS_PERMISSIONS:
                if perm in manifest:
                    dangerous_from_manifest.append(perm)
            result["dangerous"] = dangerous_from_manifest

        result["ads"] = Analyzer.check_ads_libraries(apk_path)
        result["quark_results"] = Analyzer.run_quark_analysis(apk_path)
        result["score"] = Analyzer.get_risk_score(
            result["dangerous"],
            result["quark_results"],
            [],
            []
        )
        result["suspicious"] = Analyzer.is_suspicious(
            result["score"],
            result["dangerous"],
            result["quark_results"],
            [],
            [],
            apk_path
        )

        if result["dangerous"]:
            result["suspicious_reasons"].append(
                f"Has {len(result['dangerous'])} dangerous permissions: {', '.join(result['dangerous'])}"
            )
        if result["boot"]:
            result["suspicious_reasons"].append("Starts automatically with system (Boot Receiver)")
        if result["accessibility"]:
            result["suspicious_reasons"].append("Uses Accessibility Service (often abused by malware)")
        if result["ads"]:
            result["suspicious_reasons"].append(f"Contains ad libraries: {', '.join(result['ads'])}")
        if result["quark_results"]:
            result["suspicious_reasons"].append(f"Quark detected {len(result['quark_results'])} suspicious behavioral patterns")

        return result