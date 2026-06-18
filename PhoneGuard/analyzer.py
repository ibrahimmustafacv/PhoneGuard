# analyzer.py
import os
import zipfile
import time
import subprocess
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
        return min(score, 10)

    @staticmethod
    def is_suspicious(score, dangerous_perms, quark_results, ad_network_connections, behavioral_indicators, package):
        if Analyzer.is_trusted_app(package):
            return False
        if score >= 4:
            return True
        if len(dangerous_perms) >= 2 and quark_results:
            return True
        if behavioral_indicators:
            if "Popup window detected" in behavioral_indicators:
                if dangerous_perms:
                    return True
                if not Analyzer.is_trusted_app(package):
                    return True
            if "Ad-related activity detected" in behavioral_indicators and "Toast notification" in behavioral_indicators:
                if len(dangerous_perms) >= 1:
                    return True
        if ad_network_connections and dangerous_perms and quark_results:
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

    @staticmethod
    def analyze_network_traffic(package, duration=10):
        try:
            cmd = f"adb shell tcpdump -i any -c 50 -A 'host {package}'"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1", shell=True)
            time.sleep(duration)
            subprocess.run(f"adb shell am force-stop {package}", shell=True)
            output, _ = process.communicate(timeout=duration+5)
            output_str = output.decode('utf-8', errors='ignore')
            connections = []
            for server in AD_SERVERS:
                if server in output_str:
                    connections.append(server)
            return connections
        except Exception as e:
            return [f"Network analysis error: {str(e)}"]

    @staticmethod
    def monitor_ad_behavior(package, duration=30):
        try:
            subprocess.run(f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1", shell=True)
            time.sleep(3)
            cmd = f"adb logcat -d -t {duration} | grep -E 'AlertDialog|WindowManager|Toast|AdView|InterstitialAd|RewardedAd'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            subprocess.run(f"adb shell am force-stop {package}", shell=True)
            output = result.stdout
            indicators = []
            if "AlertDialog" in output or "WindowManager" in output:
                indicators.append("Popup window detected")
            if "AdView" in output or "InterstitialAd" in output or "RewardedAd" in output:
                indicators.append("Ad-related activity detected")
            if "Toast" in output:
                indicators.append("Toast notification detected")
            if "display" in output and "window" in output:
                indicators.append("New window displayed")
            ad_count = output.count("AdView") + output.count("InterstitialAd") + output.count("RewardedAd")
            if ad_count > 5:
                indicators.append("Frequent ads detected")
            return indicators
        except Exception as e:
            return [f"Behavioral analysis error: {str(e)}"]