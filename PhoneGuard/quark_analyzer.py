# quark_analyzer.py
import subprocess
import os

class QuarkAnalyzer:
    @staticmethod
    def analyze(apk_path):
        """تحليل APK باستخدام Quark-Engine (سطر الأوامر)"""
        if not os.path.exists(apk_path):
            return {"error": "APK file not found"}

        try:
            # استخدام quark-engine في سطر الأوامر (أسهل)
            result = subprocess.run(
                ["quark", "-a", apk_path, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                return {"error": "Quark analysis failed", "details": result.stderr}
            # تحليل الناتج (JSON)
            import json
            output = result.stdout
            if not output:
                return {"error": "No output from Quark"}
            try:
                data = json.loads(output)
                return {"success": True, "data": data}
            except:
                return {"error": "Invalid JSON output"}
        except Exception as e:
            return {"error": str(e)}