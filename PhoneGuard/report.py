import os
from datetime import datetime

class Report:
    def __init__(self):
        self.logs_dir = "logs"
        os.makedirs(self.logs_dir, exist_ok=True)

    def generate_report(self, packages_data):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.logs_dir}/report_{timestamp}.txt"
        with open(filename, "w") as f:
            f.write("=== PhoneGuard v5.0 Advanced Report ===\n")
            f.write(f"Generated: {datetime.now()}\n\n")
            for pkg, data in packages_data.items():
                f.write(f"Package: {pkg}\n")
                f.write(f"  Risk Score: {data['score']}/10\n")
                f.write(f"  Suspicious: {'Yes' if data['suspicious'] else 'No'}\n")
                
                if data['dangerous']:
                    f.write(f"  Dangerous Permissions: {', '.join(data['dangerous'])}\n")
                if data.get('boot'):
                    f.write(f"  Boot Receiver: Yes\n")
                if data.get('ads'):
                    f.write(f"  Ads Libraries: {', '.join(data['ads'])}\n")
                if data.get('accessibility'):
                    f.write(f"  Accessibility: Yes\n")
                
                if data.get('quark_results'):
                    f.write("  Quark Analysis:\n")
                    for qr in data['quark_results']:
                        if isinstance(qr, dict):
                            rule = qr.get('rule', 'Unknown')
                            confidence = qr.get('confidence', 'N/A')
                            desc = qr.get('description', '')
                            f.write(f"    - {rule} (Confidence: {confidence}%)\n")
                            if desc:
                                f.write(f"      → {desc}\n")
                
                if data.get('ad_connections'):
                    f.write("  Ad Network Connections:\n")
                    for conn in data['ad_connections']:
                        f.write(f"    - {conn}\n")
                
                if data.get('behavioral_indicators'):
                    f.write("  Behavioral Indicators:\n")
                    for ind in data['behavioral_indicators']:
                        f.write(f"    - {ind}\n")
                
                if data.get('suspicious_reasons'):
                    f.write("  Suspicious Reasons:\n")
                    for reason in data['suspicious_reasons']:
                        f.write(f"    - {reason}\n")
                f.write("\n")
        return filename