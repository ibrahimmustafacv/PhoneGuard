import subprocess
import os

class ADBController:
    def __init__(self):
        self.device_serial = None

    def check_adb(self):
        try:
            subprocess.run(["adb", "version"], capture_output=True, check=True)
            return True
        except:
            print("[!] ADB not found. Please install it: sudo apt install adb")
            return False

    def get_devices(self):
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")[1:]
        devices = []
        for line in lines:
            if line.strip() and "device" in line:
                serial = line.split()[0]
                devices.append(serial)
        return devices

    def select_device(self):
        devices = self.get_devices()
        if not devices:
            print("[!] No devices connected.")
            return None
        if len(devices) == 1:
            self.device_serial = devices[0]
            print(f"[+] Device selected: {self.device_serial}")
            return self.device_serial
        print("[+] Multiple devices found:")
        for i, serial in enumerate(devices):
            print(f"  {i+1}. {serial}")
        choice = input("Enter number: ")
        try:
            self.device_serial = devices[int(choice)-1]
            return self.device_serial
        except:
            print("[!] Invalid choice.")
            return None

    def run_adb(self, command, as_root=False):
        if not self.device_serial:
            print("[!] No device selected.")
            return None
        cmd = ["adb", "-s", self.device_serial]
        if as_root:
            cmd.append("root")
        cmd.extend(command.split())
        try:
            # استخدام errors='ignore' لتجنب مشاكل الترميز
            result = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            return result.stdout.strip()
        except UnicodeDecodeError:
            # إذا حدث خطأ في الترميز، نحاول مرة أخرى مع encoding مختلف
            try:
                result = subprocess.run(cmd, capture_output=True, text=False)
                # محاولة فك الترميز باستخدام latin-1 (يتعامل مع جميع البايتات)
                return result.stdout.decode('latin-1', errors='ignore').strip()
            except:
                return ""

    def list_packages(self):
        output = self.run_adb("shell pm list packages")
        if not output:
            return []
        packages = []
        for line in output.split("\n"):
            if line.startswith("package:"):
                packages.append(line.replace("package:", "").strip())
        return packages

    def get_package_permissions(self, package):
        output = self.run_adb(f"shell dumpsys package {package}")
        if not output:
            return []
        permissions = []
        in_perms = False
        for line in output.split("\n"):
            if "granted permissions:" in line:
                in_perms = True
                continue
            if in_perms and line.strip() and ":" in line:
                perm = line.split(":")[0].strip()
                if perm.startswith("android.permission."):
                    permissions.append(perm.replace("android.permission.", ""))
            if in_perms and not line.strip():
                break
        return permissions

    def pull_apk(self, package):
        """سحب ملف APK من الجهاز إلى المجلد المحلي"""
        path_output = self.run_adb(f"shell pm path {package}")
        if not path_output:
            return None
        if "package:" in path_output:
            apk_path = path_output.split(":")[1].strip()
        else:
            return None
        local_path = f"apks/{package}.apk"
        os.makedirs("apks", exist_ok=True)
        result = self.run_adb(f"pull {apk_path} {local_path}")
        if result and "error" in result.lower():
            print(f"[!] Failed to pull APK for {package}")
            return None
        return local_path

    def uninstall_package(self, package):
        result = self.run_adb(f"uninstall {package}")
        return result and "Success" in result