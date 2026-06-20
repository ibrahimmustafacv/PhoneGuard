# gui.py
import tkinter as tk
from tkinter import ttk, messagebox
from adb_controller import ADBController
from analyzer import Analyzer
from quark_analyzer import QuarkAnalyzer
import threading

class PhoneGuardGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PhoneGuard - Android Scanner")
        self.root.geometry("900x600")
        self.root.configure(bg='#1e1e2e')

        self.adb = ADBController()
        self.packages_data = {}
        self.suspicious_list = []

        self.create_widgets()
        self.check_adb()

    def create_widgets(self):
        # العنوان
        title = tk.Label(self.root, text="PhoneGuard v2.0", font=("Arial", 20, "bold"), fg="#4fc3f7", bg="#1e1e2e")
        title.pack(pady=10)

        # إطار الأزرار
        frame_buttons = tk.Frame(self.root, bg="#1e1e2e")
        frame_buttons.pack(pady=10)

        btn_scan = tk.Button(frame_buttons, text="🔍 Scan", command=self.start_scan, bg="#4fc3f7", fg="#000", padx=20)
        btn_scan.pack(side=tk.LEFT, padx=10)

        btn_uninstall = tk.Button(frame_buttons, text="🗑️ Uninstall Selected", command=self.uninstall_selected, bg="#ef5350", fg="#fff", padx=20)
        btn_uninstall.pack(side=tk.LEFT, padx=10)

        btn_refresh = tk.Button(frame_buttons, text="🔄 Refresh", command=self.refresh, bg="#78909c", fg="#fff", padx=20)
        btn_refresh.pack(side=tk.LEFT, padx=10)

        # إطار الجدول
        frame_table = tk.Frame(self.root, bg="#1e1e2e")
        frame_table.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.tree = ttk.Treeview(frame_table, columns=("Package", "Risk", "Dangerous Perms", "Boot", "Ads", "Accessibility"), show="headings")
        self.tree.heading("Package", text="Package")
        self.tree.heading("Risk", text="Risk Score")
        self.tree.heading("Dangerous Perms", text="Dangerous Perms")
        self.tree.heading("Boot", text="Boot Receiver")
        self.tree.heading("Ads", text="Ads Libraries")
        self.tree.heading("Accessibility", text="Accessibility")
        self.tree.column("Package", width=150)
        self.tree.column("Risk", width=80)
        self.tree.column("Dangerous Perms", width=200)
        self.tree.column("Boot", width=80)
        self.tree.column("Ads", width=100)
        self.tree.column("Accessibility", width=100)

        scrollbar = ttk.Scrollbar(frame_table, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # حالة
        self.status_label = tk.Label(self.root, text="Ready", fg="#aaa", bg="#1e1e2e")
        self.status_label.pack(pady=5)

    def check_adb(self):
        if not self.adb.check_adb():
            messagebox.showerror("Error", "ADB not found. Please install ADB.")
            self.root.quit()

    def start_scan(self):
        self.status_label.config(text="Scanning...")
        threading.Thread(target=self.scan_thread, daemon=True).start()

    def scan_thread(self):
        try:
            if not self.adb.select_device():
                self.status_label.config(text="No device selected.")
                return

            packages = self.adb.list_packages()
            if not packages:
                self.status_label.config(text="No packages found.")
                return

            self.packages_data = {}
            self.suspicious_list = []
            for pkg in packages:
                perms = self.adb.get_package_permissions(pkg)
                dangerous = Analyzer.analyze_permissions(perms)
                score = Analyzer.get_risk_score(dangerous)
                suspicious = Analyzer.is_suspicious(dangerous)

                # تحليل إضافي (Boot, Ads, Accessibility) - سيتم تحسينه لاحقاً
                # محاكاة للعرض
                boot = Analyzer.check_boot_receiver("")  # سيتم استكماله
                ads = []
                accessibility = False

                self.packages_data[pkg] = {
                    "dangerous": dangerous,
                    "score": score,
                    "suspicious": suspicious,
                    "boot": boot,
                    "ads": ads,
                    "accessibility": accessibility
                }
                if suspicious:
                    self.suspicious_list.append(pkg)

            self.update_table()
            self.status_label.config(text=f"Scan complete. Found {len(self.suspicious_list)} suspicious apps.")
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")

    def update_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for pkg, data in self.packages_data.items():
            self.tree.insert("", tk.END, values=(
                pkg,
                data["score"],
                ", ".join(data["dangerous"]),
                "Yes" if data["boot"] else "No",
                ", ".join(data["ads"]) if data["ads"] else "None",
                "Yes" if data["accessibility"] else "No"
            ))

    def uninstall_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Info", "No app selected.")
            return
        for item in selected:
            pkg = self.tree.item(item, "values")[0]
            if messagebox.askyesno("Confirm", f"Uninstall {pkg}?"):
                result = self.adb.uninstall_package(pkg)
                if "Success" in result:
                    messagebox.showinfo("Success", f"{pkg} uninstalled.")
                    self.refresh()
                else:
                    messagebox.showerror("Error", f"Failed to uninstall {pkg}.")

    def refresh(self):
        self.start_scan()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PhoneGuardGUI()
    app.run()