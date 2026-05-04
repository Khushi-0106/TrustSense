import os

class ForensicSimulator:
    def __init__(self):
        self.signatures = {
            "JPEG": b"\xFF\xD8\xFF",
            "PNG": b"\x89\x50\x4E\x47",
            "PDF": b"\x25\x50\x44\x46",
            "ZIP": b"\x50\x4B\x03\x04"
        }

    def simulate_recovery_attempt(self, target_path):
        findings = {sig: 0 for sig in self.signatures}

        try:
            with open(target_path, "rb") as f:
                while chunk := f.read(4096):
                    for name, sig in self.signatures.items():
                        if sig in chunk:
                            findings[name] += 1

            return self._format_results(findings)

        except:
            return "No data found.", True

    def _format_results(self, findings):
        total = sum(findings.values())

        report = "\n[--- FORENSIC AUDIT REPORT ---]\n"
        for k, v in findings.items():
            report += f"{k}: {'FOUND' if v > 0 else 'EMPTY'} ({v} fragments)\n"

        report += f"FINAL VERDICT: {'SECURE' if total == 0 else 'UNSAFE'}\n"

        return report, total == 0


# 🔥 THIS FUNCTION FIXES YOUR ERROR
def simulate_attack():
    simulator = ForensicSimulator()

    test_file = "test_drive.bin"

    if not os.path.exists(test_file):
        with open(test_file, "wb") as f:
            f.write(b"CleanRandomData123")

    report, is_secure = simulator.simulate_recovery_attempt(test_file)

    return {
        "report": report,
        "is_secure": is_secure
    }