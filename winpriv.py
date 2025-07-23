import subprocess, sys, os

class AdminCheck:
    def isAd(self):
        try:
            return os.getuid() == 0
        except AttributeError:
            try:
                subprocess.check_call(['net', 'session'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            except:  # This 'except' block was missing to catch errors from subprocess.check_call
                return False

class RegOps:
    def _run(self, cmd):
        try:
            return subprocess.run(cmd, check=True, capture_output=True, text=True, shell=True)
        except subprocess.CalledProcessError as e:
            raise Exception(f"Reg cmd fail: {e.stderr.strip()}")
        except FileNotFoundError:
            raise Exception("Reg cmd missing. Win only.")
        except Exception as e:
            raise Exception(f"Reg op error: {e}")

    def setV(self, k, v, t, d):
        try:
            self._run(f'reg add "{k}" /v "{v}" /t {t} /d {d} /f')
        except Exception as e:
            print(f"Set fail: {e}")

    def getV(self, k, v):
        try:
            out = self._run(f'reg query "{k}" /v "{v}"').stdout
            for line in out.strip().split('\n'):
                if v.lower() in line.lower():
                    p = line.split()
                    if len(p) >= 3:
                        return p[-1]
            return None
        except:
            return None

class PrivOpt:
    def __init__(self, n, k_p, v_n, stat_map, extra_k=None, extra_v=None, warn=None):
        self.n = n
        self.k_p = k_p
        self.v_n = v_n
        self.s_map = stat_map
        self.e_k = extra_k
        self.e_v = extra_v
        self.w = warn
        self.reg = RegOps()

    def tog(self, on):
        d = "1" if on else "0"
        self.reg.setV(self.k_p, self.v_n, "REG_DWORD", d)
        if self.e_k and self.e_v:
            self.reg.setV(self.e_k, self.e_v, "REG_DWORD", d)
        if not on and self.w:
            print(f"WARN: {self.w}")

    def stat(self):
        val = self.reg.getV(self.k_p, self.v_n)
        if self.e_k and self.e_v:
            e_val = self.reg.getV(self.e_k, self.e_v)
            if val in self.s_map and e_val in self.s_map:
                print(f"Status: {self.n} ({self.s_map[val]} / {self.s_map[e_val]})")
            else:
                print(f"Status: {self.n} (Mixed/Unknown)")
        else:
            print(f"Status: {self.n} ({self.s_map.get(val, 'Unknown')})")

def main():
    if not AdminCheck().isAd():
        print("\n" + "="*70)
        print("  Administration permissions required.")
        print("  Run as administrator.")
        print("="*70 + "\n")
        sys.exit(1)

    print("\n" + "="*70)
    print("        Win Priv Config (Admin)")
    print("="*70)
    print("  RISK: This code changes your registry, so create a restore point for your computer before use.")
    print("="*70 + "\n")

    opts = {
        "1": PrivOpt("Telemetry", r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry",
                     {"0x0": "Security", "0x1": "Basic", "0x2": "Enhanced", "0x3": "Full"}),
        "2": PrivOpt("Ads ID", r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled",
                     {"0x0": "DISABLED", "0x1": "ENABLED"}),
        "3": PrivOpt("Location", r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Location", "LocationSystemEnabled",
                     {"0x0": "DISABLED", "0x1": "ENABLED"}),
        "4": PrivOpt("Activity History", r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities",
                     {"0x0": "DISABLED", "0x1": "ENABLED"}, extra_k=r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System", extra_v="EnableActivityFeed"),
        "5": PrivOpt("SmartScreen", r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen",
                     {"0x0": "DISABLED", "0x1": "ENABLED"}, warn="Disabling SmartScreen reduces security."),
        "6": PrivOpt("Cortana/Search", r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled",
                     {"0x0": "DISABLED", "0x1": "ENABLED"}, extra_k=r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search", extra_v="CortanaConsent"),
    }

    while True:
        print("\n--- Opt ---")
        for k, v in opts.items():
            print(f"{k}. {v.n}")
        print("S. All Status")
        print("Q. Quit")

        c = input("Choice: ").strip().upper()

        if c == 'Q':
            print("Exiting, reboot for changes.")
            break
        elif c == 'S':
            print("\n--- Current Status ---")
            for k_s in sorted(opts.keys(), key=int):
                print(f"\n--- {opts[k_s].n} ---")
                opts[k_s].stat()
            print("\n-------------------------------------")
        elif c in opts:
            s_o = opts[c]
            print(f"\n--- {s_o.n} ---")
            print("1. Disable")
            print("2. Enable")
            print("3. Status")
            print("B. Back")

            sub_c = input("Sub-choice: ").strip().upper()
            if sub_c == '1':
                s_o.tog(False)
            elif sub_c == '2':
                s_o.tog(True)
            elif sub_c == '3':
                s_o.stat()
            elif sub_c == 'B':
                continue
            else:
                print("Incorrect sub choice.")
        else:
            print("Incorrect choice.")

if __name__ == "__main__":
    main()
