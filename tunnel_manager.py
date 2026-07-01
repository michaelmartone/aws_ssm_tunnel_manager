#!/usr/bin/env python3
"""
AWS SSM Tunnel Manager
Uses boto3 for AWS API calls; session-manager-plugin handles the actual WebSocket tunnel.

Requires:
  - Python 3.8+
  - boto3          (`pip install boto3`)
  - PyYAML         (`pip install pyyaml`)
  - AWS Session Manager Plugin  (https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
  - AWS CLI v2 (only for `aws sso login` browser flow)
"""

import json
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

# ── Auto-install dependencies ─────────────────────────────────────────────────

def _pip(*pkgs):
    subprocess.run(
        [sys.executable, "-m", "pip", "install", *pkgs, "--break-system-packages", "-q"],
        check=False,
    )

try:
    import yaml
except ImportError:
    _pip("pyyaml")
    import yaml

try:
    import boto3
    import botocore.exceptions
except ImportError:
    _pip("boto3")
    import boto3
    import botocore.exceptions

# ── Constants ─────────────────────────────────────────────────────────────────

SETTINGS_FILE     = Path(__file__).parent / ".tunnel_manager_settings.json"
DEFAULT_CONFIG    = Path(__file__).parent / "tunnels.yaml"
WIN32             = sys.platform == "win32"
NO_WINDOW         = subprocess.CREATE_NO_WINDOW if WIN32 else 0
RECONNECT_DELAY   = 5   # seconds between auto-reconnect attempts

# Errors that mean "token expired / no credentials" rather than a real AWS error
_CRED_ERRORS = {
    "ExpiredTokenException", "AuthExpiredException",
    "UnauthorizedException", "InvalidClientTokenId",
    "AccessDeniedException",
}

# ── Colour palette ────────────────────────────────────────────────────────────

C = {
    "bg":       "#1e1e2e",
    "panel":    "#24273a",
    "border":   "#313244",
    "text":     "#cdd6f4",
    "muted":    "#6c7086",
    "green":    "#a6e3a1",
    "red":      "#f38ba8",
    "yellow":   "#f9e2af",
    "lavender": "#b4befe",
    "btn":      "#313244",
    "btn_h":    "#45475a",
}

# ══════════════════════════════════════════════════════════════════════════════
# Settings
# ══════════════════════════════════════════════════════════════════════════════

def load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def save_settings(s: dict):
    SETTINGS_FILE.write_text(json.dumps(s, indent=2), encoding="utf-8")

# ══════════════════════════════════════════════════════════════════════════════
# Config
# ══════════════════════════════════════════════════════════════════════════════

BUILTIN_DEFAULT = {
    "profile": "VerifoneIntercardProd",
    "region": "eu-west-3",
    "instance_id": "i-0c057ac8ccfaf1a46",
    "check_interval": 30,
    "tunnels": [
        {
            "name": "RDP",
            "enabled": True,
            "document": "AWS-StartPortForwardingSession",
            "parameters": {"portNumber": "3389", "localPortNumber": "13389"},
        },
        {
            "name": "Bitbucket-Git",
            "enabled": True,
            "document": "AWS-StartPortForwardingSessionToRemoteHost",
            "parameters": {
                "host": "bitbucket.vficloud.net",
                "portNumber": "7999",
                "localPortNumber": "7999",
            },
        },
        {
            "name": "Bitbucket-HTTPS",
            "enabled": True,
            "document": "AWS-StartPortForwardingSessionToRemoteHost",
            "parameters": {
                "host": "bitbucket.vficloud.net",
                "portNumber": "443",
                "localPortNumber": "443",
            },
        },
        {
            "name": "Jenkins-HTTPS",
            "enabled": False,
            "document": "AWS-StartPortForwardingSessionToRemoteHost",
            "parameters": {
                "host": "jenkins2.verifone.com",
                "portNumber": "8443",
                "localPortNumber": "8443",
            },
        },
    ],
}

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def create_default_config(path: str):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(BUILTIN_DEFAULT, f, default_flow_style=False, sort_keys=False)

# ══════════════════════════════════════════════════════════════════════════════
# Tunnel states
# ══════════════════════════════════════════════════════════════════════════════

class S:
    STOPPED      = "Stopped"
    STARTING     = "Starting"
    RUNNING      = "Running"
    RECONNECTING = "Reconnecting"
    ERROR        = "Error"

# ══════════════════════════════════════════════════════════════════════════════
# TunnelManager
#
# Flow per tunnel:
#   boto3 ssm.start_session()  →  session-manager-plugin subprocess
#                                 (handles WebSocket + local port binding)
#   On exit/stop  →  boto3 ssm.terminate_session()
# ══════════════════════════════════════════════════════════════════════════════

class TunnelManager:
    def __init__(self, tunnel_cfg: dict, global_cfg: dict, on_update):
        self.cfg       = tunnel_cfg
        self.gcfg      = global_cfg
        self.on_update = on_update          # (name, state, message) → None
        self.name      = tunnel_cfg["name"]
        self.enabled   = tunnel_cfg.get("enabled", False)

        self._proc       = None             # subprocess.Popen | None
        self._thread     = None             # threading.Thread | None
        self._ssm_client = None             # boto3 SSM client | None
        self._session_id = None             # active SSM SessionId | None
        self._stop_evt   = threading.Event()
        self._generation = 0
        self._lock       = threading.Lock()

    # ── public ────────────────────────────────────────────────────────────────

    def start(self):
        if self._thread and self._thread.is_alive() and self.enabled:
            return
        self.enabled = True
        gen = self._generation
        t = threading.Thread(target=self._run_loop, args=(gen,), daemon=True)
        self._thread = t
        t.start()

    def stop(self):
        self.enabled = False
        self._generation += 1
        self._stop_evt.set()
        # Terminate process and SSM session under lock
        with self._lock:
            proc       = self._proc
            sid        = self._session_id
            ssm_client = self._ssm_client
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        if sid and ssm_client:
            try:
                ssm_client.terminate_session(SessionId=sid)
            except Exception:
                pass
        # Fresh event for next start()
        self._stop_evt = threading.Event()

    # ── internals ─────────────────────────────────────────────────────────────

    def _boto_session(self):
        return boto3.Session(
            profile_name=self.gcfg["profile"],
            region_name=self.gcfg["region"],
        )

    def _ssm_params(self) -> dict:
        """Convert config parameters to SSM API format (values must be lists)."""
        return {
            k: [v] if not isinstance(v, list) else v
            for k, v in self.cfg["parameters"].items()
        }

    def _describe(self) -> str:
        p = self.cfg["parameters"]
        return (
            f"localhost:{p.get('localPortNumber','?')}  →  "
            f"{p.get('host', 'instance')}:{p.get('portNumber','?')}"
        )

    def _run_loop(self, generation: int):
        stop_evt = self._stop_evt

        while self.enabled and self._generation == generation:
            self.on_update(self.name, S.STARTING, "Connecting…")

            # ── Step 1: create SSM session via boto3 ──────────────────────────
            session_id  = None
            ssm_client  = None
            try:
                bsession   = self._boto_session()
                ssm_client = bsession.client("ssm", region_name=self.gcfg["region"])
                params     = self._ssm_params()

                api_resp = ssm_client.start_session(
                    Target=self.gcfg["instance_id"],
                    DocumentName=self.cfg["document"],
                    Parameters=params,
                )
                session_id = api_resp["SessionId"]

            except botocore.exceptions.NoCredentialsError:
                self.on_update(self.name, S.ERROR, "No credentials — SSO login required")
                stop_evt.wait(RECONNECT_DELAY)
                continue
            except botocore.exceptions.ClientError as e:
                code = e.response["Error"]["Code"]
                if code in _CRED_ERRORS:
                    self.on_update(self.name, S.ERROR, "SSO token expired — click Re-login")
                else:
                    self.on_update(self.name, S.ERROR, f"AWS: {code}")
                stop_evt.wait(RECONNECT_DELAY)
                continue
            except Exception as e:
                msg = str(e)
                # Catch SSOTokenLoadError / TokenRetrievalError by message
                if "token" in msg.lower() or "sso" in msg.lower():
                    self.on_update(self.name, S.ERROR, "SSO token missing — click Re-login")
                else:
                    self.on_update(self.name, S.ERROR, msg[:80])
                stop_evt.wait(RECONNECT_DELAY)
                continue

            # ── Step 2: hand off to session-manager-plugin ────────────────────
            # The plugin needs the raw API response (minus ResponseMetadata)
            # plus the original request params, matching what the AWS CLI passes.
            plugin_response = json.dumps({
                "SessionId":  api_resp["SessionId"],
                "TokenValue": api_resp["TokenValue"],
                "StreamUrl":  api_resp["StreamUrl"],
            })
            request_params = json.dumps({
                "Target":       self.gcfg["instance_id"],
                "DocumentName": self.cfg["document"],
                "Parameters":   params,
            })
            endpoint = ssm_client.meta.endpoint_url

            cmd = [
                "session-manager-plugin",
                plugin_response,
                self.gcfg["region"],
                "StartSession",
                self.gcfg["profile"],
                request_params,
                endpoint,
            ]

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    creationflags=NO_WINDOW,
                )
            except FileNotFoundError:
                self._terminate_session(ssm_client, session_id)
                self.on_update(
                    self.name, S.ERROR,
                    "session-manager-plugin not found — install AWS Session Manager Plugin",
                )
                return   # no point retrying; it won't appear by itself
            except Exception as e:
                self._terminate_session(ssm_client, session_id)
                self.on_update(self.name, S.ERROR, str(e)[:80])
                stop_evt.wait(RECONNECT_DELAY)
                continue

            with self._lock:
                self._proc       = proc
                self._session_id = session_id
                self._ssm_client = ssm_client

            self.on_update(self.name, S.RUNNING, self._describe())
            proc.wait()

            # ── Step 3: clean up ──────────────────────────────────────────────
            self._terminate_session(ssm_client, session_id)
            with self._lock:
                self._proc       = None
                self._session_id = None
                self._ssm_client = None

            if not self.enabled or self._generation != generation:
                break

            try:
                err = (proc.stderr.read() or b"").decode(errors="replace").strip()
                err_hint = f" ({err[:80]})" if err else ""
            except Exception:
                err_hint = ""

            self.on_update(
                self.name, S.RECONNECTING,
                f"Reconnecting in {RECONNECT_DELAY}s…{err_hint}",
            )
            stop_evt.wait(RECONNECT_DELAY)

        self.on_update(self.name, S.STOPPED, "")

    @staticmethod
    def _terminate_session(client, session_id: str):
        if client and session_id:
            try:
                client.terminate_session(SessionId=session_id)
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# SSOMonitor — polls STS via boto3; no CLI needed
# ══════════════════════════════════════════════════════════════════════════════

class SSOMonitor:
    def __init__(self, profile: str, region: str, interval: int, on_update):
        self.profile   = profile
        self.region    = region
        self.interval  = interval
        self.on_update = on_update   # (active: bool, checked: str) → None
        self._stop     = threading.Event()
        self._thread   = None

    def _check(self) -> bool:
        try:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            sts = session.client("sts", region_name=self.region)
            sts.get_caller_identity()
            return True
        except botocore.exceptions.NoCredentialsError:
            return False
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            return code not in _CRED_ERRORS
        except Exception:
            return False

    def _loop(self):
        while not self._stop.is_set():
            self.on_update(self._check(), time.strftime("%H:%M:%S"))
            self._stop.wait(self.interval)

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def check_now(self):
        threading.Thread(
            target=lambda: self.on_update(self._check(), time.strftime("%H:%M:%S")),
            daemon=True,
        ).start()


# ══════════════════════════════════════════════════════════════════════════════
# GUI helpers
# ══════════════════════════════════════════════════════════════════════════════

def make_btn(parent, text, cmd, width=None) -> tk.Button:
    kw = dict(
        text=text, command=cmd,
        bg=C["btn"], fg=C["text"],
        activebackground=C["btn_h"], activeforeground=C["text"],
        relief="flat", padx=10, pady=3,
        font=("Segoe UI", 9), cursor="hand2", bd=0,
    )
    if width:
        kw["width"] = width
    return tk.Button(parent, **kw)

def make_label(parent, text="", fg=None, font_spec=("Segoe UI", 9),
               anchor="w", **kw) -> tk.Label:
    return tk.Label(
        parent, text=text, bg=C["panel"],
        fg=fg or C["text"], font=font_spec,
        anchor=anchor, **kw,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Application window
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AWS SSM Tunnel Manager")
        self.configure(bg=C["bg"])
        self.resizable(False, False)

        self._settings     = load_settings()
        self._cfg_path     = self._settings.get("config_path", "")
        self._config       = None
        self._managers     = {}   # name → TunnelManager
        self._sso          = None
        self._q            = queue.Queue()
        self._tunnel_rows  = {}   # name → {dot, status, toggle}

        self._build_ui()
        self._load_config()
        self._poll_queue()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        hdr = tk.Frame(self, bg=C["bg"])
        hdr.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(hdr, text="AWS SSM Tunnel Manager",
                 bg=C["bg"], fg=C["lavender"],
                 font=("Segoe UI", 13, "bold")).pack(side="left")

        # Config
        cfg_panel = self._section("Config File")
        cfg_inner = tk.Frame(cfg_panel, bg=C["panel"])
        cfg_inner.pack(fill="x", padx=8, pady=(2, 8))
        self._cfg_lbl = make_label(cfg_inner, fg=C["muted"], font_spec=("Segoe UI", 8))
        self._cfg_lbl.pack(side="left", fill="x", expand=True)
        make_btn(cfg_inner, "Browse…", self._browse).pack(side="right")

        # SSO
        sso_panel = self._section("SSO Session")
        self._sso_meta = make_label(sso_panel, fg=C["muted"], font_spec=("Segoe UI", 8))
        self._sso_meta.pack(anchor="w", padx=10, pady=(2, 0))
        sso_row = tk.Frame(sso_panel, bg=C["panel"])
        sso_row.pack(fill="x", padx=8, pady=(2, 8))
        self._sso_dot = make_label(sso_row, text="●", fg=C["muted"],
                                   font_spec=("Segoe UI", 13))
        self._sso_dot.pack(side="left")
        self._sso_txt = make_label(sso_row, text="Checking…", fg=C["muted"])
        self._sso_txt.pack(side="left", padx=(4, 0))
        make_btn(sso_row, "Check Now", self._sso_check_now).pack(side="right")
        make_btn(sso_row, "Re-login",  self._sso_login    ).pack(side="right", padx=(0, 4))

        # Tunnels
        self._tun_panel = self._section("Tunnels")
        self._tun_frame = tk.Frame(self._tun_panel, bg=C["panel"])
        self._tun_frame.pack(fill="x", padx=4, pady=(0, 4))

        # Bottom bar
        bot = tk.Frame(self, bg=C["bg"])
        bot.pack(fill="x", padx=12, pady=(4, 14))
        make_btn(bot, "Start All", self._start_all).pack(side="left", padx=(0, 4))
        make_btn(bot, "Stop All",  self._stop_all ).pack(side="left")
        make_btn(bot, "Quit",      self._quit     ).pack(side="right")

    def _section(self, title: str) -> tk.Frame:
        outer = tk.Frame(self, bg=C["border"])
        outer.pack(fill="x", padx=12, pady=3)
        tk.Label(outer, text=f"  {title}",
                 bg=C["border"], fg=C["muted"],
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", pady=(3, 0))
        inner = tk.Frame(outer, bg=C["panel"])
        inner.pack(fill="x", padx=1, pady=(0, 1))
        return inner

    def _build_tunnel_rows(self, tunnels: list):
        for w in self._tun_frame.winfo_children():
            w.destroy()
        self._tunnel_rows.clear()

        for t in tunnels:
            name    = t["name"]
            enabled = t.get("enabled", False)
            p       = t.get("parameters", {})
            local   = p.get("localPortNumber", "?")
            port    = p.get("portNumber", "?")
            host    = p.get("host", "instance")
            desc    = f"localhost:{local}  →  {host}:{port}"

            row = tk.Frame(self._tun_frame, bg=C["panel"])
            row.pack(fill="x", padx=4, pady=1)

            dot = tk.Label(row, text="●", bg=C["panel"],
                           fg=C["muted"], font=("Segoe UI", 12))
            dot.pack(side="left", padx=(4, 6))

            tk.Label(row, text=name, bg=C["panel"], fg=C["text"],
                     font=("Segoe UI", 10, "bold"), width=16,
                     anchor="w").pack(side="left")

            tk.Label(row, text=desc, bg=C["panel"], fg=C["muted"],
                     font=("Segoe UI", 9), width=40,
                     anchor="w").pack(side="left")

            status_lbl = tk.Label(row, text="Stopped", bg=C["panel"],
                                   fg=C["muted"], font=("Segoe UI", 9),
                                   width=36, anchor="w")
            status_lbl.pack(side="left", padx=(4, 0))

            tog = make_btn(row, "Stop" if enabled else "Start",
                           lambda n=name: self._toggle(n), width=6)
            tog.pack(side="right", padx=(4, 6), pady=3)

            self._tunnel_rows[name] = {"dot": dot, "status": status_lbl, "toggle": tog}

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_config(self):
        path = self._cfg_path
        if not path or not Path(path).exists():
            if not DEFAULT_CONFIG.exists():
                create_default_config(str(DEFAULT_CONFIG))
            path = str(DEFAULT_CONFIG)
            self._cfg_path = path

        self._cfg_lbl.config(text=path)
        try:
            self._config = load_config(path)
        except Exception as e:
            messagebox.showerror("Config Error", f"Could not load config:\n{e}")
            return

        self._apply_config()
        self._settings["config_path"] = path
        save_settings(self._settings)

    def _apply_config(self):
        for m in self._managers.values():
            m.stop()
        self._managers.clear()
        if self._sso:
            self._sso.stop()

        cfg = self._config
        self._sso_meta.config(
            text=(f"Profile: {cfg['profile']}   ·   Region: {cfg['region']}"
                  f"   ·   Instance: {cfg['instance_id']}"))

        tunnels = cfg.get("tunnels", [])
        self._build_tunnel_rows(tunnels)

        for t in tunnels:
            mgr = TunnelManager(t, cfg, self._on_tunnel)
            self._managers[t["name"]] = mgr
            if t.get("enabled", False):
                mgr.start()

        self._sso = SSOMonitor(
            cfg["profile"], cfg["region"],
            cfg.get("check_interval", 30),
            self._on_sso,
        )
        self._sso.start()

    def _browse(self):
        initial = str(Path(self._cfg_path).parent) if self._cfg_path else "."
        path = filedialog.askopenfilename(
            title="Select config file",
            filetypes=[("YAML files", "*.yaml *.yml"), ("All files", "*.*")],
            initialdir=initial,
        )
        if path:
            self._cfg_path = path
            self._load_config()

    # ── Tunnel control ────────────────────────────────────────────────────────

    def _toggle(self, name: str):
        mgr = self._managers.get(name)
        if mgr:
            mgr.stop() if mgr.enabled else mgr.start()

    def _start_all(self):
        for m in self._managers.values():
            if not m.enabled:
                m.start()

    def _stop_all(self):
        for m in self._managers.values():
            if m.enabled:
                m.stop()

    def _quit(self):
        for m in self._managers.values():
            m.stop()
        if self._sso:
            self._sso.stop()
        self.destroy()

    # ── SSO actions ───────────────────────────────────────────────────────────

    def _sso_check_now(self):
        if self._sso:
            self._sso_txt.config(text="Checking…", fg=C["muted"])
            self._sso.check_now()

    def _sso_login(self):
        if not self._config:
            return
        profile = self._config["profile"]
        messagebox.showinfo(
            "SSO Login",
            f"A browser window will open for SSO login.\nProfile: {profile}\n\n"
            "A terminal window will appear — wait for it to complete.",
        )
        def do_login():
            # boto3 cannot drive the SSO browser flow; the CLI handles it
            if WIN32:
                subprocess.Popen(
                    f'start cmd /k aws sso login --profile {profile}',
                    shell=True,
                )
            else:
                subprocess.Popen(
                    ["bash", "-c",
                     f"aws sso login --profile {profile}; "
                     "echo ''; echo 'Done — press Enter to close'; read"],
                )
            time.sleep(3)
            if self._sso:
                self._sso.check_now()
        threading.Thread(target=do_login, daemon=True).start()

    # ── Queue / render ────────────────────────────────────────────────────────

    def _on_tunnel(self, name: str, state: str, message: str):
        self._q.put(("t", name, state, message))

    def _on_sso(self, active: bool, checked: str):
        self._q.put(("s", active, checked))

    def _poll_queue(self):
        try:
            while True:
                msg = self._q.get_nowait()
                if msg[0] == "t":
                    self._render_tunnel(*msg[1:])
                elif msg[0] == "s":
                    self._render_sso(*msg[1:])
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _render_tunnel(self, name: str, state: str, message: str):
        row = self._tunnel_rows.get(name)
        mgr = self._managers.get(name)
        if not row or not mgr:
            return
        color = {
            S.RUNNING:      C["green"],
            S.STARTING:     C["yellow"],
            S.RECONNECTING: C["yellow"],
            S.STOPPED:      C["muted"],
            S.ERROR:        C["red"],
        }.get(state, C["muted"])
        row["dot"].config(fg=color)
        row["status"].config(text=message or state, fg=color)
        row["toggle"].config(text="Stop" if mgr.enabled else "Start")

    def _render_sso(self, active: bool, checked: str):
        if active:
            self._sso_dot.config(fg=C["green"])
            self._sso_txt.config(text=f"Active  (checked {checked})", fg=C["green"])
        else:
            self._sso_dot.config(fg=C["red"])
            self._sso_txt.config(text=f"Expired  (checked {checked})", fg=C["red"])


# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app._quit)
    app.mainloop()
