# =============================================================================
# GhostSecure 2.0 â€” Status Dashboard (tkinter GUI)
# Coded by Egyan
# =============================================================================

import logging
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("GhostSecure2.GUI")

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    HAS_TK = True
except ImportError:
    HAS_TK = False


class StatusDashboard:
    """Real-time monitoring dashboard for GhostSecure 2.0."""

    def __init__(self, detector_engine=None):
        if not HAS_TK:
            logger.error("tkinter not available.")
            return
        self._engine = detector_engine
        self._running = False
        self._root = None

    def launch(self):
        if not HAS_TK:
            print("ERROR: tkinter not available.")
            return

        self._root = tk.Tk()
        self._root.title(
            f"{config.APP_NAME} v{config.APP_VERSION} â€” Dashboard â€” Coded by Egyan"
        )
        self._root.geometry("900x650")
        self._root.configure(bg="#1a1a2e")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Title.TLabel", background="#1a1a2e",
                         foreground="#e94560", font=("Consolas", 18, "bold"))
        style.configure("Subtitle.TLabel", background="#1a1a2e",
                         foreground="#0f3460", font=("Consolas", 10))
        style.configure("Stat.TLabel", background="#16213e",
                         foreground="#ffffff", font=("Consolas", 11))
        style.configure("StatValue.TLabel", background="#16213e",
                         foreground="#e94560", font=("Consolas", 14, "bold"))
        style.configure("Dark.TFrame", background="#1a1a2e")
        style.configure("Card.TFrame", background="#16213e")
        style.configure("Green.TLabel", background="#16213e",
                         foreground="#00ff00", font=("Consolas", 12, "bold"))

        # Header
        hdr = ttk.Frame(self._root, style="Dark.TFrame")
        hdr.pack(fill=tk.X, padx=10, pady=(10, 5))
        ttk.Label(hdr, text=f"\U0001f47b {config.APP_NAME}",
                  style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(hdr, text=f"  AD Attack Detector â€” Coded by {config.APP_AUTHOR}",
                  style="Subtitle.TLabel").pack(side=tk.LEFT, padx=(10, 0), pady=(8, 0))

        # Stats row
        sf = ttk.Frame(self._root, style="Dark.TFrame")
        sf.pack(fill=tk.X, padx=10, pady=5)
        self._status_card = self._make_card(sf, "Status", "INITIALIZING")
        self._status_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self._events_card = self._make_card(sf, "Events", "0")
        self._events_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self._alerts_card = self._make_card(sf, "Alerts", "0")
        self._alerts_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self._uptime_card = self._make_card(sf, "Uptime", "0s")
        self._uptime_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # Log area
        lf = ttk.Frame(self._root, style="Dark.TFrame")
        lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        ttk.Label(lf, text="\U0001f4cb Live Alert Log",
                  style="Stat.TLabel").pack(anchor=tk.W, pady=(0, 5))
        self._log_text = scrolledtext.ScrolledText(
            lf, wrap=tk.WORD, bg="#0d1117", fg="#c9d1d9",
            font=("Consolas", 9), state=tk.DISABLED, height=20
        )
        self._log_text.pack(fill=tk.BOTH, expand=True)
        self._log_text.tag_config("critical", foreground="#ff4444")
        self._log_text.tag_config("separator", foreground="#333333")

        # Footer
        ft = ttk.Frame(self._root, style="Dark.TFrame")
        ft.pack(fill=tk.X, padx=10, pady=(5, 10))
        ttk.Label(
            ft,
            text=f"Red Parrot Accounting Ltd â€” {config.APP_NAME} â€” GDPR/ICO",
            style="Subtitle.TLabel"
        ).pack(side=tk.LEFT)
        tk.Button(
            ft, text="\U0001f504 Refresh", command=self._load_log,
            bg="#0f3460", fg="#fff", font=("Consolas", 9), relief=tk.FLAT
        ).pack(side=tk.RIGHT)

        self._running = True
        threading.Thread(target=self._update_loop, daemon=True).start()
        self._load_log()
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._root.mainloop()

    def _make_card(self, parent, title, value):
        card = ttk.Frame(parent, style="Card.TFrame", padding=10)
        ttk.Label(card, text=title, style="Stat.TLabel").pack(anchor=tk.W)
        vl = ttk.Label(card, text=value, style="StatValue.TLabel")
        vl.pack(anchor=tk.W, pady=(5, 0))
        card._value_label = vl
        return card

    def _update_loop(self):
        while self._running:
            try:
                if self._engine:
                    stats = self._engine.get_stats()
                    self._root.after(0, self._refresh_stats, stats)
                self._root.after(0, self._load_log)
            except Exception:
                pass
            time.sleep(5)

    def _refresh_stats(self, stats):
        try:
            ep = stats.get("events_processed", 0)
            self._status_card._value_label.configure(
                text="MONITORING" if ep > 0 else "WAITING"
            )
            self._events_card._value_label.configure(text=str(ep))
            self._alerts_card._value_label.configure(
                text=str(stats.get("alerts_triggered", 0))
            )
            self._uptime_card._value_label.configure(
                text=stats.get("uptime_human", "0s")
            )
        except Exception:
            pass

    def _load_log(self):
        try:
            if not os.path.exists(config.LOG_FILE):
                return
            with open(config.LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            self._log_text.configure(state=tk.NORMAL)
            self._log_text.delete("1.0", tk.END)
            for line in content.split("\n"):
                tag = None
                if "CRITICAL" in line or "ATTACK" in line:
                    tag = "critical"
                elif "===" in line:
                    tag = "separator"
                if tag:
                    self._log_text.insert(tk.END, line + "\n", tag)
                else:
                    self._log_text.insert(tk.END, line + "\n")
            self._log_text.see(tk.END)
            self._log_text.configure(state=tk.DISABLED)
        except Exception:
            pass

    def _on_close(self):
        self._running = False
        if self._root:
            self._root.destroy()


def launch_dashboard(detector_engine=None):
    StatusDashboard(detector_engine).launch()


if __name__ == "__main__":
    launch_dashboard()
