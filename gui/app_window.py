import csv
import os
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.dates as mdates

from core.log_parser import parse_log_file
from core.detector import detect_bruteforce, top_attackers, attempts_per_minute
from core.sample_generator import generate_sample_log

# ------------------------- theme -------------------------
BG = "#0a0f14"
HEADER = "#0d141b"
PANEL = "#111a23"
PANEL2 = "#17232e"
HOVER = "#223a4d"
BORDER = "#223241"
FG = "#d8e3ec"
MUTED = "#7d91a3"
ACCENT = "#22d3ee"
GREEN = "#2ecc71"
RED = "#ff4d4f"
ORANGE = "#ff9f43"
YELLOW = "#f1c40f"
NEUTRAL_BAR = "#4b6a82"

SEV_COLORS = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW}

FONT = "Segoe UI"
MONO = "Consolas"
HEAD_FONT = (FONT, 9, "bold")


# ------------------------- custom widgets -------------------------
class FlatButton(tk.Label):
    """Label-based button (no white flash on Windows)."""

    def __init__(self, parent, text, command, bg=PANEL2, fg=FG, hover=HOVER):
        super().__init__(parent, text=text, bg=bg, fg=fg, padx=16, pady=8,
                         cursor="hand2", font=(FONT, 9, "bold"))
        self._bg, self._hover, self._cmd = bg, hover, command
        self.bind("<Enter>", lambda e: self.config(bg=self._hover))
        self.bind("<Leave>", lambda e: self.config(bg=self._bg))
        self.bind("<ButtonRelease-1>", self._click)

    def _click(self, e):
        if 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height():
            self._cmd()


class Stepper(tk.Frame):
    """Small  [-] value [+]  control."""

    def __init__(self, parent, var, lo, hi, on_change=None):
        super().__init__(parent, bg=PANEL2, highlightthickness=1,
                         highlightbackground=BORDER)
        self.var, self.lo, self.hi, self.on_change = var, lo, hi, on_change
        self._btn("-", -1).pack(side="left")
        tk.Label(self, textvariable=var, width=4, bg=PANEL2, fg=FG,
                 font=(MONO, 11, "bold")).pack(side="left")
        self._btn("+", 1).pack(side="left")

    def _btn(self, text, delta):
        b = tk.Label(self, text=text, width=3, bg=PANEL2, fg=ACCENT,
                     cursor="hand2", font=(FONT, 11, "bold"))
        b.bind("<Enter>", lambda e: b.config(bg=HOVER))
        b.bind("<Leave>", lambda e: b.config(bg=PANEL2))
        b.bind("<Button-1>", lambda e: self._step(delta))
        return b

    def _step(self, delta):
        self.var.set(max(self.lo, min(self.hi, self.var.get() + delta)))
        if self.on_change:
            self.on_change()


# ------------------------- main window -------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SSH Brute-Force Detector - Security Operations Lab")
        self.geometry("1360x820")
        self.minsize(1100, 680)
        self.configure(bg=BG)
        try:
            self.state("zoomed")          # start maximized on Windows
        except tk.TclError:
            pass

        self.events = []
        self.alerts = []
        self.log_path = ""
        self.threshold = tk.IntVar(value=5)
        self.window = tk.IntVar(value=2)
        self.status = tk.StringVar(
            value="Ready. Open a log file or generate a sample log to begin.")

        self._style()
        self._build_header()
        self._build_rule_bar()
        self._build_stats()
        self._build_status()     # bottom widgets are packed before the middle area
        self._build_charts()
        self._build_middle()
        self._draw_charts()
        self._show_detail(None)

    # ---------- ttk styling ----------
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=FG, rowheight=30, borderwidth=0,
                    bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL,
                    font=(FONT, 10))
        s.map("Treeview",
              background=[("selected", "#1d3a52")],
              foreground=[("selected", "#ffffff")])

        s.configure("Treeview.Heading", background=PANEL2, foreground=ACCENT,
                    font=HEAD_FONT, relief="flat", borderwidth=0,
                    padding=(4, 8), bordercolor=PANEL2,
                    lightcolor=PANEL2, darkcolor=PANEL2)
        s.map("Treeview.Heading",
              background=[("active", "#1f3344"), ("pressed", "#1f3344")],
              foreground=[("active", ACCENT), ("pressed", ACCENT)])

        for orient in ("Vertical", "Horizontal"):
            s.configure(f"{orient}.TScrollbar", background=PANEL2, troughcolor=PANEL,
                        bordercolor=PANEL, lightcolor=PANEL2, darkcolor=PANEL2,
                        arrowcolor=MUTED, relief="flat")
            s.map(f"{orient}.TScrollbar", background=[("active", HOVER)])

    # ---------- header ----------
    def _build_header(self):
        bar = tk.Frame(self, bg=HEADER)
        bar.pack(fill="x")
        tk.Frame(bar, bg=ACCENT, height=2).pack(fill="x")

        inner = tk.Frame(bar, bg=HEADER, padx=18, pady=10)
        inner.pack(fill="x")

        left = tk.Frame(inner, bg=HEADER)
        left.pack(side="left")
        tk.Label(left, text="SSH BRUTE-FORCE DETECTOR", bg=HEADER, fg=FG,
                 font=(FONT, 17, "bold")).pack(anchor="w")
        tk.Label(left,
                 text="Security Operations Lab   |   Authentication Log Analysis   |   "
                      "MITRE ATT&CK T1110 - Brute Force",
                 bg=HEADER, fg=MUTED, font=(FONT, 9)).pack(anchor="w")

        right = tk.Frame(inner, bg=HEADER)
        right.pack(side="right")
        FlatButton(right, "RUN DETECTION", self.load_and_analyze,
                   bg=ACCENT, fg="#001018", hover="#67e8f9").pack(side="right", padx=(8, 0))
        FlatButton(right, "Export CSV", self.export_csv).pack(side="right", padx=(8, 0))
        FlatButton(right, "Generate Sample Log", self.make_sample).pack(side="right", padx=(8, 0))
        FlatButton(right, "Open Log File", self.open_log).pack(side="right", padx=(8, 0))

    # ---------- detection rule bar ----------
    def _build_rule_bar(self):
        cfg = tk.Frame(self, bg=PANEL, padx=18, pady=8,
                       highlightthickness=1, highlightbackground=BORDER)
        cfg.pack(fill="x", padx=14, pady=(10, 0))

        tk.Label(cfg, text="DETECTION RULE", bg=PANEL, fg=MUTED,
                 font=(FONT, 8, "bold")).pack(side="left")
        tk.Label(cfg, text="Alert when one IP has at least", bg=PANEL, fg=FG,
                 font=(FONT, 10)).pack(side="left", padx=(14, 8))
        Stepper(cfg, self.threshold, 2, 500, self._rerun).pack(side="left")
        tk.Label(cfg, text="failed logins within", bg=PANEL, fg=FG,
                 font=(FONT, 10)).pack(side="left", padx=8)
        Stepper(cfg, self.window, 1, 120, self._rerun).pack(side="left")
        tk.Label(cfg, text="minute(s)", bg=PANEL, fg=FG,
                 font=(FONT, 10)).pack(side="left", padx=8)

        self.file_label = tk.Label(cfg, text="Log source: none", bg=PANEL, fg=MUTED,
                                   font=(MONO, 9), anchor="e")
        self.file_label.pack(side="right")

    # ---------- KPI cards ----------
    def _build_stats(self):
        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=14, pady=(8, 0))
        self.card_vars = {}
        self.card_labels = {}
        specs = [("events", "TOTAL EVENTS", ACCENT),
                 ("failed", "FAILED LOGINS", ORANGE),
                 ("alerts", "ALERTS", YELLOW),
                 ("critical", "CRITICAL", RED),
                 ("threat", "THREAT LEVEL", MUTED)]
        for i, (key, label, color) in enumerate(specs):
            card = tk.Frame(row, bg=PANEL, highlightthickness=1,
                            highlightbackground=BORDER)
            card.pack(side="left", fill="x", expand=True,
                      padx=(0 if i == 0 else 10, 0))
            tk.Frame(card, bg=color, height=3).pack(fill="x")
            box = tk.Frame(card, bg=PANEL, padx=16, pady=6)
            box.pack(fill="x")
            tk.Label(box, text=label, bg=PANEL, fg=MUTED,
                     font=(FONT, 8, "bold")).pack(anchor="w")
            var = tk.StringVar(value="N/A" if key == "threat" else "0")
            lbl = tk.Label(box, textvariable=var, bg=PANEL, fg=color,
                           font=(FONT, 20, "bold"))
            lbl.pack(anchor="w")
            self.card_vars[key] = var
            self.card_labels[key] = lbl

    # ---------- status bar ----------
    def _build_status(self):
        bar = tk.Frame(self, bg=HEADER, padx=14, pady=6)
        bar.pack(side="bottom", fill="x")
        tk.Label(bar, textvariable=self.status, bg=HEADER, fg=MUTED,
                 font=(FONT, 9), anchor="w").pack(side="left")

    # ---------- charts (bottom row, compact) ----------
    def _build_charts(self):
        wrap = tk.Frame(self, bg=PANEL, highlightthickness=1,
                        highlightbackground=BORDER)
        wrap.pack(side="bottom", fill="x", padx=14, pady=(8, 8))
        self.fig = Figure(figsize=(12, 2.2), dpi=100, facecolor=PANEL)
        self.ax1 = self.fig.add_subplot(121)
        self.ax2 = self.fig.add_subplot(122)
        self.canvas = FigureCanvasTkAgg(self.fig, master=wrap)
        widget = self.canvas.get_tk_widget()
        widget.configure(bg=PANEL, highlightthickness=0)
        widget.pack(fill="x")

    # ---------- middle: tabs/table + details ----------
    def _build_middle(self):
        mid = tk.Frame(self, bg=BG)
        mid.pack(fill="both", expand=True, padx=14, pady=(8, 0))
        mid.columnconfigure(0, weight=3)
        mid.columnconfigure(1, weight=2, minsize=330)
        mid.rowconfigure(0, weight=1)

        # ----- left: custom tabs -----
        left = tk.Frame(mid, bg=PANEL, highlightthickness=1,
                        highlightbackground=BORDER)
        left.grid(row=0, column=0, sticky="nsew")

        tabbar = tk.Frame(left, bg=HEADER)
        tabbar.pack(fill="x")
        content = tk.Frame(left, bg=PANEL)
        content.pack(fill="both", expand=True)

        self.tab_btns = {}
        self.tab_frames = {}

        alerts_tab = self._add_tab(tabbar, content, "alerts", "Alerts")
        raw_tab = self._add_tab(tabbar, content, "raw", "Raw Events")

        cols = ("severity", "ip", "attempts", "total", "users", "first", "last", "compromised")
        heads = {"severity": "Severity", "ip": "Source IP", "attempts": "Attempts",
                 "total": "Failed", "users": "Users",
                 "first": "First Seen", "last": "Last Seen", "compromised": "Compromised"}
        # minimum widths (the header text width is measured and used if larger)
        widths = {"severity": 110, "ip": 110, "attempts": 80, "total": 70,
                  "users": 120, "first": 90, "last": 90, "compromised": 110}
        self.tree = self._make_tree(alerts_tab, cols, heads, widths, "users")
        for sev, col in SEV_COLORS.items():
            self.tree.tag_configure(sev, foreground=col)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        rcols = ("time", "status", "user", "ip")
        rheads = {"time": "Timestamp", "status": "Status",
                  "user": "Username", "ip": "Source IP"}
        rwidths = {"time": 170, "status": 110, "user": 180, "ip": 150}
        self.raw_tree = self._make_tree(raw_tab, rcols, rheads, rwidths, "ip")
        self.raw_tree.tag_configure("FAILED", foreground=ORANGE)
        self.raw_tree.tag_configure("ACCEPTED", foreground=GREEN)

        self._select_tab("alerts")

        # ----- right: details panel (scrollable) -----
        right = tk.Frame(mid, bg=PANEL, highlightthickness=1,
                         highlightbackground=BORDER)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        head = tk.Frame(right, bg=HEADER)
        head.pack(fill="x")
        tk.Label(head, text="ALERT DETAILS & RECOMMENDED RESPONSE", bg=HEADER,
                 fg=MUTED, font=(FONT, 8, "bold"), padx=14, pady=11).pack(anchor="w")

        body = tk.Frame(right, bg=PANEL)
        body.pack(fill="both", expand=True)
        dsb = ttk.Scrollbar(body, orient="vertical")
        dsb.pack(side="right", fill="y")
        self.detail = tk.Text(body, bg=PANEL, fg=FG, relief="flat",
                              font=(MONO, 10), wrap="word", padx=14, pady=10,
                              highlightthickness=0, state="disabled", cursor="arrow",
                              spacing1=1, spacing3=1, yscrollcommand=dsb.set)
        self.detail.pack(side="left", fill="both", expand=True)
        dsb.config(command=self.detail.yview)

        self.detail.tag_configure("title_red", foreground=RED, font=(MONO, 11, "bold"))
        self.detail.tag_configure("title_orange", foreground=ORANGE, font=(MONO, 11, "bold"))
        self.detail.tag_configure("title_yellow", foreground=YELLOW, font=(MONO, 11, "bold"))
        self.detail.tag_configure("h", foreground=ACCENT, font=(MONO, 10, "bold"))
        self.detail.tag_configure("k", foreground=MUTED)
        self.detail.tag_configure("v", foreground=FG)
        self.detail.tag_configure("red", foreground=RED, font=(MONO, 10, "bold"))
        self.detail.tag_configure("green", foreground=GREEN, font=(MONO, 10, "bold"))

    def _add_tab(self, bar, content, key, title):
        holder = tk.Frame(bar, bg=HEADER)
        holder.pack(side="left")
        lbl = tk.Label(holder, text=title, bg=HEADER, fg=MUTED, padx=22, pady=8,
                       cursor="hand2", font=(FONT, 10, "bold"))
        lbl.pack()
        line = tk.Frame(holder, bg=HEADER, height=2)
        line.pack(fill="x")
        lbl.bind("<Button-1>", lambda e: self._select_tab(key))
        frame = tk.Frame(content, bg=PANEL)
        self.tab_btns[key] = (lbl, line)
        self.tab_frames[key] = frame
        return frame

    def _select_tab(self, key):
        for k, frame in self.tab_frames.items():
            lbl, line = self.tab_btns[k]
            if k == key:
                frame.pack(fill="both", expand=True)
                lbl.config(fg=ACCENT)
                line.config(bg=ACCENT)
            else:
                frame.pack_forget()
                lbl.config(fg=MUTED)
                line.config(bg=HEADER)

    def _make_tree(self, parent, cols, heads, widths, stretch_col):
        wrap = tk.Frame(parent, bg=PANEL)
        wrap.pack(fill="both", expand=True)
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        head_font = tkfont.Font(family=FONT, size=9, weight="bold")
        for c in cols:
            # width = whichever is bigger: preset width or header text + padding
            need = head_font.measure(heads[c]) + 30
            w = max(widths[c], need)
            tree.heading(c, text=heads[c],
                         anchor="w" if c == stretch_col else "center")
            tree.column(c, width=w, minwidth=w,
                        anchor="w" if c == stretch_col else "center",
                        stretch=(c == stretch_col))

        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        return tree

    # ---------- actions ----------
    def open_log(self):
        path = filedialog.askopenfilename(
            title="Select an SSH authentication log file",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")])
        if path:
            self.log_path = path
            self.load_and_analyze()

    def make_sample(self):
        os.makedirs("data", exist_ok=True)
        self.log_path = generate_sample_log(os.path.join("data", "sample_auth.log"))
        self.load_and_analyze()
        self.status.set(self.status.get() + "  |  Source: generated sample data")

    def load_and_analyze(self):
        path = self.log_path
        if not path or not os.path.isfile(path):
            messagebox.showwarning(
                "No log file",
                "Please open a log file or generate a sample log first.")
            return

        try:
            self.events = parse_log_file(path)
        except Exception as exc:
            messagebox.showerror("Read error", f"Could not read the file:\n{exc}")
            return

        self.file_label.config(text="Log source: " + self._short(path))

        if not self.events:
            self.alerts = []
            self._refresh()
            self.status.set("No SSH authentication events were found in the selected file.")
            messagebox.showwarning(
                "No SSH events found",
                "No SSH authentication events were found in this file.\n\n"
                "Expected format:\n"
                "Oct 11 14:22:01 server sshd[1234]: Failed password for root "
                "from 1.2.3.4 port 22 ssh2")
            return

        self._analyze()

    def _rerun(self):
        """Called when the rule values change."""
        if self.events:
            self._analyze()

    def _analyze(self):
        thr, win = int(self.threshold.get()), int(self.window.get())
        self.alerts = detect_bruteforce(self.events, thr, win)
        self._refresh()
        self.status.set(
            f"Analyzed {len(self.events)} events  |  {len(self.alerts)} alert(s)  |  "
            f"Rule: >= {thr} failed logins within {win} min")

    @staticmethod
    def _short(path, n=60):
        return path if len(path) <= n else "..." + path[-n:]

    def _threat_level(self):
        if not self.events:
            return "N/A", MUTED
        sevs = {a["severity"] for a in self.alerts}
        if "CRITICAL" in sevs:
            return "CRITICAL", RED
        if "HIGH" in sevs:
            return "HIGH", ORANGE
        if "MEDIUM" in sevs:
            return "MEDIUM", YELLOW
        return "LOW", GREEN

    def _refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for a in self.alerts:
            self.tree.insert("", "end", tags=(a["severity"],), values=(
                "● " + a["severity"], a["ip"], a["attempts_in_window"],
                a["total_failed"], a["users_targeted"],
                a["first_seen"].strftime("%H:%M:%S"),
                a["last_seen"].strftime("%H:%M:%S"), a["compromised"]))

        for r in self.raw_tree.get_children():
            self.raw_tree.delete(r)
        for e in self.events[:3000]:
            self.raw_tree.insert("", "end", tags=(e["status"],), values=(
                e["time"].strftime("%Y-%m-%d %H:%M:%S"), e["status"],
                e["user"], e["ip"]))

        failed = sum(1 for e in self.events if e["status"] == "FAILED")
        self.card_vars["events"].set(str(len(self.events)))
        self.card_vars["failed"].set(str(failed))
        self.card_vars["alerts"].set(str(len(self.alerts)))
        self.card_vars["critical"].set(
            str(sum(1 for a in self.alerts if a["severity"] == "CRITICAL")))
        level, color = self._threat_level()
        self.card_vars["threat"].set(level)
        self.card_labels["threat"].config(fg=color)

        self.tab_btns["alerts"][0].config(text=f"Alerts ({len(self.alerts)})")
        self.tab_btns["raw"][0].config(text=f"Raw Events ({len(self.events)})")

        if self.alerts:
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)
            self._show_detail(self.alerts[0])
        else:
            self._show_detail(None)
        self._draw_charts()

    # ---------- details panel ----------
    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if sel:
            idx = self.tree.index(sel[0])
            if 0 <= idx < len(self.alerts):
                self._show_detail(self.alerts[idx])

    def _show_detail(self, a):
        d = self.detail
        d.config(state="normal")
        d.delete("1.0", "end")

        if a is None:
            if self.events:
                d.insert("end", "No brute-force activity detected\n", "h")
                d.insert("end", "\nNo source IP matched the current detection rule. "
                                "Lower the threshold or increase the time window "
                                "to make the rule more sensitive.", "k")
            else:
                d.insert("end", "No data loaded\n", "h")
                d.insert("end", "\nOpen a log file or generate a sample log to begin "
                                "the analysis. Select an alert in the table to see "
                                "its details and the recommended response here.", "k")
            d.config(state="disabled")
            return

        def row(label, value, tag="v"):
            d.insert("end", f"{label:<19}", "k")
            d.insert("end", f"{value}\n", tag)

        sev = a["severity"]
        title_tag = {"CRITICAL": "title_red", "HIGH": "title_orange"}.get(sev, "title_yellow")
        d.insert("end", f"[{sev}] SSH brute-force attack\n\n", title_tag)

        row("Source IP", a["ip"])
        row("Attempts in window", a["attempts_in_window"])
        row("Total failed", a["total_failed"])
        row("First seen", f"{a['first_seen']:%Y-%m-%d %H:%M:%S}")
        row("Last seen", f"{a['last_seen']:%Y-%m-%d %H:%M:%S}")
        row("Usernames tried", a["users_targeted"])
        row("Login succeeded",
            a["compromised"], "red" if a["compromised"] == "YES" else "green")
        row("MITRE ATT&CK", "T1110 - Brute Force")

        d.insert("end", "\nRecommended response\n", "h")
        if sev == "CRITICAL":
            steps = [
                "1. Isolate the host: the attacker authenticated successfully.",
                "2. Reset passwords for the targeted accounts and kill active sessions.",
                f"3. Block the source IP:  sudo ufw deny from {a['ip']}",
                "4. Check for persistence: last -i, ~/.ssh/authorized_keys, crontab.",
            ]
        elif sev == "HIGH":
            steps = [
                f"1. Block the source IP:  sudo ufw deny from {a['ip']}",
                "2. Enable fail2ban to ban repeated offenders automatically.",
                "3. Disable SSH password login and use key-based authentication.",
            ]
        else:
            steps = [
                "1. Monitor this IP, no successful login was observed.",
                "2. Block it if the number of attempts keeps growing.",
                "3. Consider deploying fail2ban for automatic blocking.",
            ]
        for s in steps:
            d.insert("end", s + "\n", "v")
        d.config(state="disabled")
        d.yview_moveto(0)

    # ---------- charts ----------
    def _style_ax(self, ax, title):
        ax.clear()
        ax.set_facecolor(PANEL)
        ax.tick_params(colors=MUTED, labelsize=8)
        for sp in ax.spines.values():
            sp.set_color(BORDER)
        ax.set_title(title, color=FG, fontsize=10, fontweight="bold", loc="left")
        ax.grid(color=BORDER, linewidth=0.5, alpha=0.7)
        ax.set_axisbelow(True)

    def _no_data(self, ax):
        ax.text(0.5, 0.5, "No data", transform=ax.transAxes,
                ha="center", va="center", color=MUTED, fontsize=10)

    def _draw_charts(self):
        # Top attackers
        self._style_ax(self.ax1, "Top Attacker IPs (failed logins)")
        top = top_attackers(self.events, 5)
        if top:
            alert_ips = {a["ip"] for a in self.alerts}
            ips = [t[0] for t in top][::-1]
            cnt = [t[1] for t in top][::-1]
            colors = [RED if ip in alert_ips else NEUTRAL_BAR for ip in ips]
            self.ax1.barh(ips, cnt, color=colors, height=0.6)
            for i, v in enumerate(cnt):
                self.ax1.text(v, i, f" {v}", va="center", color=FG, fontsize=8)
            self.ax1.set_xlim(0, max(cnt) * 1.18)
        else:
            self._no_data(self.ax1)

        # Timeline
        self._style_ax(self.ax2, "Failed Login Attempts per Minute")
        keys, vals = attempts_per_minute(self.events)
        if keys:
            self.ax2.plot(keys, vals, color=ACCENT, linewidth=1.8,
                          marker="o", markersize=3)
            self.ax2.fill_between(keys, vals, color=ACCENT, alpha=0.15)
            self.ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
            self.ax2.set_ylim(bottom=0)
        else:
            self._no_data(self.ax2)

        self.fig.tight_layout(pad=1.2)
        self.canvas.draw()

    # ---------- export ----------
    def export_csv(self):
        if not self.alerts:
            messagebox.showinfo("Nothing to export",
                                "Run a detection first. There are no alerts to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Severity", "IP", "Attempts In Window", "Total Failed",
                        "Users Targeted", "First Seen", "Last Seen", "Compromised"])
            for a in self.alerts:
                w.writerow([a["severity"], a["ip"], a["attempts_in_window"],
                            a["total_failed"], a["users_targeted"],
                            a["first_seen"], a["last_seen"], a["compromised"]])
        self.status.set(f"Alerts exported to: {path}")
        messagebox.showinfo("Export complete", f"Alerts saved to:\n{path}")