"""FSLogix Log Analyzer — main entry point and GUI."""

import tkinter as tk
from tkinter import ttk, filedialog
import os
import re
import threading
import webbrowser
import tempfile
import html as html_escape_mod
from pathlib import Path
from typing import List, Optional, Dict

from parser import (
    LogEntry, ParsedLog, DetectedIssue,
    parse_log_file, collect_log_files, detect_issues, group_by_subdir,
)

APP_NAME = "FSLogix Log Analyzer"
APP_VERSION = "1.0.0"
DEFAULT_LOG_PATH = r"C:\ProgramData\FSLogix\Logs"

# ── Colour palette (Catppuccin Mocha) ────────────────────────────────────────
C = {
    "base":    "#1e1e2e",
    "mantle":  "#181825",
    "surface": "#313244",
    "overlay": "#45475a",
    "muted":   "#6c7086",
    "text":    "#cdd6f4",
    "blue":    "#89b4fa",
    "green":   "#a6e3a1",
    "yellow":  "#f9e2af",
    "orange":  "#fab387",
    "red":     "#f38ba8",
    "mauve":   "#cba6f7",
    "teal":    "#94e2d5",
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  v{APP_VERSION}")
        self.geometry("1300x820")
        self.minsize(960, 640)
        self.configure(bg=C["base"])

        # State
        self.log_path = tk.StringVar(value=DEFAULT_LOG_PATH)
        self.filter_level = tk.StringVar(value="ALL")
        self.filter_text = tk.StringVar()
        self.all_logs: List[ParsedLog] = []
        self.all_entries: List[LogEntry] = []
        self.detected_issues: List[DetectedIssue] = []
        self._active_entries: List[LogEntry] = []  # currently shown in viewer

        self._setup_styles()
        self._build_ui()

        if os.path.isdir(DEFAULT_LOG_PATH):
            self.after(200, self._start_analysis)

    # ── Styles ────────────────────────────────────────────────────────────────

    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        s.configure(".",
                     background=C["base"], foreground=C["text"],
                     font=("Segoe UI", 10), borderwidth=0)
        s.configure("TFrame", background=C["base"])
        s.configure("TLabel", background=C["base"], foreground=C["text"])
        s.configure("TButton",
                     background=C["surface"], foreground=C["text"],
                     padding=(12, 5), relief="flat")
        s.map("TButton",
              background=[("active", C["blue"]), ("pressed", C["blue"])],
              foreground=[("active", C["base"]), ("pressed", C["base"])])
        s.configure("Accent.TButton",
                     background=C["blue"], foreground=C["base"],
                     font=("Segoe UI", 10, "bold"), padding=(14, 6))
        s.map("Accent.TButton",
              background=[("active", C["teal"]), ("pressed", C["teal"])],
              foreground=[("active", C["base"])])
        s.configure("TEntry",
                     fieldbackground=C["surface"], foreground=C["text"],
                     insertcolor=C["text"], relief="flat")
        s.configure("TCombobox",
                     fieldbackground=C["surface"], foreground=C["text"],
                     selectbackground=C["overlay"], relief="flat")
        s.map("TCombobox", fieldbackground=[("readonly", C["surface"])])
        s.configure("Treeview",
                     background=C["mantle"], foreground=C["text"],
                     fieldbackground=C["mantle"], rowheight=22)
        s.configure("Treeview.Heading",
                     background=C["surface"], foreground=C["blue"],
                     font=("Segoe UI", 10, "bold"), relief="flat")
        s.map("Treeview",
              background=[("selected", C["blue"])],
              foreground=[("selected", C["base"])])
        s.configure("TNotebook", background=C["base"], tabmargins=[0, 4, 0, 0])
        s.configure("TNotebook.Tab",
                     background=C["surface"], foreground=C["muted"],
                     padding=[16, 6], font=("Segoe UI", 10))
        s.map("TNotebook.Tab",
              background=[("selected", C["blue"])],
              foreground=[("selected", C["base"])],
              font=[("selected", ("Segoe UI", 10, "bold"))])
        s.configure("TScrollbar",
                     background=C["overlay"], troughcolor=C["mantle"],
                     arrowcolor=C["muted"], relief="flat")
        s.configure("TLabelframe",
                     background=C["base"], foreground=C["blue"],
                     bordercolor=C["overlay"], relief="groove")
        s.configure("TLabelframe.Label",
                     background=C["base"], foreground=C["blue"],
                     font=("Segoe UI", 10, "bold"))
        s.configure("TProgressbar",
                     background=C["blue"], troughcolor=C["surface"],
                     thickness=4)
        s.configure("TSeparator", background=C["overlay"])

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header bar ──
        header = tk.Frame(self, bg=C["mantle"], pady=8)
        header.pack(fill=tk.X)

        tk.Label(header, text=APP_NAME, font=("Segoe UI", 14, "bold"),
                 bg=C["mantle"], fg=C["blue"]).pack(side=tk.LEFT, padx=14)
        tk.Label(header, text=f"v{APP_VERSION}",
                 font=("Segoe UI", 9), bg=C["mantle"], fg=C["muted"]).pack(side=tk.LEFT)

        # ── Path / action bar ──
        path_bar = ttk.Frame(self)
        path_bar.pack(fill=tk.X, padx=12, pady=6)

        ttk.Label(path_bar, text="Log Path:").pack(side=tk.LEFT)
        ttk.Entry(path_bar, textvariable=self.log_path, width=55).pack(
            side=tk.LEFT, padx=6, fill=tk.X, expand=True)
        ttk.Button(path_bar, text="Browse…", command=self._browse).pack(side=tk.LEFT, padx=2)
        ttk.Button(path_bar, text="Analyze", command=self._start_analysis,
                   style="Accent.TButton").pack(side=tk.LEFT, padx=4)
        ttk.Button(path_bar, text="Export HTML", command=self._export_html).pack(side=tk.LEFT, padx=2)

        self.status_var = tk.StringVar(value="")
        ttk.Label(path_bar, textvariable=self.status_var,
                  foreground=C["muted"]).pack(side=tk.RIGHT, padx=6)

        # ── Progress bar (hidden until analysis) ──
        self.progress = ttk.Progressbar(self, mode="indeterminate", style="TProgressbar")

        # ── Main paned layout ──
        pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 4))

        # Left panel — file tree
        left = ttk.LabelFrame(pane, text="Log Files")
        pane.add(left, weight=1)
        self._build_file_tree(left)

        # Right panel — notebook
        right = ttk.Frame(pane)
        pane.add(right, weight=5)
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        diag_tab = ttk.Frame(self.notebook)
        self.notebook.add(diag_tab, text="  Diagnostics  ")
        self._build_diagnostics_tab(diag_tab)

        viewer_tab = ttk.Frame(self.notebook)
        self.notebook.add(viewer_tab, text="  Log Viewer  ")
        self._build_viewer_tab(viewer_tab)

        # ── Status bar ──
        status_bar = ttk.Frame(self)
        status_bar.pack(fill=tk.X, padx=12, pady=(0, 6))
        self.stats_var = tk.StringVar(value="No logs loaded.")
        ttk.Label(status_bar, textvariable=self.stats_var,
                  foreground=C["muted"], font=("Segoe UI", 9)).pack(side=tk.LEFT)

    def _build_file_tree(self, parent):
        self.file_tree = ttk.Treeview(
            parent, show="tree headings",
            columns=("errors", "warns"), selectmode="browse")
        self.file_tree.heading("#0", text="File / Folder")
        self.file_tree.heading("errors", text="ERR")
        self.file_tree.heading("warns",  text="WARN")
        self.file_tree.column("#0", minwidth=80, stretch=True)
        self.file_tree.column("errors", width=42, anchor="center", stretch=False)
        self.file_tree.column("warns",  width=50, anchor="center", stretch=False)

        sb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=sb.set)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.file_tree.tag_configure("err_file",  foreground=C["red"])
        self.file_tree.tag_configure("warn_file", foreground=C["orange"])
        self.file_tree.tag_configure("ok_file",   foreground=C["text"])
        self.file_tree.bind("<<TreeviewSelect>>", self._on_file_select)

    def _build_diagnostics_tab(self, parent):
        # Issues treeview (top half)
        top = ttk.LabelFrame(parent, text="Detected Issues")
        top.pack(fill=tk.X, padx=6, pady=6)

        self.issues_tree = ttk.Treeview(
            top, columns=("severity", "count"), height=6, selectmode="browse")
        self.issues_tree.heading("#0",       text="Issue Name")
        self.issues_tree.heading("severity", text="Severity")
        self.issues_tree.heading("count",    text="Matches")
        self.issues_tree.column("severity", width=90,  anchor="center", stretch=False)
        self.issues_tree.column("count",    width=70,  anchor="center", stretch=False)
        self.issues_tree.pack(fill=tk.X, padx=4, pady=4)

        self.issues_tree.tag_configure("critical", foreground=C["red"])
        self.issues_tree.tag_configure("high",     foreground=C["orange"])
        self.issues_tree.tag_configure("medium",   foreground=C["yellow"])
        self.issues_tree.tag_configure("low",      foreground=C["green"])
        self.issues_tree.bind("<<TreeviewSelect>>", self._on_issue_select)

        # Detail text (bottom half)
        bottom = ttk.LabelFrame(parent, text="Detail & Remediation")
        bottom.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))

        self.detail_text = tk.Text(
            bottom, wrap=tk.WORD, state=tk.DISABLED,
            bg=C["mantle"], fg=C["text"], relief=tk.FLAT,
            font=("Segoe UI", 10), padx=14, pady=10,
            cursor="arrow",
        )
        sb = ttk.Scrollbar(bottom, orient=tk.VERTICAL, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=sb.set)
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        # Text tags
        dt = self.detail_text
        dt.tag_configure("title",     font=("Segoe UI", 13, "bold"), foreground=C["blue"],    spacing3=4)
        dt.tag_configure("severity",  font=("Segoe UI", 9,  "bold"), foreground=C["orange"],  spacing3=8)
        dt.tag_configure("section",   font=("Segoe UI", 10, "bold"), foreground=C["teal"],    spacing1=10, spacing3=2)
        dt.tag_configure("body",      foreground=C["text"])
        dt.tag_configure("bullet",    foreground=C["text"],  lmargin1=20, lmargin2=36)
        dt.tag_configure("step",      foreground=C["text"],  lmargin1=20, lmargin2=44)
        dt.tag_configure("code",      font=("Cascadia Code", 9), foreground=C["green"],
                         background=C["surface"], lmargin1=44, lmargin2=44)
        dt.tag_configure("link",      foreground=C["blue"],  underline=True)
        dt.tag_configure("log_ts",    foreground=C["muted"], font=("Cascadia Code", 8))
        dt.tag_configure("log_body",  foreground=C["text"],  font=("Cascadia Code", 8),
                         lmargin1=20, lmargin2=20)
        dt.tag_configure("no_issues", foreground=C["green"], font=("Segoe UI", 11, "bold"))

        # Enable clickable links
        dt.tag_bind("link", "<Button-1>", self._open_link)
        dt.tag_bind("link", "<Enter>",    lambda e: dt.configure(cursor="hand2"))
        dt.tag_bind("link", "<Leave>",    lambda e: dt.configure(cursor="arrow"))

    def _build_viewer_tab(self, parent):
        # Filter bar
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, padx=6, pady=6)

        ttk.Label(bar, text="Level:").pack(side=tk.LEFT)
        cb = ttk.Combobox(bar, textvariable=self.filter_level, state="readonly",
                          values=["ALL", "ERROR", "WARNING", "INFO", "VERBOSE"], width=10)
        cb.pack(side=tk.LEFT, padx=4)
        cb.bind("<<ComboboxSelected>>", lambda _e: self._apply_filter())

        ttk.Label(bar, text="Search:").pack(side=tk.LEFT, padx=(10, 0))
        fe = ttk.Entry(bar, textvariable=self.filter_text, width=32)
        fe.pack(side=tk.LEFT, padx=4)
        fe.bind("<Return>", lambda _e: self._apply_filter())
        ttk.Button(bar, text="Go", command=self._apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Clear", command=self._clear_filter).pack(side=tk.LEFT, padx=2)

        self.entry_count_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.entry_count_var,
                  foreground=C["muted"], font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=6)

        # Log text widget
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))

        self.log_text = tk.Text(
            frame, wrap=tk.NONE, state=tk.DISABLED,
            bg=C["mantle"], fg=C["text"], relief=tk.FLAT,
            font=("Cascadia Code", 9),
        )
        ys = ttk.Scrollbar(frame, orient=tk.VERTICAL,   command=self.log_text.yview)
        xs = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)

        self.log_text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # Colour tags
        lt = self.log_text
        lt.tag_configure("ts",      foreground=C["muted"])
        lt.tag_configure("pid",     foreground=C["overlay"])
        lt.tag_configure("ERROR",   foreground=C["red"])
        lt.tag_configure("WARNING", foreground=C["orange"])
        lt.tag_configure("INFO",    foreground=C["green"])
        lt.tag_configure("VERBOSE", foreground=C["muted"])
        lt.tag_configure("hl",      background=C["overlay"])   # search highlight

    # ── Event handlers ────────────────────────────────────────────────────────

    def _browse(self):
        path = filedialog.askdirectory(
            initialdir=self.log_path.get(),
            title="Select FSLogix Log Directory")
        if path:
            self.log_path.set(path)
            self._start_analysis()

    def _start_analysis(self):
        path = self.log_path.get()
        if not os.path.isdir(path):
            self.status_var.set(f"Path not found: {path}")
            return
        self.status_var.set("Scanning…")
        self.progress.pack(fill=tk.X, padx=12)
        self.progress.start(12)
        threading.Thread(target=self._run_analysis, args=(path,), daemon=True).start()

    def _run_analysis(self, path: str):
        files = collect_log_files(path)
        parsed = [parse_log_file(fp) for fp in files]
        all_entries = [e for p in parsed for e in p.entries]
        issues = detect_issues(all_entries)
        self.after(0, self._on_analysis_done, parsed, all_entries, issues)

    def _on_analysis_done(self, parsed, all_entries, issues):
        self.progress.stop()
        self.progress.pack_forget()

        self.all_logs = parsed
        self.all_entries = all_entries
        self._active_entries = all_entries
        self.detected_issues = issues

        total_err  = sum(p.errors   for p in parsed)
        total_warn = sum(p.warnings for p in parsed)
        self.stats_var.set(
            f"Files: {len(parsed)}  |  Entries: {len(all_entries):,}  |  "
            f"Errors: {total_err:,}  |  Warnings: {total_warn:,}  |  "
            f"Issues detected: {len(issues)}")
        self.status_var.set(
            f"Done — {len(issues)} issue(s) found" if issues else "Done — no known issues detected")

        self._populate_file_tree(parsed)
        self._populate_issues(issues)
        self._render_entries(all_entries)

    def _on_file_select(self, _event):
        sel = self.file_tree.selection()
        if not sel:
            return
        iid = sel[0]
        for p in self.all_logs:
            if p.file_path == iid:
                self._active_entries = p.entries
                self._apply_filter()
                self.notebook.select(1)
                return
        # Folder node — aggregate all child logs
        child_entries: List[LogEntry] = []
        for p in self.all_logs:
            if os.path.relpath(p.file_path, self.log_path.get()).split(os.sep)[0] == iid:
                child_entries.extend(p.entries)
        if child_entries:
            self._active_entries = child_entries
            self._apply_filter()
            self.notebook.select(1)

    def _on_issue_select(self, _event):
        sel = self.issues_tree.selection()
        if not sel:
            return
        issue_id = sel[0]
        for issue in self.detected_issues:
            if issue.id == issue_id:
                self._show_issue_detail(issue)
                return

    def _apply_filter(self):
        level = self.filter_level.get()
        needle = self.filter_text.get().lower()
        filtered = [
            e for e in self._active_entries
            if (level == "ALL" or e.level == level)
            and (not needle or needle in e.message.lower() or needle in e.raw.lower())
        ]
        self._render_entries(filtered, highlight=needle)
        self.entry_count_var.set(f"{len(filtered):,} of {len(self._active_entries):,} entries")

    def _clear_filter(self):
        self.filter_level.set("ALL")
        self.filter_text.set("")
        self._active_entries = self.all_entries
        self._render_entries(self.all_entries)
        self.entry_count_var.set(f"{len(self.all_entries):,} entries")

    def _open_link(self, event):
        idx = self.detail_text.index(f"@{event.x},{event.y}")
        for tag in self.detail_text.tag_names(idx):
            if tag.startswith("url:"):
                webbrowser.open(tag[4:])
                return

    # ── UI population ─────────────────────────────────────────────────────────

    def _populate_file_tree(self, parsed: List[ParsedLog]):
        self.file_tree.delete(*self.file_tree.get_children())
        base = self.log_path.get()
        groups = group_by_subdir(parsed, base)

        for dir_name in sorted(groups):
            logs = groups[dir_name]
            d_err  = sum(l.errors   for l in logs)
            d_warn = sum(l.warnings for l in logs)
            tag = "err_file" if d_err else ("warn_file" if d_warn else "ok_file")
            parent_iid = self.file_tree.insert(
                "", "end", iid=dir_name, text=dir_name,
                values=(d_err or "", d_warn or ""), tags=(tag,), open=True)

            for log in sorted(logs, key=lambda l: l.file_path):
                name = Path(log.file_path).name
                tag  = "err_file" if log.errors else ("warn_file" if log.warnings else "ok_file")
                self.file_tree.insert(
                    parent_iid, "end", iid=log.file_path, text=name,
                    values=(log.errors or "", log.warnings or ""), tags=(tag,))

    def _populate_issues(self, issues: List[DetectedIssue]):
        self.issues_tree.delete(*self.issues_tree.get_children())
        for issue in issues:
            self.issues_tree.insert(
                "", "end", iid=issue.id, text=issue.name,
                values=(issue.severity.upper(), len(issue.matched_entries)),
                tags=(issue.severity,))

        dt = self.detail_text
        dt.configure(state=tk.NORMAL)
        dt.delete("1.0", tk.END)

        if not issues:
            dt.insert(tk.END, "\n\n   No known issues detected in these logs.\n", "no_issues")
        else:
            self.issues_tree.selection_set(issues[0].id)
            self._show_issue_detail(issues[0])
            return

        dt.configure(state=tk.DISABLED)

    def _show_issue_detail(self, issue: DetectedIssue):
        dt = self.detail_text
        dt.configure(state=tk.NORMAL)
        dt.delete("1.0", tk.END)

        # Title + severity
        dt.insert(tk.END, f"{issue.name}\n", "title")
        sev_labels = {"critical": "● CRITICAL", "high": "● HIGH", "medium": "● MEDIUM", "low": "● LOW"}
        dt.insert(tk.END, f"{sev_labels.get(issue.severity, issue.severity)}  |  {len(issue.matched_entries)} matching log entries\n", "severity")

        # Description
        dt.insert(tk.END, "Description\n", "section")
        dt.insert(tk.END, f"{issue.description}\n", "body")

        # Causes
        dt.insert(tk.END, "Likely Causes\n", "section")
        for cause in issue.causes:
            dt.insert(tk.END, f"• {cause}\n", "bullet")

        # Remediation
        dt.insert(tk.END, "Remediation Steps\n", "section")
        # Command-like patterns to highlight as code
        _cmd_re = re.compile(
            r'((?:Test-|Get-|Start-|Repair-|Resolve-|Query-|w32tm|klist|frx|reg add|sc query|wt )\S[^\n,;]*'
            r'|\\\\[^\s,;]+)',
            re.IGNORECASE)

        for i, step in enumerate(issue.remediation_steps, 1):
            dt.insert(tk.END, f"{i}. ", "step")
            # Split on embedded command-like text
            parts = _cmd_re.split(step)
            for j, part in enumerate(parts):
                if j % 2 == 1:
                    dt.insert(tk.END, part, "code")
                else:
                    dt.insert(tk.END, part, "step")
            dt.insert(tk.END, "\n")

        # Links
        if issue.links:
            dt.insert(tk.END, "Reference Links\n", "section")
            for link in issue.links:
                tag_name = f"url:{link}"
                dt.tag_configure(tag_name, foreground=C["blue"], underline=True)
                dt.tag_bind(tag_name, "<Button-1>", self._open_link)
                dt.tag_bind(tag_name, "<Enter>", lambda e: dt.configure(cursor="hand2"))
                dt.tag_bind(tag_name, "<Leave>", lambda e: dt.configure(cursor="arrow"))
                dt.insert(tk.END, f"  {link}\n", (tag_name, "link"))

        # Sample matched entries
        dt.insert(tk.END, f"Matched Log Entries (first {min(8, len(issue.matched_entries))} of {len(issue.matched_entries)})\n", "section")
        for entry in issue.matched_entries[:8]:
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "Unknown time"
            fname = Path(entry.source_file).name
            dt.insert(tk.END, f"  [{ts}] {fname}\n", "log_ts")
            dt.insert(tk.END, f"  {entry.message[:180]}\n", "log_body")

        dt.configure(state=tk.DISABLED)

    def _render_entries(self, entries: List[LogEntry], highlight: str = ""):
        lt = self.log_text
        lt.configure(state=tk.NORMAL)
        lt.delete("1.0", tk.END)

        _level_pad = {"ERROR": "ERROR  ", "WARNING": "WARN   ", "INFO": "INFO   ", "VERBOSE": "VERB   "}

        for entry in entries:
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "????-??-?? ??:??:??"
            lt.insert(tk.END, f"[{ts}] ", "ts")
            lt.insert(tk.END, f"[{entry.pid}.{entry.tid}] ", "pid")
            lpad = _level_pad.get(entry.level, entry.level.ljust(7))
            lt.insert(tk.END, lpad, entry.level)
            body_tag = entry.level if entry.level in ("ERROR", "WARNING") else ""
            lt.insert(tk.END, f"  {entry.message}\n", body_tag)

        # Search highlight
        if highlight:
            start = "1.0"
            while True:
                pos = lt.search(highlight, start, stopindex=tk.END, nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(highlight)}c"
                lt.tag_add("hl", pos, end)
                start = end

        lt.configure(state=tk.DISABLED)
        if entries:
            lt.see("1.0")

        self.entry_count_var.set(f"{len(entries):,} entries")

    # ── HTML export ───────────────────────────────────────────────────────────

    def _export_html(self):
        if not self.all_logs:
            self.status_var.set("Nothing to export — run an analysis first.")
            return

        out_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html")],
            initialfile="fslogix_report.html",
            title="Save HTML Report",
        )
        if not out_path:
            return

        h = html_escape_mod.escape
        lines = [
            "<!DOCTYPE html><html lang='en'><head>",
            "<meta charset='utf-8'>",
            f"<title>{APP_NAME} Report</title>",
            "<style>",
            "body{font-family:'Segoe UI',Arial,sans-serif;background:#1e1e2e;color:#cdd6f4;margin:0;padding:24px}",
            "h1{color:#89b4fa}h2{color:#94e2d5;margin-top:32px}h3{color:#fab387;margin-top:20px}",
            "p,li{line-height:1.7}",
            ".issue{background:#181825;border-left:4px solid #89b4fa;padding:16px;margin:16px 0;border-radius:4px}",
            ".critical .badge{background:#f38ba8;color:#1e1e2e}",
            ".high .badge{background:#fab387;color:#1e1e2e}",
            ".medium .badge{background:#f9e2af;color:#1e1e2e}",
            ".low .badge{background:#a6e3a1;color:#1e1e2e}",
            ".badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.8em;font-weight:bold;margin-left:10px}",
            "code{background:#313244;padding:2px 6px;border-radius:3px;font-family:'Cascadia Code',monospace;color:#a6e3a1;font-size:.9em}",
            "a{color:#89b4fa}",
            ".no-issue{color:#a6e3a1;font-size:1.1em}",
            "table{border-collapse:collapse;width:100%}th{background:#313244;color:#89b4fa;padding:8px;text-align:left}",
            "td{padding:6px 8px;border-bottom:1px solid #313244}tr:nth-child(even){background:#181825}",
            ".err{color:#f38ba8}.warn{color:#fab387}.info{color:#a6e3a1}.verb{color:#6c7086}",
            "</style></head><body>",
            f"<h1>{h(APP_NAME)}</h1>",
            f"<p>Log path: <code>{h(self.log_path.get())}</code></p>",
        ]

        total_err  = sum(p.errors   for p in self.all_logs)
        total_warn = sum(p.warnings for p in self.all_logs)
        lines += [
            "<table>",
            "<tr><th>Files</th><th>Total Entries</th><th>Errors</th><th>Warnings</th><th>Issues Detected</th></tr>",
            f"<tr><td>{len(self.all_logs)}</td><td>{len(self.all_entries):,}</td>"
            f"<td class='err'>{total_err:,}</td><td class='warn'>{total_warn:,}</td>"
            f"<td>{len(self.detected_issues)}</td></tr>",
            "</table>",
            "<h2>Detected Issues</h2>",
        ]

        if not self.detected_issues:
            lines.append("<p class='no-issue'>&#10003; No known issues detected.</p>")
        else:
            for issue in self.detected_issues:
                lines += [
                    f"<div class='issue {h(issue.severity)}'>",
                    f"<h3>{h(issue.name)}<span class='badge'>{h(issue.severity.upper())}</span></h3>",
                    f"<p>{h(issue.description)}</p>",
                    "<h4>Likely Causes</h4><ul>",
                    *[f"<li>{h(c)}</li>" for c in issue.causes],
                    "</ul><h4>Remediation Steps</h4><ol>",
                    *[f"<li>{h(s)}</li>" for s in issue.remediation_steps],
                    "</ol>",
                ]
                if issue.links:
                    lines.append("<h4>References</h4><ul>")
                    for link in issue.links:
                        lines.append(f"<li><a href='{h(link)}' target='_blank'>{h(link)}</a></li>")
                    lines.append("</ul>")
                lines.append("</div>")

        # Error log table
        err_entries = [e for e in self.all_entries if e.level == "ERROR"]
        if err_entries:
            lines += [
                "<h2>Error Log Entries</h2>",
                "<table><tr><th>Timestamp</th><th>File</th><th>Message</th></tr>",
            ]
            for e in err_entries:
                ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "?"
                fname = h(Path(e.source_file).name)
                msg   = h(e.message[:300])
                lines.append(f"<tr><td class='err'>{h(ts)}</td><td>{fname}</td><td>{msg}</td></tr>")
            lines.append("</table>")

        lines.append("</body></html>")

        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        self.status_var.set(f"Exported: {out_path}")
        webbrowser.open(out_path)


if __name__ == "__main__":
    app = App()
    app.mainloop()
