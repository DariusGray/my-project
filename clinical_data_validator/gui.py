# gui.py
"""
Tkinter GUI for the Clinical Data Validator.

New layout:
- LEFT  : Connection Panel (Host / Username / Password + state)
- CENTER: Server Browser (search + list of files)
- RIGHT : Workspace (local directories + actions)
- BOTTOM: Activity Feed (processing log)

This keeps all required features but uses a very different visual structure
from the reference UI.
"""

from __future__ import annotations

import os
import shutil
import threading
from datetime import datetime
from typing import List

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import scrolledtext

from config import (
    FTP_HOST,
    FTP_USER,
    FTP_PASSWORD,
    ARCHIVE_DIR,
    ERRORS_DIR,
    TEMP_DIR,
)
from ftp_client import FTPClient
from validator import validate_csv_file
from logger import log_errors, has_been_processed, mark_processed
MAX_ERRORS_IN_POPUP = 5

class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("HelixSoft Clinical Data Console")
        self.root.geometry("1100x620")

        self._init_style()

        self.ftp_client = FTPClient()
        self.all_files: List[str] = []

        # Local directories (user-configurable)
        self.download_dir = TEMP_DIR
        self.archive_dir = ARCHIVE_DIR
        self.errors_dir = ERRORS_DIR

        self._build_ui()
        self._set_disconnected_state()

    # ------------------------------------------------------------------ #
    #   STYLING
    # ------------------------------------------------------------------ #

    def _init_style(self) -> None:
        style = ttk.Style()
        # Use a modern-ish theme if available
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Section.TLabelframe.Label", font=("Segoe UI", 11, "bold"))
        style.configure("StatusGood.TLabel", foreground="#0a8a0a")
        style.configure("StatusBad.TLabel", foreground="#c0392b")
        style.configure("Accent.TButton", padding=6)
        style.configure("Danger.TButton", padding=6)

    # ------------------------------------------------------------------ #
    #   BUILD UI
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        # === HEADER BAR ======================================================
        header = ttk.Frame(self.root, padding=(10, 6))
        header.grid(row=0, column=0, columnspan=3, sticky="nsew")

        title = ttk.Label(
            header,
            text="Clinical Trial Data Validation & Archival",
            style="Header.TLabel",
        )
        title.pack(side="left")

        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(header, textvariable=self.status_var)
        self.status_label.pack(side="right")

        ttk.Separator(self.root, orient="horizontal").grid(
            row=1, column=0, columnspan=3, sticky="ew"
        )

        # === MAIN PANELS =====================================================

        # LEFT: Connection
        self._build_connection_panel()

        # CENTER: Server browser
        self._build_server_panel()

        # RIGHT: Workspace
        self._build_workspace_panel()

        # === ACTIVITY FEED (bottom) =========================================
        log_frame = ttk.Labelframe(
            self.root, text="Activity Feed", padding=8, style="Section.TLabelframe"
        )
        log_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=10, pady=8)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, state="disabled")
        self.log_text.pack(fill="both", expand=True)

        # Configure grid weights
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_rowconfigure(3, weight=2)
        self.root.grid_columnconfigure(1, weight=2)
        self.root.grid_columnconfigure(2, weight=2)

    def _build_connection_panel(self) -> None:
        conn = ttk.Labelframe(
            self.root,
            text="Connection",
            padding=10,
            style="Section.TLabelframe",
        )
        conn.grid(row=2, column=0, sticky="nsew", padx=(10, 5), pady=8)

        ttk.Label(conn, text="FTP Host").grid(row=0, column=0, sticky="w")
        self.host_var = tk.StringVar(value=FTP_HOST)
        ttk.Entry(conn, textvariable=self.host_var, width=24).grid(
            row=1, column=0, sticky="ew", pady=(0, 6)
        )

        ttk.Label(conn, text="Username").grid(row=2, column=0, sticky="w")
        self.user_var = tk.StringVar(value=FTP_USER)
        ttk.Entry(conn, textvariable=self.user_var, width=24).grid(
            row=3, column=0, sticky="ew", pady=(0, 6)
        )

        ttk.Label(conn, text="Password").grid(row=4, column=0, sticky="w")
        self.pass_var = tk.StringVar(value=FTP_PASSWORD)
        ttk.Entry(conn, textvariable=self.pass_var, show="*", width=24).grid(
            row=5, column=0, sticky="ew", pady=(0, 10)
        )

        btn_row = ttk.Frame(conn)
        btn_row.grid(row=6, column=0, sticky="ew")
        self.btn_connect = ttk.Button(
            btn_row, text="Connect", style="Accent.TButton", command=self.on_connect_clicked
        )
        self.btn_connect.pack(side="left", fill="x", expand=True, padx=(0, 2))

        self.btn_disconnect = ttk.Button(
            btn_row,
            text="Disconnect",
            style="Danger.TButton",
            command=self.on_disconnect_clicked,
        )
        self.btn_disconnect.pack(side="left", fill="x", expand=True, padx=(2, 0))

        conn.grid_rowconfigure(7, weight=1)
        conn.grid_columnconfigure(0, weight=1)

    def _build_server_panel(self) -> None:
        server = ttk.Labelframe(
            self.root,
            text="Server Browser",
            padding=10,
            style="Section.TLabelframe",
        )
        server.grid(row=2, column=1, sticky="nsew", padx=5, pady=8)

        # Search row
        search_row = ttk.Frame(server)
        search_row.pack(fill="x", pady=(0, 6))

        ttk.Label(search_row, text="Filter:").pack(side="left")
        self.search_var = tk.StringVar()
        self.entry_search = ttk.Entry(search_row, textvariable=self.search_var)
        self.entry_search.pack(side="left", fill="x", expand=True, padx=4)
        self.entry_search.bind("<Return>", lambda event: self.on_search_clicked())

        self.btn_search = ttk.Button(
            search_row, text="Apply", width=7, command=self.on_search_clicked
        )
        self.btn_search.pack(side="left", padx=2)

        self.btn_clear_filter = ttk.Button(
            search_row, text="Reset", width=7, command=self.on_clear_filter_clicked
        )
        self.btn_clear_filter.pack(side="left", padx=2)

        self.btn_refresh = ttk.Button(
            search_row, text="Reload", width=7, command=self.on_refresh_clicked
        )
        self.btn_refresh.pack(side="left", padx=2)

        # File list
        list_frame = ttk.Frame(server)
        list_frame.pack(fill="both", expand=True)

        self.file_listbox = tk.Listbox(
            list_frame, selectmode=tk.SINGLE, activestyle="dotbox"
        )
        self.file_listbox.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(
            list_frame, orient="vertical", command=self.file_listbox.yview
        )
        scrollbar.pack(side="right", fill="y")
        self.file_listbox.config(yscrollcommand=scrollbar.set)

        server.pack_propagate(False)
        self.root.grid_rowconfigure(2, weight=1)

    def _build_workspace_panel(self) -> None:
        work = ttk.Labelframe(
            self.root,
            text="Workspace & Actions",
            padding=10,
            style="Section.TLabelframe",
        )
        work.grid(row=2, column=2, sticky="nsew", padx=(5, 10), pady=8)

        # Local directories
        ttk.Label(work, text="Download directory").grid(row=0, column=0, sticky="w")
        self.download_dir_var = tk.StringVar(value=self.download_dir)
        ttk.Entry(work, textvariable=self.download_dir_var).grid(
            row=1, column=0, sticky="ew", pady=(0, 4)
        )
        ttk.Button(
            work, text="Browse…", command=self.on_browse_download
        ).grid(row=1, column=1, padx=4)

        ttk.Label(work, text="Archive directory").grid(row=2, column=0, sticky="w")
        self.archive_dir_var = tk.StringVar(value=self.archive_dir)
        ttk.Entry(work, textvariable=self.archive_dir_var).grid(
            row=3, column=0, sticky="ew", pady=(0, 4)
        )
        ttk.Button(
            work, text="Browse…", command=self.on_browse_archive
        ).grid(row=3, column=1, padx=4)

        ttk.Label(work, text="Errors directory").grid(row=4, column=0, sticky="w")
        self.errors_dir_var = tk.StringVar(value=self.errors_dir)
        ttk.Entry(work, textvariable=self.errors_dir_var).grid(
            row=5, column=0, sticky="ew", pady=(0, 4)
        )
        ttk.Button(
            work, text="Browse…", command=self.on_browse_errors
        ).grid(row=5, column=1, padx=4)

        ttk.Separator(work, orient="horizontal").grid(
            row=6, column=0, columnspan=2, sticky="ew", pady=6
        )

        # Action buttons
        action_row1 = ttk.Frame(work)
        action_row1.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(0, 4))

        self.btn_validate = ttk.Button(
            action_row1,
            text="Validate Selected File",
            style="Accent.TButton",
            command=self.on_validate_clicked,
        )
        self.btn_validate.pack(side="left", fill="x", expand=True, padx=(0, 2))

        self.btn_process = ttk.Button(
            action_row1,
            text="Process Selected File",
            style="Accent.TButton",
            command=self.on_process_clicked,
        )
        self.btn_process.pack(side="left", fill="x", expand=True, padx=(2, 0))

        action_row2 = ttk.Frame(work)
        action_row2.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(2, 0))

        self.btn_open_error_log = ttk.Button(
            action_row2, text="Open Error Log", command=self.on_open_error_log_clicked
        )
        self.btn_open_error_log.pack(side="left", fill="x", expand=True, padx=(0, 2))

        self.btn_clear_log = ttk.Button(
            action_row2, text="Clear Activity Feed", command=self.on_clear_log_clicked
        )
        self.btn_clear_log.pack(side="left", fill="x", expand=True, padx=(2, 0))

        work.grid_columnconfigure(0, weight=1)

    # ------------------------------------------------------------------ #
    #   UTILITIES: logging & threading
    # ------------------------------------------------------------------ #

    def _log(self, text: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {text}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _log_threadsafe(self, text: str) -> None:
        self.root.after(0, lambda: self._log(text))

    def _build_error_preview(self, errors, max_items: int = 5) -> tuple[str, int]:
        # Remove noisy "empty row" messages from preview
        important = [
            e for e in errors
            if "Empty or malformed row encountered" not in e
        ]

        # If everything was filtered out (e.g. file is only empty rows),
        # fall back to the original list so user still sees *something*.
        if not important:
            important = errors

        shown = important[:max_items]
        hidden_count = max(0, len(important) - max_items)

        bullet_lines = "\n".join(f"• {msg}" for msg in shown)
        return bullet_lines, hidden_count

    def _run_in_thread(self, target, *args) -> None:
        t = threading.Thread(target=target, args=args, daemon=True)
        t.start()

    # ------------------------------------------------------------------ #
    #   STATE MANAGEMENT
    # ------------------------------------------------------------------ #

    def _set_connected_state(self) -> None:
        self.status_var.set("Connected")
        self.status_label.configure(style="StatusGood.TLabel")

        self.btn_connect.config(state="disabled")
        self.btn_disconnect.config(state="normal")
        self.btn_refresh.config(state="normal")
        self.btn_search.config(state="normal")
        self.btn_clear_filter.config(state="normal")
        self.btn_validate.config(state="normal")
        self.btn_process.config(state="normal")

    def _set_disconnected_state(self) -> None:
        self.status_var.set("Disconnected")
        self.status_label.configure(style="StatusBad.TLabel")

        self.btn_connect.config(state="normal")
        self.btn_disconnect.config(state="disabled")
        self.btn_refresh.config(state="disabled")
        self.btn_search.config(state="disabled")
        self.btn_clear_filter.config(state="disabled")
        self.btn_validate.config(state="disabled")
        self.btn_process.config(state="disabled")

        self.file_listbox.delete(0, tk.END)
        self.all_files = []

    # ------------------------------------------------------------------ #
    #   DIRECTORY BROWSE
    # ------------------------------------------------------------------ #

    def _choose_directory(self, current: str) -> str | None:
        initial = current if os.path.isdir(current) else os.getcwd()
        path = filedialog.askdirectory(initialdir=initial, mustexist=False)
        if path:
            os.makedirs(path, exist_ok=True)
            return path
        return None

    def on_browse_download(self) -> None:
        path = self._choose_directory(self.download_dir)
        if path:
            self.download_dir = path
            self.download_dir_var.set(path)
            self._log(f"Download directory set to: {path}")

    def on_browse_archive(self) -> None:
        path = self._choose_directory(self.archive_dir)
        if path:
            self.archive_dir = path
            self.archive_dir_var.set(path)
            self._log(f"Archive directory set to: {path}")

    def on_browse_errors(self) -> None:
        path = self._choose_directory(self.errors_dir)
        if path:
            self.errors_dir = path
            self.errors_dir_var.set(path)
            self._log(f"Errors directory set to: {path}")

    # ------------------------------------------------------------------ #
    #   BUTTON HANDLERS
    # ------------------------------------------------------------------ #

    def on_connect_clicked(self) -> None:
        host = self.host_var.get().strip()
        user = self.user_var.get().strip()
        password = self.pass_var.get()

        if not host or not user:
            messagebox.showerror(
                "Missing credentials",
                "Please enter at least Host and Username before connecting.",
            )
            return

        def worker():
            self._log_threadsafe(f"Connecting to {host} as {user}...")
            try:
                self.ftp_client.connect(host, user, password)
            except Exception as e:
                self._log_threadsafe(f"Connection failed: {e}")
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Connection Error", f"Failed to connect: {e}"
                    ),
                )
                return

            self._log_threadsafe("Connection established.")
            self.root.after(0, self._set_connected_state)
            self.root.after(0, self._refresh_file_list)

        self._run_in_thread(worker)

    def on_disconnect_clicked(self) -> None:
        def worker():
            self._log_threadsafe("Disconnecting from FTP server...")
            self.ftp_client.disconnect()
            self._log_threadsafe("Disconnected.")
            self.root.after(0, self._set_disconnected_state)

        self._run_in_thread(worker)

    def on_refresh_clicked(self) -> None:
        self._refresh_file_list()

    def on_search_clicked(self) -> None:
        query = self.search_var.get().strip().lower()
        self.file_listbox.delete(0, tk.END)

        if not query:
            for f in self.all_files:
                self.file_listbox.insert(tk.END, f)
            self._log("Filter cleared: showing all files.")
            return

        matches = [f for f in self.all_files if query in f.lower()]
        if not matches:
            messagebox.showinfo("Filter", "No files match in the file server.")
            self._log(f"Filter '{query}' returned no files.")
        else:
            for f in matches:
                self.file_listbox.insert(tk.END, f)
            self._log(f"Filter '{query}' returned {len(matches)} file(s).")

    def on_clear_filter_clicked(self) -> None:
        self.search_var.set("")
        self.file_listbox.delete(0, tk.END)
        for f in self.all_files:
            self.file_listbox.insert(tk.END, f)
        self._log("Filter reset.")

    def on_clear_log_clicked(self) -> None:
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def on_open_error_log_clicked(self) -> None:
        path = os.path.join(self.errors_dir, "error_report.log")
        if not os.path.exists(path):
            messagebox.showinfo(
                "Error Log", f"No error_report.log found in:\n{self.errors_dir}"
            )
            return

        self._log(f"Opening error log: {path}")
        try:
            if hasattr(os, "startfile"):  # Windows
                os.startfile(path)
            else:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                viewer = tk.Toplevel(self.root)
                viewer.title("Error Log")
                txt = scrolledtext.ScrolledText(viewer)
                txt.pack(fill="both", expand=True)
                txt.insert("1.0", content)
                txt.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Error Log", f"Failed to open error log:\n{e}")

    def on_validate_clicked(self) -> None:
        filename = self._get_selected_filename()
        if not filename:
            return
        self._run_in_thread(self._validate_file_worker, filename)

    def on_process_clicked(self) -> None:
        filename = self._get_selected_filename()
        if not filename:
            return
        self._run_in_thread(self._process_file_worker, filename)

    # ------------------------------------------------------------------ #
    #   CORE ACTIONS
    # ------------------------------------------------------------------ #

    def _refresh_file_list(self) -> None:
        def worker():
            if not self.ftp_client.is_connected():
                self._log_threadsafe("Cannot refresh: not connected.")
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "FTP Error", "Not connected to FTP server."
                    ),
                )
                return

            self._log_threadsafe("Requesting file list from server...")
            try:
                files = self.ftp_client.list_files()
            except Exception as e:
                self._log_threadsafe(f"Failed to list files: {e}")
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "FTP Error", f"Failed to list files: {e}"
                    ),
                )
                return

            self.all_files = sorted(files)
            self._log_threadsafe(f"Found {len(self.all_files)} CSV file(s).")
            self.root.after(0, self._update_file_listbox)

        self._run_in_thread(worker)

    def _update_file_listbox(self) -> None:
        self.file_listbox.delete(0, tk.END)
        for f in self.all_files:
            self.file_listbox.insert(tk.END, f)

    def _get_selected_filename(self) -> str | None:
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning(
                "No selection", "Please choose a file from the Server Browser list."
            )
            return None
        index = selection[0]
        return self.file_listbox.get(index)

    # ------------- VALIDATE (DRY RUN) ---------------------------------- #

    def _validate_file_worker(self, filename: str) -> None:
        if not self.ftp_client.is_connected():
            self._log_threadsafe("Validation aborted: not connected.")
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "FTP Error", "Not connected to FTP server."
                ),
            )
            return

        os.makedirs(self.download_dir, exist_ok=True)
        temp_path = os.path.join(self.download_dir, filename)

        try:
            self._log_threadsafe(f"Downloading '{filename}' for validation…")
            self.ftp_client.download_file(filename, temp_path)

            self._log_threadsafe("Running validation (dry run)…")
            is_valid, errors = validate_csv_file(filename, temp_path)

        except Exception as e:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

            self._log_threadsafe(f"Validation failed: {e}")
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Validation Error", f"Failed to validate file: {e}"
                ),
            )
            return

        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass

        def show_result():
            if is_valid:
                self._log(f"'{filename}' is VALID (dry run).")
                messagebox.showinfo(
                    "Validation Result",
                    f"File '{filename}' is VALID.\n"
                    f"(Dry run only, nothing has been moved.)",
                )
            else:
                self._log(f"'{filename}' is INVALID (dry run).")

                # Build a cleaner preview, hiding noisy "empty row" messages
                bullet_text, hidden_count = self._build_error_preview(
                    errors, max_items=MAX_ERRORS_IN_POPUP
                )

                if hidden_count > 0:
                    bullet_text += f"\n\n+ {hidden_count} more issue(s) not shown."

                messagebox.showwarning(
                    "Validation Result",
                    (
                        f"File '{filename}' is INVALID.\n\n"
                        f"Sample of validation issues:\n\n{bullet_text}\n\n"
                        f"(Dry run only; file not moved and not logged.)"
                    ),
                )



        self.root.after(0, show_result)

    # ------------- PROCESS (DOWNLOAD + ROUTE) -------------------------- #

    def _process_file_worker(self, filename: str) -> None:
        if not self.ftp_client.is_connected():
            self._log_threadsafe("Processing aborted: not connected.")
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "FTP Error", "Not connected to FTP server."
                ),
            )
            return

        if has_been_processed(filename):
            self._log_threadsafe(f"'{filename}' skipped (already processed).")
            self.root.after(
                0,
                lambda: messagebox.showinfo(
                    "Duplicate Detected",
                    f"The file '{filename}' has already been processed.",
                ),
            )
            return

        os.makedirs(self.download_dir, exist_ok=True)
        os.makedirs(self.archive_dir, exist_ok=True)
        os.makedirs(self.errors_dir, exist_ok=True)

        temp_path = os.path.join(self.download_dir, filename)

        try:
            self._log_threadsafe(f"Downloading '{filename}' for processing…")
            self.ftp_client.download_file(filename, temp_path)

            self._log_threadsafe("Running validation before routing…")
            is_valid, errors = validate_csv_file(filename, temp_path)

            if is_valid:
                today_suffix = datetime.now().strftime("%Y%m%d")
                base, ext = os.path.splitext(filename)
                new_name = f"{base}_{today_suffix}{ext}"
                dest_path = os.path.join(self.archive_dir, new_name)

                shutil.move(temp_path, dest_path)
                mark_processed(filename)
                self._log_threadsafe(
                    f"'{filename}' is VALID and archived as '{new_name}'."
                )
                self.root.after(
                    0,
                    lambda: messagebox.showinfo(
                        "Processing Complete",
                        f"File '{filename}' is VALID and archived as:\n{new_name}",
                    ),
                )

            else:
                dest_path = os.path.join(self.errors_dir, filename)
                shutil.move(temp_path, dest_path)

                log_errors(filename, errors, self.errors_dir)
                mark_processed(filename)

                self._log_threadsafe(
                    f"'{filename}' is INVALID and moved to Errors; details logged."
                )

                def show_invalid():
                    bullet_text, hidden_count = self._build_error_preview(
                        errors, max_items=MAX_ERRORS_IN_POPUP
                    )

                    if hidden_count > 0:
                        bullet_text += f"\n\n+ {hidden_count} more issue(s) not shown."

                    messagebox.showwarning(
                        "Processing Complete",
                        (
                            f"File '{filename}' is INVALID and has been moved to the "
                            f"Errors folder.\n\n"
                            f"A full error report has been written to:\n"
                            f"{os.path.join(self.errors_dir, 'error_report.log')}\n\n"
                            f"Sample of recorded issues:\n\n{bullet_text}"
                        ),
                    )


                self.root.after(0, show_invalid)


        except Exception as e:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

            self._log_threadsafe(f"Processing failed: {e}")
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Processing Error", f"Failed to process file: {e}"
                ),
            )
        finally:
            self.root.after(0, self._refresh_file_list)
