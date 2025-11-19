# gui.py
"""
Tkinter GUI for FTP connection, file discovery, search, validation, processing,
and workspace management.

Key user actions:
- Connect / Disconnect
- Refresh file list
- Search files
- Validate (dry-run)
- Process (download + validate + route to Archive/Errors + logging)
"""

from __future__ import annotations

import os
import shutil
import threading
from datetime import datetime
from typing import List

import tkinter as tk
from tkinter import ttk, messagebox

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


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.geometry("900x500")

        self.ftp_client = FTPClient()
        self.all_files: List[str] = []

        self._build_ui()
        self._set_disconnected_state()

    # --------------------------------------------------------------------- #
    # UI construction
    # --------------------------------------------------------------------- #

    def _build_ui(self) -> None:
        self.root.title("Clinical Data Validation & Archival System")

        # Top frame: connection controls
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill="x")

        self.btn_connect = ttk.Button(
            top_frame, text="Connect", command=self.on_connect_clicked
        )
        self.btn_connect.pack(side="left", padx=5)

        self.btn_disconnect = ttk.Button(
            top_frame, text="Disconnect", command=self.on_disconnect_clicked
        )
        self.btn_disconnect.pack(side="left", padx=5)

        self.btn_refresh = ttk.Button(
            top_frame, text="Refresh Workspace", command=self.on_refresh_clicked
        )
        self.btn_refresh.pack(side="left", padx=5)

        # Status label
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(
            top_frame, textvariable=self.status_var, foreground="red"
        )
        self.status_label.pack(side="right")

        # Middle frame: search + listbox
        mid_frame = ttk.Frame(self.root, padding=10)
        mid_frame.pack(fill="both", expand=True)

        search_frame = ttk.Frame(mid_frame)
        search_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(search_frame, text="Search filename:").pack(side="left")

        self.search_var = tk.StringVar()
        self.entry_search = ttk.Entry(search_frame, textvariable=self.search_var)
        self.entry_search.pack(side="left", padx=5, fill="x", expand=True)

        self.btn_search = ttk.Button(
            search_frame, text="Search", command=self.on_search_clicked
        )
        self.btn_search.pack(side="left", padx=5)

        self.btn_clear_search = ttk.Button(
            search_frame, text="Clear", command=self.on_clear_search_clicked
        )
        self.btn_clear_search.pack(side="left", padx=5)

        # Listbox for files
        list_frame = ttk.Frame(mid_frame)
        list_frame.pack(fill="both", expand=True)

        self.file_listbox = tk.Listbox(list_frame, selectmode=tk.SINGLE)
        self.file_listbox.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(
            list_frame, orient="vertical", command=self.file_listbox.yview
        )
        scrollbar.pack(side="right", fill="y")

        self.file_listbox.config(yscrollcommand=scrollbar.set)

        # Bottom frame: validation + processing
        bottom_frame = ttk.Frame(self.root, padding=10)
        bottom_frame.pack(fill="x")

        self.btn_validate = ttk.Button(
            bottom_frame, text="Validate (Dry Run)", command=self.on_validate_clicked
        )
        self.btn_validate.pack(side="left", padx=5)

        self.btn_process = ttk.Button(
            bottom_frame, text="Process File", command=self.on_process_clicked
        )
        self.btn_process.pack(side="left", padx=5)

        self.btn_exit = ttk.Button(bottom_frame, text="Exit", command=self.root.quit)
        self.btn_exit.pack(side="right", padx=5)

    # --------------------------------------------------------------------- #
    # Helper: state management
    # --------------------------------------------------------------------- #

    def _set_connected_state(self) -> None:
        self.status_var.set("Connected")
        self.status_label.configure(foreground="green")

        self.btn_connect.config(state="disabled")
        self.btn_disconnect.config(state="normal")
        self.btn_refresh.config(state="normal")
        self.btn_search.config(state="normal")
        self.btn_clear_search.config(state="normal")
        self.btn_validate.config(state="normal")
        self.btn_process.config(state="normal")

    def _set_disconnected_state(self) -> None:
        self.status_var.set("Disconnected")
        self.status_label.configure(foreground="red")

        self.btn_connect.config(state="normal")
        self.btn_disconnect.config(state="disabled")
        self.btn_refresh.config(state="disabled")
        self.btn_search.config(state="disabled")
        self.btn_clear_search.config(state="disabled")
        self.btn_validate.config(state="disabled")
        self.btn_process.config(state="disabled")

        self.file_listbox.delete(0, tk.END)
        self.all_files = []

    def _run_in_thread(self, target, *args) -> None:
        t = threading.Thread(target=target, args=args, daemon=True)
        t.start()

    # --------------------------------------------------------------------- #
    # Button handlers
    # --------------------------------------------------------------------- #

    def on_connect_clicked(self) -> None:
        def worker():
            try:
                self.ftp_client.connect(FTP_HOST, FTP_USER, FTP_PASSWORD)
            except Exception as e:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Connection Error", f"Failed to connect: {e}"
                    ),
                )
                return

            self.root.after(0, self._set_connected_state)
            # Immediately refresh file list after connect
            self.root.after(0, self._refresh_file_list)

        self._run_in_thread(worker)

    def on_disconnect_clicked(self) -> None:
        def worker():
            self.ftp_client.disconnect()
            self.root.after(0, self._set_disconnected_state)

        self._run_in_thread(worker)

    def on_refresh_clicked(self) -> None:
        self._refresh_file_list()

    def on_search_clicked(self) -> None:
        query = self.search_var.get().strip().lower()
        self.file_listbox.delete(0, tk.END)

        if not query:
            # Show all
            for f in self.all_files:
                self.file_listbox.insert(tk.END, f)
            return

        matches = [f for f in self.all_files if query in f.lower()]

        if not matches:
            messagebox.showinfo("Search", "No matching files found.")
        else:
            for f in matches:
                self.file_listbox.insert(tk.END, f)

    def on_clear_search_clicked(self) -> None:
        self.search_var.set("")
        self.file_listbox.delete(0, tk.END)
        for f in self.all_files:
            self.file_listbox.insert(tk.END, f)

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

    # --------------------------------------------------------------------- #
    # Core actions
    # --------------------------------------------------------------------- #

    def _refresh_file_list(self) -> None:
        def worker():
            if not self.ftp_client.is_connected():
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "FTP Error", "Not connected to FTP server."
                    ),
                )
                return

            try:
                files = self.ftp_client.list_csv_files()
            except Exception as e:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "FTP Error", f"Failed to list files: {e}"
                    ),
                )
                return

            self.all_files = sorted(files)
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
                "Selection Required", "Please select a file from the list first."
            )
            return None

        index = selection[0]
        return self.file_listbox.get(index)

    # ------------------ VALIDATE (DRY RUN) ------------------------------- #

    def _validate_file_worker(self, filename: str) -> None:
        if not self.ftp_client.is_connected():
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "FTP Error", "Not connected to FTP server."
                ),
            )
            return

        temp_path = os.path.join(TEMP_DIR, filename)

        try:
            # Download to temp
            self.ftp_client.download_file(filename, temp_path)

            # Validate
            is_valid, errors = validate_csv_file(filename, temp_path)

        except Exception as e:
            # Clean up temp file
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Validation Error", f"Failed to validate file: {e}"
                ),
            )
            return

        # Remove temp file after dry-run
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass

        def show_result():
            if is_valid:
                messagebox.showinfo(
                    "Validation Result",
                    f"File '{filename}' is VALID.\n"
                    f"(Dry run only, nothing has been moved.)",
                )
            else:
                # Show summary, not every single error if there are many
                preview_errors = "\n".join(errors[:10])
                extra = "" if len(errors) <= 10 else f"\n...and {len(errors) - 10} more."
                messagebox.showwarning(
                    "Validation Result",
                    f"File '{filename}' is INVALID.\n\n"
                    f"Sample of validation errors:\n{preview_errors}{extra}\n\n"
                    f"(Dry run only, file not moved, no error log written.)",
                )

        self.root.after(0, show_result)

    # ------------------ PROCESS (DOWNLOAD + ROUTE) ----------------------- #

    def _process_file_worker(self, filename: str) -> None:
        if not self.ftp_client.is_connected():
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "FTP Error", "Not connected to FTP server."
                ),
            )
            return

        # Duplicate prevention (file-level)
        if has_been_processed(filename):
            self.root.after(
                0,
                lambda: messagebox.showinfo(
                    "Duplicate Detection",
                    f"The file '{filename}' has already been processed.\n"
                    f"Re-processing is not allowed.",
                ),
            )
            return

        temp_path = os.path.join(TEMP_DIR, filename)

        try:
            # Download file from FTP
            self.ftp_client.download_file(filename, temp_path)

            # Validate file
            is_valid, errors = validate_csv_file(filename, temp_path)

            if is_valid:
                # Archive path: CLINICALDATA_YYYYMMDDHHMMSS_YYYYMMDD.csv
                today_suffix = datetime.now().strftime("%Y%m%d")

                base_name = filename
                ext = ""
                if "." in filename:
                    base_name, ext = os.path.splitext(filename)

                new_name = f"{base_name}_{today_suffix}{ext}"
                dest_path = os.path.join(ARCHIVE_DIR, new_name)

                shutil.move(temp_path, dest_path)

                mark_processed(filename)

                self.root.after(
                    0,
                    lambda: messagebox.showinfo(
                        "Processing Complete",
                        f"File '{filename}' is VALID and has been archived as:\n"
                        f"{new_name}",
                    ),
                )

            else:
                # Move to Errors directory with original filename
                dest_path = os.path.join(ERRORS_DIR, filename)
                shutil.move(temp_path, dest_path)

                # Log all errors with GUIDs
                log_errors(filename, errors)
                mark_processed(filename)

                def show_invalid():
                    preview_errors = "\n".join(errors[:10])
                    extra = (
                        "" if len(errors) <= 10 else f"\n...and {len(errors) - 10} more."
                    )
                    messagebox.showwarning(
                        "Processing Complete",
                        f"File '{filename}' is INVALID and has been moved to Errors.\n"
                        f"Errors have been logged in 'Errors/error_report.log'.\n\n"
                        f"Sample of error messages:\n{preview_errors}{extra}",
                    )

                self.root.after(0, show_invalid)

        except Exception as e:
            # Clean up temp file if something exploded in the middle
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Processing Error", f"Failed to process file: {e}"
                ),
            )
            return
        finally:
            self.root.after(0, self._refresh_file_list)
