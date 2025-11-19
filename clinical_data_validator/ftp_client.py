# ftp_client.py
"""
Thin wrapper around ftplib.FTP to manage FTP connection and file operations.
"""

import ftplib
from typing import List


class FTPClient:
    def __init__(self) -> None:
        self.ftp: ftplib.FTP | None = None

    def connect(self, host: str, user: str, password: str) -> None:
        """Establish FTP connection in passive mode."""
        if self.ftp is not None:
            return  # already connected

        ftp = ftplib.FTP(host, timeout=15)
        ftp.set_pasv(True)
        ftp.login(user=user, passwd=password)
        self.ftp = ftp

    def disconnect(self) -> None:
        """Close FTP connection safely."""
        if self.ftp is not None:
            try:
                self.ftp.quit()
            except Exception:
                # Best-effort close
                try:
                    self.ftp.close()
                except Exception:
                    pass
            finally:
                self.ftp = None

    def is_connected(self) -> bool:
        return self.ftp is not None

    def list_csv_files(self) -> List[str]:
        """
        Return list of CSV files on the remote server.
        Case-insensitive detection for .csv / .CSV / .Csv etc.
        """
        if self.ftp is None:
            raise RuntimeError("FTP client not connected")

        files = self.ftp.nlst()
        return [f for f in files if f.lower().endswith(".csv")]

    def download_file(self, remote_filename: str, local_path: str) -> None:
        """Download a file from the FTP server to the given local path."""
        if self.ftp is None:
            raise RuntimeError("FTP client not connected")

        with open(local_path, "wb") as fp:
            self.ftp.retrbinary(f"RETR {remote_filename}", fp.write)
