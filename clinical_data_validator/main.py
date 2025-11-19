# main.py
"""
Entry point for the Clinical Data Validation & Archival System.
"""

import tkinter as tk
import config
from gui import App


def main() -> None:
    config.ensure_directories()

    root = tk.Tk()
    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
