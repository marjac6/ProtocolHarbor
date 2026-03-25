# main.py
from gui import App
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.iconbitmap("icon.ico")
    except Exception:
        pass
    app = App(root)
    root.mainloop()