# main.py
import sys
import os
import ctypes
import tkinter as tk
import webbrowser
from debug_utils import configure_debug_logging, install_exception_hooks


WINDOWS_APP_ID = "marjac6.ProtocolHarbor"
_ICON_HANDLES = []
NPCAP_URL = "https://npcap.com/#download"

def _resource_path(filename):
    base = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(base, filename)


def _set_window_icon(root):
    icon_path = _resource_path("icon.ico")
    if not os.path.exists(icon_path):
        return

    try:
        root.iconbitmap(default=icon_path)
    except Exception:
        pass

    if os.name != "nt":
        return

    try:
        user32 = ctypes.windll.user32
        root.update_idletasks()
        hwnd = root.winfo_id()
        parent_hwnd = user32.GetParent(hwnd)
        if parent_hwnd:
            hwnd = parent_hwnd

        WM_SETICON = 0x0080
        ICON_BIG = 1
        ICON_SMALL = 0
        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x0010
        GCLP_HICON = -14
        GCLP_HICONSM = -34
        SM_CXICON = 11
        SM_CYICON = 12
        SM_CXSMICON = 49
        SM_CYSMICON = 50

        set_class_long = getattr(user32, "SetClassLongPtrW", None)
        if set_class_long is None:
            set_class_long = user32.SetClassLongW

        hbig = user32.LoadImageW(
            0,
            icon_path,
            IMAGE_ICON,
            user32.GetSystemMetrics(SM_CXICON),
            user32.GetSystemMetrics(SM_CYICON),
            LR_LOADFROMFILE,
        )
        hsmall = user32.LoadImageW(
            0,
            icon_path,
            IMAGE_ICON,
            user32.GetSystemMetrics(SM_CXSMICON),
            user32.GetSystemMetrics(SM_CYSMICON),
            LR_LOADFROMFILE,
        )

        if hbig:
            _ICON_HANDLES.append(hbig)
            user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hbig)
            set_class_long(hwnd, GCLP_HICON, hbig)

        if hsmall:
            _ICON_HANDLES.append(hsmall)
            user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hsmall)
            set_class_long(hwnd, GCLP_HICONSM, hsmall)
    except Exception:
        pass


def _can_load_windows_dll(dll_name: str) -> tuple[bool, str]:
    if os.name != "nt":
        return True, ""
    try:
        ctypes.WinDLL(dll_name)
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _detect_npcap_problem() -> str:
    """Return an error description when Npcap WinPcap-compatible runtime is missing."""
    if os.name == "nt":
        packet_ok, packet_err = _can_load_windows_dll("Packet.dll")
        wpcap_ok, wpcap_err = _can_load_windows_dll("wpcap.dll")
        if not (packet_ok and wpcap_ok):
            reason_parts = []
            if not packet_ok:
                reason_parts.append(f"Packet.dll: {packet_err}")
            if not wpcap_ok:
                reason_parts.append(f"wpcap.dll: {wpcap_err}")
            return "; ".join(reason_parts)
    return ""


def _show_npcap_warning() -> None:
    reason = _detect_npcap_problem()
    if not reason:
        return

    dialog_root = tk.Tk()
    dialog_root.withdraw()
    dialog_root.attributes("-topmost", True)

    win = tk.Toplevel(dialog_root)
    win.title("Wymagany Npcap / Npcap Required")
    win.resizable(False, False)
    win.transient(dialog_root)

    outer = tk.Frame(win, padx=18, pady=14)
    outer.pack(fill="both", expand=True)

    tk.Label(
        outer,
        text="Brakuje Npcap - funkcje EtherCAT sa obecnie niedostepne.\n"
             "Npcap is missing - EtherCAT features are currently unavailable.",
        anchor="w",
        justify="left",
        font=("Segoe UI", 10, "bold"),
    ).pack(fill="x", pady=(0, 8))

    tk.Label(
        outer,
           text="Aby wlaczyc EtherCAT, zainstaluj Npcap z zaznaczona opcja:\n"
               "Install Npcap in WinPcap API-compatible Mode.\n\n"
               "To enable EtherCAT, install Npcap with this option selected:\n"
               "Install Npcap in WinPcap API-compatible Mode.",
        anchor="w",
        justify="left",
        font=("Segoe UI", 9),
    ).pack(fill="x")

    link = tk.Label(
        outer,
        text=NPCAP_URL,
        fg="#0b57d0",
        cursor="hand2",
        anchor="w",
        justify="left",
        font=("Segoe UI", 9, "underline"),
    )
    link.pack(fill="x", pady=(10, 0))
    link.bind("<Button-1>", lambda _event: webbrowser.open(NPCAP_URL))

    tk.Label(
        outer,
        text=f"Szczegoly diagnostyczne / Diagnostic details: {reason}",
        anchor="w",
        justify="left",
        fg="#555555",
        wraplength=520,
        font=("Segoe UI", 8),
    ).pack(fill="x", pady=(8, 0))

    button_row = tk.Frame(outer)
    button_row.pack(fill="x", pady=(14, 0))

    def _open_and_close():
        webbrowser.open(NPCAP_URL)
        win.destroy()

    tk.Button(
        button_row,
        text="Pobierz Npcap / Download Npcap",
        width=30,
        bg="#0b57d0",
        fg="white",
        relief="flat",
        command=_open_and_close,
    ).pack(side="left")

    tk.Button(
        button_row,
        text="Uruchom mimo to / Continue anyway",
        width=30,
        command=win.destroy,
    ).pack(side="right")

    win.update_idletasks()
    width = max(win.winfo_width(), 580)
    height = max(win.winfo_height(), 250)
    screen_w = win.winfo_screenwidth()
    screen_h = win.winfo_screenheight()
    pos_x = max((screen_w - width) // 2, 0)
    pos_y = max((screen_h - height) // 2, 0)
    win.geometry(f"{width}x{height}+{pos_x}+{pos_y}")

    win.grab_set()
    win.focus_force()
    win.wait_window()
    dialog_root.destroy()

if __name__ == "__main__":
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(WINDOWS_APP_ID)
    except Exception:
        pass
    configure_debug_logging()
    install_exception_hooks()

    _show_npcap_warning()

    from gui import App

    root = tk.Tk()
    app = App(root)
    _set_window_icon(root)
    root.after_idle(lambda: _set_window_icon(root))
    root.mainloop()
