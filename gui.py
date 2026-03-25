# gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scanner import get_adapters, start_scan, start_active_scan, send_arp_probe
from profinet_scanner import start_dcp_scan_all, start_dcp_scan


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Balluff / BNI Device Scanner")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        self.stop_event = threading.Event()
        self.scanning = False
        self.found_devices = []

        self.auto_refresh = tk.BooleanVar(value=False)
        self.refresh_interval = tk.IntVar(value=30)
        self._auto_refresh_job = None

        self._build_ui()
        self._load_adapters()

    def _build_ui(self):
        # ── Górny panel: wybór adaptera ──────────────────────────
        top = tk.LabelFrame(self.root, text="Adapter sieciowy", padx=8, pady=6)
        top.pack(fill="x", padx=10, pady=(10, 4))

        tk.Label(top, text="Skanuj:").grid(row=0, column=0, sticky="w")

        self.adapter_var = tk.StringVar(value="Wszystkie adaptery")
        self.adapter_cb = ttk.Combobox(top, textvariable=self.adapter_var, width=55, state="readonly")
        self.adapter_cb.grid(row=0, column=1, padx=8)

        self.btn_scan = tk.Button(top, text="▶  Start", width=12,
                                   bg="#2e7d32", fg="white", font=("Segoe UI", 9, "bold"),
                                   command=self.toggle_scan)
        self.btn_scan.grid(row=0, column=2, padx=4)

        self.btn_clear = tk.Button(top, text="🗑  Wyczyść", width=12,
                                    command=self.clear_results)
        self.btn_clear.grid(row=0, column=3, padx=4)

        # ── Panel auto-odświeżania ────────────────────────────────
        refresh_frame = tk.LabelFrame(self.root, text="Auto-odświeżanie", padx=8, pady=4)
        refresh_frame.pack(fill="x", padx=10, pady=(0, 4))

        self.chk_auto = tk.Checkbutton(refresh_frame, text="Włącz",
                                        variable=self.auto_refresh,
                                        command=self._on_auto_refresh_toggle)
        self.chk_auto.grid(row=0, column=0, padx=(0, 8))

        tk.Label(refresh_frame, text="Interwał (s):").grid(row=0, column=1)
        self.spin_interval = tk.Spinbox(refresh_frame, from_=10, to=300,
                                         textvariable=self.refresh_interval,
                                         width=5)
        self.spin_interval.grid(row=0, column=2, padx=4)

        self.lbl_next = tk.Label(refresh_frame, text="", fg="gray")
        self.lbl_next.grid(row=0, column=3, padx=12)

        # ── Status ───────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Gotowy")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                               anchor="w", relief="sunken", font=("Segoe UI", 8))
        status_bar.pack(fill="x", padx=10, pady=(0, 4))

# ── Tabela wyników ───────────────────────────────────────
        table_frame = tk.LabelFrame(self.root, text="Znalezione urządzenia", padx=8, pady=6)
        table_frame.pack(fill="both", expand=True, padx=10, pady=4)

        cols = ("ip", "mac", "name", "protocol", "vendor_id", "device_id", "adapter")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)
        self.tree.heading("ip",        text="Adres IP")
        self.tree.heading("mac",       text="Adres MAC")
        self.tree.heading("name",      text="Nazwa / Producent")
        self.tree.heading("protocol",  text="Protokół")
        self.tree.heading("vendor_id", text="VendorID")
        self.tree.heading("device_id", text="DeviceID")
        self.tree.heading("adapter",   text="Adapter")
        self.tree.column("ip",        width=120)
        self.tree.column("mac",       width=145)
        self.tree.column("name",      width=160)
        self.tree.column("protocol",  width=100)
        self.tree.column("vendor_id", width=70)
        self.tree.column("device_id", width=70)
        self.tree.column("adapter",   width=170)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # ── Log ──────────────────────────────────────────────────
        log_frame = tk.LabelFrame(self.root, text="Log", padx=8, pady=4)
        log_frame.pack(fill="x", padx=10, pady=(4, 10))

        self.log = scrolledtext.ScrolledText(log_frame, height=5,
                                              font=("Consolas", 8), state="disabled")
        self.log.pack(fill="x")

    def _load_adapters(self):
        adapters = get_adapters()
        self.adapters = adapters
        names = ["Wszystkie adaptery"] + [
            f"{a['description']}  [{', '.join(a['ips']) or 'brak IP'}]"
            for a in adapters
        ]
        self.adapter_cb["values"] = names
        self.adapter_cb.current(0)
        self.log_message(f"Znaleziono {len(adapters)} adapterów.")

    def log_message(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def on_device_found(self, info):
        self.root.after(0, self._add_device, info)
    def on_profinet_found(self, info):
        self.root.after(0, self._add_profinet_device, info)

    def _add_device(self, info):
        key = (info["ip"], info["mac"])
        if key in [(d.get("ip"), d.get("mac")) for d in self.found_devices]:
            return
        self.found_devices.append(info)
        self.tree.insert("", "end", values=(
            info.get("ip", ""),
            info.get("mac", ""),
            info.get("keyword", ""),
            info.get("type", "ARP"),
            "", "",
            info.get("adapter", "?"),
        ))
        self.log_message(
            f"✔ ARP: {info.get('keyword','?')}  IP={info.get('ip','?')}  "
            f"MAC={info.get('mac','?')}  [{info.get('adapter','?')}]"
        )

    def _add_profinet_device(self, info):
        key = (info.get("ip", ""), info.get("mac", ""))
        if key in [(d.get("ip"), d.get("mac")) for d in self.found_devices]:
            return
        self.found_devices.append(info)
        self.tree.insert("", "end", values=(
            info.get("ip", ""),
            info.get("mac", ""),
            info.get("name_of_station", ""),
            "Profinet DCP",
            info.get("vendor_id", ""),
            info.get("device_id", ""),
            info.get("adapter", "?"),
        ))
        self.log_message(
            f"🏭 Profinet: {info.get('name_of_station', '?')}  "
            f"IP={info.get('ip', '?')}  MAC={info.get('mac', '?')}"
        )

    def toggle_scan(self):
        if not self.scanning:
            self._start_scan()
        else:
            self._stop_scan()

    def _start_scan(self):
        self.scanning = True
        self.stop_event.clear()
        self.btn_scan.config(text="⏹  Stop", bg="#c62828")
        self.status_var.set("⏳ Skanowanie w toku...")

        selected = self.adapter_cb.current()

        if selected == 0:
            self.log_message("Uruchamiam ARP + Profinet DCP na wszystkich adapterach...")

            threading.Thread(
                target=start_active_scan,
                args=(self.on_device_found, self.stop_event),
                daemon=True
            ).start()

            threading.Thread(
                target=start_dcp_scan_all,
                args=(self.on_profinet_found, self.stop_event),
                daemon=True
            ).start()

        else:
            adapter = self.adapters[selected - 1]
            self.log_message(f"Uruchamiam ARP + Profinet DCP: {adapter['description']}...")

            threading.Thread(
                target=start_scan,
                args=(adapter["name"], self.on_device_found, self.stop_event),
                daemon=True
            ).start()

            threading.Thread(
                target=send_arp_probe,
                args=(adapter["name"], self.stop_event),
                daemon=True
            ).start()

            threading.Thread(
                target=start_dcp_scan,
                args=(adapter["name"], self.on_profinet_found, self.stop_event),
                daemon=True
            ).start()

    def _stop_scan(self):
        self.scanning = False
        self.stop_event.set()
        self.btn_scan.config(text="▶  Start", bg="#2e7d32")
        self.status_var.set("Zatrzymano.")
        self.log_message("Skanowanie zatrzymane.")

    def clear_results(self):
        self.found_devices.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.log_message("Wyniki wyczyszczone.")

    def _on_auto_refresh_toggle(self):
        if self.auto_refresh.get():
            self.log_message("Auto-odświeżanie włączone.")
            self._schedule_next_refresh()
        else:
            self.log_message("Auto-odświeżanie wyłączone.")
            self._cancel_auto_refresh()
            self.lbl_next.config(text="")

    def _schedule_next_refresh(self):
        interval = self.refresh_interval.get() * 1000
        self._countdown(self.refresh_interval.get())
        self._auto_refresh_job = self.root.after(interval, self._auto_refresh_cycle)

    def _cancel_auto_refresh(self):
        if self._auto_refresh_job:
            self.root.after_cancel(self._auto_refresh_job)
            self._auto_refresh_job = None

    def _auto_refresh_cycle(self):
        if not self.auto_refresh.get():
            return
        self.log_message("⟳ Auto-odświeżanie — restart skanowania...")
        if self.scanning:
            self._stop_scan()
            self.root.after(500, self._restart_after_stop)
        else:
            self._start_scan()
            self._schedule_next_refresh()

    def _restart_after_stop(self):
        self._start_scan()
        self._schedule_next_refresh()

    def _countdown(self, seconds_left):
        if not self.auto_refresh.get():
            return
        self.lbl_next.config(text=f"Następne odświeżenie za: {seconds_left}s")
        if seconds_left > 0:
            self.root.after(1000, self._countdown, seconds_left - 1)