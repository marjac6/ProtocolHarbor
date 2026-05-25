Changelog

[1.3.1]

- Fixed startup crash in EXE when EtherCAT runtime DLL dependencies are missing.
- Added startup dependency check for Npcap (WinPcap API-compatible mode).
- Added user-friendly popup with official Npcap download link when Npcap is not installed.
- Improved startup resilience: app can continue to run with EtherCAT features unavailable.
- Replaced runtime SVG rendering with bundled github.png to avoid Cairo/reportlab dependency at startup.
- Fixed footer GitHub logo sizing by adding explicit icon downscaling.

[1.3.0]

- Added protocol switch: EtherCAT -> Profinet / Modbus TCP / Ethernet IP.
- Added full PL/EN interface with automatic OS language detection.
- Added language switcher in the top-right corner (PL/EN flags).
- Added bilingual, resizable changelog window.

[1.2.0]

- Added protocol switch: EtherCAT -> Profinet / Modbus TCP / Ethernet IP.
- Added IP status markers and quick open of device web panel.
- Improved scan behavior when changing network adapter.

[1.1.0]

- Added Profinet device configuration from GUI (IP and station name).
- Added verification after saving Profinet settings.
- Improved Profinet UI layout and compatibility.

[1.0.1]

- Added device description column in the main table.
- Added IP conflict detection and row coloring.
- Improved vendor recognition and subnet detection.

[1.0.0]

- Unified device list and protocol detection.
- Added LLDP and Profinet data enrichment.
- Improved logging and diagnostics.

[0.3.0]

- Added EtherCAT scan support.

[0.2.0]

- Improved scan stability and adapter handling.
- Improved Profinet DCP discovery.
- Added UI quality-of-life improvements.

[0.1.0]

- Initial release.