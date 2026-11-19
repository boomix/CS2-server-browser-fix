# Third-party notices

CS2 Server Filter itself is MIT licensed. It bundles or uses:

| Component | Use | License |
|---|---|---|
| [WinDivert](https://reqrypt.org/windivert.html) (driver + DLL, shipped inside `pydivert`) | packet interception | LGPL-3.0 / GPL-2.0 (dual) |
| [pydivert](https://github.com/ffalcinelli/pydivert) | Python bindings for WinDivert | LGPL-3.0 |
| [customtkinter](https://github.com/TomSchimansky/CustomTkinter) | user interface | MIT |
| [pystray](https://github.com/moses-palmer/pystray) | tray icon | LGPL-3.0 |
| [Pillow](https://python-pillow.org) | images | HPND |
| [PyInstaller](https://pyinstaller.org) | builds the .exe | GPL-2.0 with bootloader exception |
| [IP Geolocation by DB-IP](https://db-ip.com) (`assets/geo/dbip.csv.gz`, "IP to Country Lite") | server country lookup | CC BY 4.0 |
| [Flag images from flagcdn.com](https://flagcdn.com) (`assets/flags`) | flags in the country list | free to use |

The LGPL components are used unmodified and can be replaced: the app is built from the source in this
repository with `python build.py`.
