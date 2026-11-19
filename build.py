"""Builds release/CS2ServerFilter.exe and the release zip.   Usage: python build.py"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
version = re.search(r'__version__ = "([^"]+)"', open("src/a2s_gui.py", encoding="utf8").read()).group(1)
if not os.path.exists("assets/icon.ico"):
    subprocess.check_call([sys.executable, "make_icon.py"])
subprocess.check_call([sys.executable, "src/a2s_filter.py", "--selftest"])

OUT = sys.argv[1] if len(sys.argv) > 1 else "release"   # e.g. "python build.py release-next" if the old exe is running
for d in ("build", OUT):
    shutil.rmtree(d, ignore_errors=True)
# Windows "Details" tab / installer-style metadata (shown in file properties and the UAC prompt)
os.makedirs("build", exist_ok=True)
v = tuple(int(x) for x in version.split(".")) + (0,) * (4 - len(version.split(".")))
open("build/version_info.txt", "w", encoding="utf8").write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'boomix'),
      StringStruct('FileDescription', 'CS2 Server Browser Fix - hides fake servers from the Steam server browser'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'CS2ServerFilter'),
      StringStruct('LegalCopyright', 'Copyright (c) 2026 boomix. MIT License.'),
      StringStruct('OriginalFilename', 'CS2ServerFilter.exe'),
      StringStruct('ProductName', 'CS2 Server Browser Fix'),
      StringStruct('ProductVersion', '{version}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ])
""")
subprocess.check_call([
    sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile", "--windowed", "--uac-admin",
    "--name", "CS2ServerFilter", "--icon", os.path.abspath("assets/icon.ico"),
    "--version-file", os.path.abspath("build/version_info.txt"), "--paths", "src",
    "--distpath", OUT, "--workpath", "build/work", "--specpath", "build",
    "--collect-all", "customtkinter", "--collect-all", "pydivert", "--hidden-import", "pystray._win32",
    "--add-data", os.path.abspath("assets") + os.pathsep + "assets",
    os.path.abspath("src/a2s_gui.py")])

exe = f"{OUT}/CS2ServerFilter.exe"
zname = f"{OUT}/CS2ServerFilter-v{version}-win64.zip"
with zipfile.ZipFile(zname, "w", zipfile.ZIP_DEFLATED) as z:
    z.write(exe, "CS2ServerFilter.exe")
    for f in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
        z.write(f, f)
with open(f"{OUT}/SHA256SUMS.txt", "w") as out:
    for f in (exe, zname):
        out.write(f"{hashlib.sha256(open(f, 'rb').read()).hexdigest()}  {os.path.basename(f)}\n")
shutil.rmtree("build", ignore_errors=True)
print("built", version, [(f, os.path.getsize(f"{OUT}/" + f)) for f in os.listdir(OUT)])
