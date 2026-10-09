# Root My Galaxy

<img width="108" height="108" alt="sprout_icon_108" src="https://github.com/user-attachments/assets/2ba0e360-0876-489c-b256-f75df7589785" />


Root My Galaxy is a one-click installer for explicitly
supported Samsung model and kernel combinations. The application itself is kept separate
from device offsets, native exploit payloads, and KernelSU build artifacts.


[Latest release](https://github.com/BuSung-dev/Root-My-Galaxy/releases)

The device feed and native payloads are maintained in
[Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads).

## Application


<img width="200" alt="KakaoTalk_20260718_170922353" src="https://github.com/user-attachments/assets/3f562ea4-8c39-4ade-bfd3-93eea1a1cc24" />
<img width="200" alt="KakaoTalk_20260718_171127319" src="https://github.com/user-attachments/assets/8dde0443-12cf-4058-ba76-0337aefb92a0" />
<img width="200" alt="KakaoTalk_20260718_171030202" src="https://github.com/user-attachments/assets/f656e8af-60a6-4fcb-a3db-d4232bede613" />

The app selects a payload whose model list and three-part kernel version match
the phone. For example, `6.6.98-android15-8-...` matches `6.6.98`. Advanced
mode filters the catalog by both values and allows manual selection with model
and kernel-version warnings.

## Investigation workspace (experimental)

The **Investigate** tab is a research-only workspace for collecting device and
firmware facts before attempting a new kernel exploit port. It does **not**
add the Galaxy S20+ to the installable catalog or launch an exploit.

On Android 11+:

1. In Developer options, enable Wireless debugging.
2. In the Shizuku manager, pair with Android's wireless-debugging pairing code
   and start its service (repeat startup after a reboot).
3. In Investigate, select Refresh, then Authorize.
4. Select Collect via Shizuku for read-only shell probes; App snapshot works
   without Shizuku.
5. Export JSON using the Android document picker. Review before sharing.

Shizuku's ADB-shell mode is **not root** and cannot extract protected boot,
vendor_boot or other partitions on a locked phone. If available, Read config.gz
extracts the running kernel's /proc/config.gz, while Save config.gz exports its
original gzip bytes. **Firmware package analysis** accepts multiple user-selected AP, BL, CP, CSC,
and HOME_CSC Odin `.tar` / `.tar.md5` files directly. It reads their TAR
headers and compressed image signatures *in place* to show partition names,
sizes, category, compression type, and 64-bit data offsets without extracting
images or copying multi-gigabyte data into app storage. It also indexes ZIP and
ZIP64 central directories without decompressing them; ZIP entries that contain
nested TAR packages must be selected separately to see their partitions.
User-supplied `.enc4` / `.enc2` packages are identified as encrypted and
require offline decryption. A local seekable file is required; non-seekable
cloud content providers may need the archive downloaded locally first.
Automatic SHA-256 is limited to files 32 MiB or smaller, so an uncomputed hash
must not be interpreted as a verified one. The in-app **Export inventory JSON**
action includes all selected archive entries and warnings without uploading.

### Selective boot image extraction

From **Investigate → Firmware package analysis**, select a matching Samsung
firmware **ZIP** (including the XAA factory ZIP) or a direct **AP_*.tar.md5**.
The resulting firmware card has **Extract boot.img.lz4**. Tap it and choose
a SAF destination. The app streams only `boot.img.lz4` to that destination,
reports scan progress, allows cancellation, and computes the *extracted file's*
SHA-256. For a ZIP, it locates the embedded AP TAR.MD5 and streams the TAR
entry without saving the multi-gigabyte AP intermediary or modifying firmware.

**Important:** the extraction returns the original LZ4-compressed boot image,
not `boot.img` or a kernel ELF. The AP ZIP CRC or Odin MD5 footer is not
verified when extraction stops early; the reported SHA-256 only covers the
saved `boot.img.lz4`. A provider that does not support deleting documents
may leave a partial output on cancellation or error; remove it before reuse.
The source must be readable from Android's document picker and the destination
must have sufficient free space for the boot image. No root, Shizuku, flashing,
or external upload is needed.


Diagnostics use a fixed read-only command allowlist, timeouts and output caps.
No arbitrary shell commands, kernel-address dumps, root payload execution, or
automatic uploads occur in this workspace.

S20+ investigation record:
https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/blob/feature/s20plus-investigation-shizuku-20261009/docs/SM-G986U1-HXL1-INVESTIGATION.md

## Build

Requirements:

- Android Studio JBR 21
- Android SDK 37
- Android NDK 28 or newer
- CMake 3.22.1

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat :app:assembleDebug
```

Output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Use only on devices you own or are explicitly authorized to test.
