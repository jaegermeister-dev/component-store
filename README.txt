NoMoreBCA Drivers
================

Community Windows driver-support preparation for NoMoreBCA.

STATUS: development preview, not a released NoMoreBCA application. The small
support kit is intended for NoMoreBCA's driver-preparation workflow; downloading
it alone does not provide the third-party driver files.

Windows 7 SP1 x64 on MacBookPro11,5
----------------------------------
The maintainer has confirmed the following on the development installation:
AMD M370X acceleration and Retina resolution; HDMI video/audio through the
laptop and tested Thunderbolt dock; Wi-Fi; internal and headset audio input
and output; SD reader; keyboard input; and Boot Camp trackpad functions after
enabling the desired options in Boot Camp Control Panel.

Known unfinished: internal keyboard backlight, internal keyboard Fn controls,
and the tested Thunderbolt dock's Ethernet connection. Camera picture, sleep
and power behaviour, and fresh-install USB-keyboard reliability are not fully
validated. The complete combined installer still needs clean-install testing.
The tested M370X configuration also requires NoMoreBCA's separate EFI support;
installing the driver alone does not provide that boot-time fix.

MacBookPro11,4
-------------
Untested. It may be able to use the shared components, but this is not a claim
of compatibility. Its support package must exclude AMD M370X and AMD HDMI-audio
drivers. Intel Iris graphics have not been validated by this project.

Distribution approach
---------------------
NoMoreBCA's next build will obtain a versioned recipe and our own installer from
this repository. Original third-party drivers will be downloaded directly
from their publishers where redistribution has not been authorised, checked
against recorded hashes, and prepared locally. This repository does not grant
rights to any Apple, AMD, Broadcom, Intel, Lenovo or Microsoft software.

No Windows installation image, FlashBoot proprietary payload, private machine
logs, SSH keys, remote-control setup, UAC-disabling configuration or administrator
automation is published here. Windows setup and activation are not modified by
this driver-support project. The driver installer requires normal UAC approval.

Future support releases will identify their version and changed components so
existing Windows users can obtain new fixes without reinstalling Windows.
Do not treat development source or an incomplete recipe as a tested release.

Reconstruction and source
-------------------------
The development reconstruction audit on Tahoe reproduced all 265 original
driver files, totalling 349,299,250 bytes, identically to the current project's
reference pack. This is a file-integrity result, not a fresh driver-install
test or proof that every publisher URL remains available forever.

source/ contains the code embedded in the installer. build_installer.py can
build it using Python and Zig; these are DEVELOPER build tools, not requirements
for the finished Windows installer or NoMoreBCA's users. The recorded compiler
was Zig 0.17.0-dev.2251+1175a3e99, targeting Windows 7 x64. Public build metadata
records the exact installer/source hashes. Vendor installers are not executed
on macOS; the recipe selects original signed files from their packages.

This project is not affiliated with or endorsed by the hardware/software vendors.
