Make sure you have provided the following information:

 - [x] link to your code branch cloned from rhboot/shim-review in the form user/repo@tag
   - https://github.com/ecos-platypus/shim-review/tree/ECOS_Technology_GmbH-shim-x64-20220217
 - [x] completed README.md file with the necessary information
   - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220217/README.md
 - [x] shim.efi to be signed
   - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220217/shimx64.efi
 - [x] public portion of your certificate(s) embedded in shim (the file passed to VENDOR_CERT_FILE)
   - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220217/ECOS_Tech_Code_signing_Certificate_Globalsign_2022.cer
 - [x] binaries, for which hashes are added to vendor_db ( if you use vendor_db and have hashes allow-listed )
   - `vendor_db` is not used
 - [x] any extra patches to shim via your own git tree or as files
   - https://github.com/ecos-platypus/shim-review/tree/ECOS_Technology_GmbH-shim-x64-20220217/patches-shim
 - [x] any extra patches to grub via your own git tree or as files
   - https://github.com/ecos-platypus/shim-review/tree/ECOS_Technology_GmbH-shim-x64-20220217/patches-grub
 - [x] build logs
    - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220217/build.log
 - [x] a Dockerfile to reproduce the build of the provided shim EFI binaries
   - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220217/Dockerfile

###### What organization or people are asking to have this signed:
ECOS Technology GmbH

https://www.ecos.de/en/

###### What product or service is this for:
ECOS Secure Boot Stick (SBS)

The ECOS Secure Boot Stick is a secure ThinClient on a USB stick.
It is approved by the german BSI for use in governmental organisations.

https://www.ecos.de/en/products/secure-boot-stick

###### Please create your shim binaries starting with the 15.5 shim release tar file:
###### https://github.com/rhboot/shim/releases/download/15.5/shim-15.5.tar.bz2
###### This matches https://github.com/rhboot/shim/releases/tag/15.5 and contains
###### the appropriate gnu-efi source.
###### Please confirm this as the origin your shim.
Yes.

###### What's the justification that this really does need to be signed for the whole world to be able to boot it:
The SBS is used with a variety of customer devices.
Enrolling custom secure boot keys on each customer devices is infeasible.
Moreover, the SBS is designed to be used with customer devices without additional setup.
We need our own publicly signed shim as we custom-build our kernels for quicker firmware updates and therefore cannot use the shim of a distribution like Fedora.


###### How do you manage and protect the keys used in your SHIM?
The key is stored on a FIPS-140-2 Token.
The key is part of our EV code signing certificate.

###### Do you use EV certificates as embedded certificates in the SHIM?
Yes.

###### If you use new vendor_db functionality, are any hashes allow-listed, and if yes: for what binaries ?
The new `vendor_db` functionality is not used.

###### Is kernel upstream commit 75b0cea7bf307f362057cc778efe89af4c615354 present in your kernel, if you boot chain includes a Linux kernel ?
Yes, it is included in all used kernels.

###### if SHIM is loading GRUB2 bootloader, are CVEs CVE-2020-14372,
###### CVE-2020-25632, CVE-2020-25647, CVE-2020-27749, CVE-2020-27779,
###### CVE-2021-20225, CVE-2021-20233, CVE-2020-10713, CVE-2020-14308,
###### CVE-2020-14309, CVE-2020-14310, CVE-2020-14311, CVE-2020-15705,
###### ( July 2020 grub2 CVE list + March 2021 grub2 CVE list )
###### and if you are shipping the shim_lock module CVE-2021-3418
###### fixed ?
Yes, all the CVEs are fixed in GRUB 2.06.

###### "Please specifically confirm that you add a vendor specific SBAT entry for SBAT header in each binary that supports SBAT metadata
###### ( grub2, fwupd, fwupdate, shim + all child shim binaries )" to shim review doc ?
###### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim
###### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation
shim:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,1,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.ecos,1,ECOS Technology GmbH,shim,15.5,mail:security@ecos.de
```

GRUB:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/
grub.ecos,1,ECOS Technology GmbH,grub2,2.06-r1,mail:security@ecos.de
```

##### Were your old SHIM hashes provided to Microsoft ?
Yes.

##### Did you change your certificate strategy, so that affected by CVE-2020-14372, CVE-2020-25632, CVE-2020-25647, CVE-2020-27749,
##### CVE-2020-27779, CVE-2021-20225, CVE-2021-20233, CVE-2020-10713,
##### CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, CVE-2020-14311, CVE-2020-15705 ( July 2020 grub2 CVE list + March 2021 grub2 CVE list )
##### grub2 bootloaders can not be verified ?
We use a new EV certificate embbeded in shim for verification of the loaded GRUB bootloader.
Older versions of GRUB were signed with an old EV certificate and hence cannot be verified by the new shim.

##### What exact implementation of Secureboot in grub2 ( if this is your bootloader ) you have ?
##### * Upstream grub2 shim_lock verifier or * Downstream RHEL/Fedora/Debian/Canonical like implementation ?
We use the upstream grub2 `shim_lock` verifier.

##### Which modules are built into your signed grub image?
```
acpi
archelp
bitmap
bitmap_scale
boot
btrfs
bufio
cpuid
crypto
datetime
disk
diskfilter
echo
efi_gop
efi_uga
ext2
extcmd
f2fs
fat
font
fshelp
gcry_crc
gcry_rsa
gcry_sha1
gcry_sha512
gettext
gfxmenu
gfxterm
gfxterm_background
gfxterm_menu
gzio
halt
iorw
keylayouts
keystatus
linux
loadenv
loopback
ls
lzopio
memdisk
minicmd
minix
mmap
mpi
net
normal
part_ecx
part_gpt
part_msdos
password_pbkdf2
pbkdf2
pgp
png
priority_queue
probe
procfs
raid6rec
regexp
relocator
smbios
terminal
test
trig
video
video_colors
video_fb
videoinfo
zstd
```

###### What is the origin and full version number of your bootloader (GRUB or other)?
GRUB 2.06 via Gentoo Linux: `sys-boot/grub:2.06-r1` (https://gitweb.gentoo.org/repo/gentoo.git/tree/sys-boot/grub/grub-2.06-r1.ebuild)

###### If your SHIM launches any other components, please provide further details on what is launched
SHIM only launches GRUB.

###### If your GRUB2 launches any other binaries that are not Linux kernel in SecureBoot mode,
###### please provide further details on what is launched and how it enforces Secureboot lockdown
GRUB only launches Linux kernel.

###### If you are re-using a previously used (CA) certificate, you
###### will need to add the hashes of the previous GRUB2 binaries
###### exposed to the CVEs to vendor_dbx in shim in order to prevent
###### GRUB2 from being able to chainload those older GRUB2 binaries. If
###### you are changing to a new (CA) certificate, this does not
###### apply. Please describe your strategy.
We use a new EV certificate.

###### How do the launched components prevent execution of unauthenticated code?

SHIM
- Verifies the signature of GRUB via our EV certificate before loading it
- Only loads `MokManager` and `fallback` binaries built by us together with the SHIM (see `ENABLE_SHIM_CERT=1`), they are not shipped with shim

GRUB
- Verifies the Linux kernel via the `shim_lock` verifier before loading it
- In addition to the `shim_lock` verifier for the Linux kernel, all files loaded by GRUB are verified via the PGP verifier (see `pgp-exit-on-verification-failure.patch` in the `README.md` in our `shim-review` fork for more details on our modifications to abort the boot process if verification fails)
- Module loading has been disabled, GRUB is shipped as one binary, `grub.cfg` is signed and embedded in the GRUB binary, a bootloader password is used to prevent tampering with the configuration and execution of commands via GRUB cmdline

Kernel
- Only loads modules signed by us
- Only executes binaries with a valid IMA signature created by us

###### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
No, GRUB uses the `shim_lock` verifier to ensure that only kernels signed by us are loaded.

###### What kernel are you using? Which patches does it includes to enforce Secure Boot?
We use kernel 5.14 as default and 5.10, 5.4, 4.14 for legacy hardware support.

5.14, 5.10 and 5.4 natively include the upstream lockdown functionality, 4.14 is patched with the Debian lockdown patches (https://salsa.debian.org/kernel-team/linux/-/tree/6c9c81696618874465c51db0019195a501e4910e/debian/patches/features/all/lockdown) and the upstream commits 1957a85b0032a81e6482ca4aab883643b8dae06e and 75b0cea7bf307f362057cc778efe89af4c615354.

All kernels enforce that only modules signed by us are loaded and that only binaries with a valid IMA signature created by us are executed.

###### What changes were made since your SHIM was last signed?

We updated from version 15.0 to the current release (15.5) since our last shim was signed by Microsoft.
We started with upstream shim and only applied a minimal set of patches for security and compatibility reasons.
We include 2 custom patches that disable allowlist functionality and dynamic second stage loader detection (see the `What patches are being applied and why` section of `README.md` in our `shim-review` fork).

###### What is the SHA256 hash of your final SHIM binary?
`5cd5c7c16248b2dc1919cefaa3660abce081d3f932e274b0bada5593b3481571`
