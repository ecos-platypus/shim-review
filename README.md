This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Here's the template:

-------------------------------------------------------------------------------
### What organization or people are asking to have this signed?
-------------------------------------------------------------------------------
ECOS Technology GmbH

https://www.ecos.de/en/

-------------------------------------------------------------------------------
### What product or service is this for?
-------------------------------------------------------------------------------
ECOS Secure Boot Stick (SBS)

The ECOS Secure Boot Stick is a secure ThinClient on a USB stick.
It is approved by the german BSI for use in governmental organisations.

https://www.ecos.de/en/products/secure-boot-stick

-------------------------------------------------------------------------------
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
-------------------------------------------------------------------------------
The SBS is used with a variety of customer devices.
Enrolling custom secure boot keys on each customer devices is infeasible.
Moreover, the SBS is designed to be used with customer devices without additional setup.
We need our own publicly signed shim as we custom-build our kernels for quicker firmware updates and therefore cannot use the shim of a distribution like Fedora.

-------------------------------------------------------------------------------
### Who is the primary contact for security updates, etc.?
-------------------------------------------------------------------------------
- Name: Simon Becker
- Position: Security Officer
- Email address: simon.becker@ecos.de
- PGP key fingerprint: `84C7B4B4AA363A483332CDC76E4AD9BA7C19AD86`

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

The public key is supplied via the repository (https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220608/pgp/simon.becker.asc) and was pushed to https://keyserver.ubuntu.com.

-------------------------------------------------------------------------------
### Who is the secondary contact for security updates, etc.?
-------------------------------------------------------------------------------
- Name: Gerald Richter
- Position: CTO
- Email address: gerald.richter@ecos.de
- PGP key fingerprint: `2637463F3110510EE2BA62C9375DEFC0CF8C6A6C`

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

The public key is supplied via the repository (https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220608/pgp/gerald.richter.asc) and was pushed to https://keyserver.ubuntu.com.

-------------------------------------------------------------------------------
### Were these binaries created from the 15.6 shim release tar?
Please create your shim binaries starting with the 15.6 shim release tar file: https://github.com/rhboot/shim/releases/download/15.6/shim-15.6.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.6 and contains the appropriate gnu-efi source.

-------------------------------------------------------------------------------
Yes.

-------------------------------------------------------------------------------
### URL for a repo that contains the exact code which was built to get this binary:
-------------------------------------------------------------------------------
https://github.com/ecos-platypus/shim-review

-------------------------------------------------------------------------------
### What patches are being applied and why:
-------------------------------------------------------------------------------

SHIM:

- `100_disable_allowlist.patch`: Our shim should only load PEs signed with the EV certificate embedded in the shim. The `check_allowlist` method was disabled (= it always returns `EFI_NOT_FOUND` and sets the verification method to `VERIFIED_BY_NOTHING`) to prevent loading of PEs trusted via `db` or `MokList`.
- `101_load_default_second_stage.patch`: We always want to use the default loader (set via `DEFAULT_LOADER` during the build) as second stage. We disable the code for dynamic second stage loader detection as it is not required and may cause issues with removable media.
- `102_force_secure_mode.patch`: We force shim to run in secure mode so that the signature of the second stage loader is always verified against our embedded code signing certificate.

GRUB:

- `corecmd-disable-insmod.patch`: Disable the `insmod` command to prevent the dynamic loading of modules at runtime.
- `minicmd-disable-dump-rmmod-lsmod.patch`: Disable the `dump`, and `lsmod` commands to prevent information leakage and the `rmmod` command to prevent unloading of modules at runtime.
- `normal-disable-exit-to-shell.patch`: Disable exit to GRUB shell if `normal_execute` fails.
- `gettext-multiple-translations.patch`: Extend the `gettext` command with support for multiple translations. This is used in our `grub.cfg` for showing multi-line translation texts.
- `loadenv-env-block-sector.patch`: The SBS uses hardware-enabled features to prevent write operations. This patch is for the support of `grubenv` on this hardware.
- `partition-ecx.patch`: We define a custom type of partition table that is essentially a clone of `GPT` with different magic numbers. This prevents Windows from detecting the partition table and prompting the user to override it with a new partition table when the SBS is attached to a running Windows system.
- `efinet-add-dhcp-proxy-support.patch`: Upstream commit (https://github.com/rhboot/grub2/commit/866ec5edb959125b8486769352f1ca04bd81ca3c) to enable DHCP proxy support for PXE boot.
- `gfxterm-get-dimensions.patch`: Add the `get_dimensions` function that sets the `dimension_width` and `dimension_height` environment variables. These variables are used in our grub.cfg to dynamically adjust the GRUB menu in relation to the screen size. 
- `pgp-exit-on-verification-failure.patch`: We use the upstream PGP verifier to verify all files that are loaded by GRUB. The upstream version of the PGP verifier does not load a file if its signature cannot be verified and then tries to carry on with the boot process. However, we want the boot process to abort when a signature cannot be verified as this implies manipulation by an attacker. Therefore, all methods used by the PGP verifier are modified to call `grub_fatal` with a generic error message (`bad signature: %s` where `%s` is replaced with the name of the file whose signature could not be verified) if verification fails for any file loaded by GRUB.
- `sb-force-secure-mode.patch`: We need to force GRUB to run in secure boot mode as we force shim to run in secure mode. Otherwise, GRUB would not verify the loaded kernel via the `shim_lock` verifier during EFI boot without secure boot, causing shim to abort the boot process.

-------------------------------------------------------------------------------
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
-------------------------------------------------------------------------------
We use the upstream GRUB2 `shim_lock` verifier.

-------------------------------------------------------------------------------
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of grub affected by any of the CVEs in the July 2020 grub2 CVE list, the March 2021 grub2 CVE list, or the June 7th 2022 grub2 CVE list:
* CVE-2020-14372
* CVE-2020-25632
* CVE-2020-25647
* CVE-2020-27749
* CVE-2020-27779
* CVE-2021-20225
* CVE-2021-20233
* CVE-2020-10713
* CVE-2020-14308
* CVE-2020-14309
* CVE-2020-14310
* CVE-2020-14311
* CVE-2020-15705
* CVE-2021-3418 (if you are shipping the shim_lock module)

* CVE-2021-3695
* CVE-2021-3696
* CVE-2021-3697
* CVE-2022-28733
* CVE-2022-28734
* CVE-2022-28735
* CVE-2022-28736
* CVE-2022-28737

### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
-------------------------------------------------------------------------------
1. No
2. Yes, we use a new EV certificate, old GRUBs cannot be booted by the new shim.

-------------------------------------------------------------------------------
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?

-------------------------------------------------------------------------------
Yes, they are included in all used kernels.

-------------------------------------------------------------------------------
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
-------------------------------------------------------------------------------
The new `vendor_db` functionality is not used.

-------------------------------------------------------------------------------
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
-------------------------------------------------------------------------------
We use a new EV certificate.

-------------------------------------------------------------------------------
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
-------------------------------------------------------------------------------
We use the Dockerfile that is part of our shim-review repository for the build.
The installed program versions are listed in the shim build log (they are printed to stdout via `dpkg -l`).

We want to prevent third parties from launching their `MokManager` and `fallback` binaries via our shim and therefore set `ENABLE_SHIM_CERT=1` for the build.
With this setting, dynamic keys are generated during the build and used to sign the `MokManager` and `fallback` binaries. The public portion of the dynamic keys are compiled into the shim so that it only loads these signed binaries as `MokManager` and `fallback`.
As these keys differ for each build, the shim binary is not completely reproducible.
However, the diff is small and only contains the embedded dynamic certificates.

-------------------------------------------------------------------------------
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.

-------------------------------------------------------------------------------
The build is executed via `docker build --no-cache --pull -t shim-ecos:15.6 . 2>&1 | tee build.log` in the repository root.
The flags `--no-cache` and `--pull` ensure that `build.log` contains all steps of the build process.
The `build.log` file in root of the repository is the output of our shim build.

-------------------------------------------------------------------------------
### What changes were made since your SHIM was last signed?
-------------------------------------------------------------------------------
We updated from version 15.0 to the current release (15.6) since our last shim was signed by Microsoft (see https://github.com/rhboot/shim-review/issues/228#issuecomment-1054159341 and https://github.com/rhboot/shim-review/issues/228#issuecomment-1066536654 for background; our old signed shim is attached to the second comment as proof).
We started with upstream shim and only applied a minimal set of patches for security and compatibility reasons.
We include 3 custom patches that enforce secure mode and disable allowlist functionality and dynamic second stage loader detection (see the `What patches are being applied and why` section of `README.md` in our `shim-review` fork).

-------------------------------------------------------------------------------
### What is the SHA256 hash of your final SHIM binary?
-------------------------------------------------------------------------------
`48c7823dc532c349d602adc76f85715c125f59ebb1246a13528b66ebcd625c65`

-------------------------------------------------------------------------------
### How do you manage and protect the keys used in your SHIM?
-------------------------------------------------------------------------------
The key is stored on a FIPS-140-2 Token.
The key is part of our EV code signing certificate.

-------------------------------------------------------------------------------
### Do you use EV certificates as embedded certificates in the SHIM?
-------------------------------------------------------------------------------
Yes.

-------------------------------------------------------------------------------
### "Please specifically confirm that you add a vendor specific SBAT entry for SBAT header in each binary that supports SBAT metadata ( grub2, fwupd, fwupdate, shim + all child shim binaries )" to shim review doc ?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
-------------------------------------------------------------------------------
Yes.

shim:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,2,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.ecos,2,ECOS Technology GmbH,shim,15.6,mail:security@ecos.de
```

GRUB:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,2,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/
grub.ecos,2,ECOS Technology GmbH,grub2,2.06-r2,mail:security@ecos.de
```

-------------------------------------------------------------------------------
### Which modules are built into your signed grub image?
-------------------------------------------------------------------------------
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

-------------------------------------------------------------------------------
### What is the origin and full version number of your bootloader (GRUB or other)?
-------------------------------------------------------------------------------
GRUB 2.06 via Gentoo Linux: `sys-boot/grub:2.06-r2` (https://gitweb.gentoo.org/repo/gentoo.git/tree/sys-boot/grub/grub-2.06-r2.ebuild)

-------------------------------------------------------------------------------
### If your SHIM launches any other components, please provide further details on what is launched.
-------------------------------------------------------------------------------
SHIM only launches GRUB.

-------------------------------------------------------------------------------
### If your GRUB2 launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
-------------------------------------------------------------------------------
GRUB only launches Linux kernel.

-------------------------------------------------------------------------------
### How do the launched components prevent execution of unauthenticated code?
-------------------------------------------------------------------------------
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

-------------------------------------------------------------------------------
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
-------------------------------------------------------------------------------
No, GRUB uses the `shim_lock` verifier to ensure that only kernels signed by us are loaded.

-------------------------------------------------------------------------------
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
-------------------------------------------------------------------------------
We use kernel 5.15 as default, 5.17 for new hardware and 5.4 and 4.14 for legacy hardware support.

5.14, 5.17 and 5.4 natively include the upstream lockdown functionality, 4.14 is patched with the Debian lockdown patches (https://salsa.debian.org/kernel-team/linux/-/tree/6c9c81696618874465c51db0019195a501e4910e/debian/patches/features/all/lockdown) and the upstream commits 1957a85b0032a81e6482ca4aab883643b8dae06e, 75b0cea7bf307f362057cc778efe89af4c615354 and eadb2f47a3ced5c64b23b90fd2a3463f63726066.

All kernels enforce that only modules signed by us are loaded and that only binaries with a valid IMA signature created by us are executed.

-------------------------------------------------------------------------------
### Add any additional information you think we may need to validate this shim.
-------------------------------------------------------------------------------

None of our latest submissions have yet been accepted via the shim-review but multiple shims were signed for us by Microsoft in the past.
Our first shim-review submission was https://github.com/rhboot/shim-review/issues/70 in May 2019 which was neither accepted nor rejected due to extensive patching. After consideration, Microsoft signed this shim (see https://github.com/rhboot/shim-review/issues/228#issuecomment-1066536654 for the binary as proof).

Since then we dropped the old patches and now only apply minimal changes to shim. With GRUB we switched from our own appended signature verification to the upstream PGP verifier.

Starting in February, we submitted a 15.4 (https://github.com/rhboot/shim-review/issues/225) and 15.5 (https://github.com/rhboot/shim-review/issues/228) shim and continuously supported the review process by reviewing the submissions of other vendors.

With regards to the Boothole 3 vulnerabilites, it is understandable that no shims have been signed in the last months. However, now that those issues are addressed we urgently need a new shim so that we can ship those fixes to our customers. Unfortunately we cannot address the GRUB vulnerabilities with the shim from May 2019 as our EV certificate expired 2 weeks ago.
