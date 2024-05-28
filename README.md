This repo is for review of requests for signing shim. To create a request for review:

- clone this repo (preferably fork it)
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push it to GitHub
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Hint: check the [docs](./docs/) directory in this repo for guidance on submission and getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
ECOS Technology GmbH

https://www.ecos.de/en/

*******************************************************************************
### What product or service is this for?
*******************************************************************************
ECOS Secure Boot Stick (SBS)

The ECOS Secure Boot Stick is a secure ThinClient on a USB stick.
It is approved by the german BSI for use in governmental organisations.

https://www.ecos.de/en/products/secure-boot-stick

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
The SBS is used with a variety of customer devices.
Enrolling custom secure boot keys on each customer devices is infeasible.
Moreover, the SBS is designed to be used with customer devices without additional setup.


*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
We need our own publicly signed shim as we custom-build our kernels for quicker firmware updates and therefore cannot use the shim of a distribution like Fedora.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Christoph Stolz
- Position: Head of development
- Email address: christoph.stolz@ecos.de
- PGP key fingerprint: `30F673456BBE7C04C8F1B1864D29627309AD653C`

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

The public key is supplied via the repository in the pgp directory
(https://github.com/ecos-platypus/shim-review/blob/shim-review-2024/pgp/christoph.stolz.asc) and was pushed to https://keyserver.ubuntu.com.

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Gerald Richter
- Position: CTO
- Email address: gerald.richter@ecos.de
- PGP key fingerprint: `2637463F3110510EE2BA62C9375DEFC0CF8C6A6C`

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

The public key is supplied via the repository in the pgp directory
(https://github.com/ecos-platypus/shim-review/blob/shim-review-2024/pgp/gerald.richter.asc) and was pushed to https://keyserver.ubuntu.com.

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

Make sure the tarball is correct by verifying your download's checksum with the following ones:

```
a9452c2e6fafe4e1b87ab2e1cac9ec00  shim-15.8.tar.bz2
cdec924ca437a4509dcb178396996ddf92c11183  shim-15.8.tar.bz2
a79f0a9b89f3681ab384865b1a46ab3f79d88b11b4ca59aa040ab03fffae80a9  shim-15.8.tar.bz2
30b3390ae935121ea6fe728d8f59d37ded7b918ad81bea06e213464298b4bdabbca881b30817965bd397facc596db1ad0b8462a84c87896ce6c1204b19371cd1  shim-15.8.tar.bz2
```

Make sure that you've verified that your build process uses that file as a source of truth (excluding external patches) and its checksum matches. Furthermore, there's [a detached signature as well](https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2.asc) - check with the public key that has the fingerprint `8107B101A432AAC9FE8E547CA348D61BC2713E9F` that the tarball is authentic. Once you're sure, please confirm this here with a simple *yes*.

A short guide on verifying public keys and signatures should be available in the [docs](./docs/) directory.
*******************************************************************************
Yes

*******************************************************************************
### URL for a repo that contains the exact code which was built to result in your binary:
Hint: If you attach all the patches and modifications that are being used to your application, you can point to the URL of your application here (*`https://github.com/YOUR_ORGANIZATION/shim-review`*).

You can also point to your custom git servers, where the code is hosted.
*******************************************************************************
https://github.com/ecos-platypus/shim-review/tree/shim-review-2024

*******************************************************************************
### What patches are being applied and why:
Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.
*******************************************************************************


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


*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
No, we do not have the NX bit set. Our complete boot stack is not ready yet.

*******************************************************************************
### What exact implementation of Secure Boot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
Skip this, if you're not using GRUB2.
*******************************************************************************
We use the upstream GRUB2 `shim_lock` verifier.

*******************************************************************************
### Do you have fixes for all the following GRUB2 CVEs applied?
**Skip this, if you're not using GRUB2, otherwise make sure these are present and confirm with _yes_.**

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
yes

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
Skip this, if you're not using GRUB2, otherwise do you have an entry in your GRUB2 binary similar to:  
`grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`?
*******************************************************************************
yes

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
If you had no previous signed shim, say so here. Otherwise a simple _yes_ will do.
*******************************************************************************
yes

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
Hint: upstream kernels should have all these applied, but if you ship your own heavily-modified older kernel version, that is being maintained separately from upstream, this may not be the case.  
If you are shipping an older kernel, double-check your sources; maybe you do not have all the patches, but ship a configuration, that does not expose the issue(s).
*******************************************************************************
Yes, they are included in all used kernels.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
Our kernels contains patches for additional hardware support. No security/efi related kernel features are patched.

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
Our product (ECOS SecureBootStick (SBS)) only boots from a hardware usb stick, which is read only, which is enforced by the hardware.
The whole software is delivered and updated as one digital sigend image, so shim, grub, initrd, kernel and kernel modules always match. 
Because the stick is read only and shim will only load our grub and our grub does not load an external grub.cfg, but only uses the buildin (and therefor signed) grub.cfg,
together with other security meassures, there is no possiblity to load other kernels and kernel modules, than the ones that are part of our image.

Additionaly we are currently in the process to change our kernel build process to use an ephemeral key for kernel module signing.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
The `vendor_db` functionality is not used.

*******************************************************************************
### If you are re-using the CA certificate from your last shim binary, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs mentioned earlier to vendor_dbx in shim. Please describe your strategy.
This ensures that your new shim+GRUB2 can no longer chainload those older GRUB2 binaries with issues.

If this is your first application or you're using a new CA certificate, please say so here.
*******************************************************************************
We use a new EV certificate.

*******************************************************************************
### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?
A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

Hint: Prefer using *frozen* packages for your toolchain, since an update to GCC, binutils, gnu-efi may result in building a shim binary with a different checksum.

If your shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case, what the differences would be and what build environment (OS and toolchain) is being used to reproduce this build? In this case please write a detailed guide, how to setup this build environment from scratch.
*******************************************************************************
yes, you can build using `docker build .` from our shim-review repository.

To do a full rebuild, run `docker build --no-cache --pull -t shim-ecos:15.8 .`, 
this will also output the sha256 hash of the resulting shim and verify that there
are no changes to the shim we submitted (and which is part of our shim-review repository)

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
The build is executed via `docker build --no-cache --pull -t shim-ecos:15.8 . 2>&1 | tee build.log` in the repository root.
The flags `--no-cache` and `--pull` ensure that `build.log` contains all steps of the build process.
The `build.log` file in root of the repository is the output of our shim build.

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..

Skip this, if this is your first application for having shim signed.
*******************************************************************************
- We updated shim from version 15.6 to the current release 15.8
- We updated grub from version 2.06 to grub 2.12
- We have a new EV certificate which is build into shim and used to sign grub
- We use newer kernels

*******************************************************************************
### What is the SHA256 hash of your final shim binary?
*******************************************************************************
`cfb155df60992a5cee2dff99d75089ee03a578d2d01e7d30b7cf5fc1c67da3b0`

*******************************************************************************
### How do you manage and protect the keys used in your shim?
Describe the security strategy that is used for key protection. This can range from using hardware tokens like HSMs or Smartcards, air-gapped vaults, physical safes to other good practices.
*******************************************************************************
The key is stored on a FIPS-140-2 Token.
The key is part of our EV code signing certificate.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the shim?
A _yes_ or _no_ will do. There's no penalty for the latter.
*******************************************************************************
yes

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide the exact SBAT entries for all binaries you are booting directly through shim.
Hint: The history of SBAT and more information on how it works can be found [here](https://github.com/rhboot/shim/blob/main/SBAT.md). That document is large, so for just some examples check out [SBAT.example.md](https://github.com/rhboot/shim/blob/main/SBAT.example.md)

If you are using a downstream implementation of GRUB2 (e.g. from Fedora or Debian), make sure you have their SBAT entries preserved and that you **append** your own (don't replace theirs) to simplify revocation.

**Remember to post the entries of all the binaries. Apart from your bootloader, you may also be shipping e.g. a firmware updater, which will also have these.**

Hint: run `objcopy --only-section .sbat -O binary YOUR_EFI_BINARY /dev/stdout` to get these entries. Paste them here. Preferably surround each listing with three backticks (\`\`\`), so they render well.
*******************************************************************************

shim:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.ecos,1,ECOS Technology GmbH,shim,15.8,mail:security@ecos.de
```

GRUB:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,4,Free Software Foundation,grub,2.12,https://www.gnu.org/software/grub/
grub.ecos,1,ECOS Technology GmbH,grub2,2.12,mail:security@ecos.de
```

We do only use shim and GRUB. There is no possibility to start other binaries directly through shim.

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
Skip this, if you're not using GRUB2.

Hint: this is about those modules that are in the binary itself, not the `.mod` files in your filesystem.
*******************************************************************************
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

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
systemd-boot is not used

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
GRUB 2.12 via Gentoo Linux: `sys-boot/grub:2.12-r4` (https://gitweb.gentoo.org/repo/gentoo.git/tree/sys-boot/grub/grub-2.12-r4.ebuild)

*******************************************************************************
### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.
Hint: The most common case here will be a firmware updater like fwupd.
*******************************************************************************
SHIM only launches GRUB.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
Skip this, if you're not using GRUB2 or systemd-boot.
*******************************************************************************
GRUB only launches Linux kernel.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
Summarize in one or two sentences, how your secure bootchain works on higher level.
*******************************************************************************
SHIM
- Verifies the signature of GRUB via our EV certificate before loading it
- Only loads `MokManager` and `fallback` binaries signed by the embedded EV certificate as allowlist is disabled via `100_disable_allowlist.patch`
- `MokManager` and `fallback` are not used and not shipped with our product.

GRUB
- Verifies the Linux kernel via the `shim_lock` verifier before loading it
- In addition to the `shim_lock` verifier for the Linux kernel, all files loaded by GRUB are verified via the PGP verifier (see `pgp-exit-on-verification-failure.patch` in the `README.md` in our `shim-review` fork for more details on our modifications to abort the boot process if verification fails)
- Module loading has been disabled, GRUB is shipped as one binary, `grub.cfg` is signed and embedded in the GRUB binary, a bootloader password is used to prevent tampering with the configuration and execution of commands via GRUB cmdline

Kernel
- Only loads modules signed by us
- Only executes binaries with a valid IMA signature created by us

*******************************************************************************
### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?
*******************************************************************************
No, GRUB uses the `shim_lock` verifier to ensure that only kernels signed by us are loaded.

*******************************************************************************
### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?
*******************************************************************************
We use kernel 6.1 as default, and 5.15 and 5.10 for legacy hardware support.

All kernels include the upstream lockdown functionality.

All kernels enforce that only modules signed by us are loaded and that only binaries with a valid IMA signature created by us are executed.

*******************************************************************************
### Add any additional information you think we may need to validate this shim signing application.
*******************************************************************************

Serveral shims have been submitted by us and signed by Microsoft since 2014.

For the 2022 submission to shim-review we reworked our patches for shim and grub to use only a minimal patchset to shim and grub. The patches make
sure shim and grub only accepts grub / kernels that are signed by us and no other software or older version can be started.

This submission only updates to the newest version of shim and grub to fix upstream security vulnerabilities. No other changes are included compared 
to the 2022 submission.

