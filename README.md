This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your branch
- approval is ready when you have accepted tag

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Here's the template:

-------------------------------------------------------------------------------
What organization or people are asking to have this signed:
-------------------------------------------------------------------------------
ECOS Technology GmbH

https://www.ecos.de/en/

-------------------------------------------------------------------------------
What product or service is this for:
-------------------------------------------------------------------------------
ECOS Secure Boot Stick (SBS)

The ECOS Secure Boot Stick is a secure ThinClient on a USB stick.
It is approved by the german BSI for use in governmental organisations.

https://www.ecos.de/en/products/secure-boot-stick

-------------------------------------------------------------------------------
What's the justification that this really does need to be signed for the whole world to be able to boot it:
-------------------------------------------------------------------------------
The SBS is used with a variety of customer devices.
Enrolling custom secure boot keys on each customer devices is infeasible.
Moreover, the SBS is designed to be used with customer devices without additional setup.
We need our own publicly signed shim as we custom-build our kernels for quicker firmware updates and therefore cannot use the shim of a distribution like Fedora.

-------------------------------------------------------------------------------
Who is the primary contact for security updates, etc.
-------------------------------------------------------------------------------
- Name: Simon Becker
- Position: Security Officer
- Email address: simon.becker@ecos.de
- PGP key fingerprint: `84C7B4B4AA363A483332CDC76E4AD9BA7C19AD86`

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

The public key is supplied via the repository (https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220217/pgp/simon.becker.asc) and was pushed to https://keyserver.ubuntu.com.

-------------------------------------------------------------------------------
Who is the secondary contact for security updates, etc.
-------------------------------------------------------------------------------
- Name: Gerald Richter
- Position: CTO
- Email address: gerald.richter@ecos.de
- PGP key fingerprint: `2637463F3110510EE2BA62C9375DEFC0CF8C6A6C`

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

The public key is supplied via the repository (https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220217/pgp/gerald.richter.asc) and was pushed to https://keyserver.ubuntu.com.

-------------------------------------------------------------------------------
Please create your shim binaries starting with the 15.5 shim release tar file:
https://github.com/rhboot/shim/releases/download/15.5/shim-15.5.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.5 and contains
the appropriate gnu-efi source.
-------------------------------------------------------------------------------
Yes.

-------------------------------------------------------------------------------
URL for a repo that contains the exact code which was built to get this binary:
-------------------------------------------------------------------------------
https://github.com/ecos-platypus/shim-review

-------------------------------------------------------------------------------
What patches are being applied and why:
-------------------------------------------------------------------------------

SHIM:

- `100_disable_allowlist.patch`: Our shim should only load PEs signed with the EV certificate embedded in the shim. The `check_allowlist` method was disabled (= it always returns `EFI_NOT_FOUND` and sets the verification method to `VERIFIED_BY_NOTHING`) to prevent loading of PEs trusted via `db` or `MokList`.
- `101_load_default_second_stage.patch`: We always want to use the default loader (set via `DEFAULT_LOADER` during the build) as second stage. We disable the code for dynamic second stage loader detection as it is not required and may cause issues with removable media.

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

-------------------------------------------------------------------------------
If bootloader, shim loading is, GRUB2: is CVE-2020-14372, CVE-2020-25632,
 CVE-2020-25647, CVE-2020-27749, CVE-2020-27779, CVE-2021-20225, CVE-2021-20233,
 CVE-2020-10713, CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, CVE-2020-14311,
 CVE-2020-15705, and if you are shipping the shim_lock module CVE-2021-3418
-------------------------------------------------------------------------------
Yes, all the CVEs are fixed in GRUB 2.06.

-------------------------------------------------------------------------------
What exact implementation of Secureboot in GRUB2 ( if this is your bootloader ) you have ?
* Upstream GRUB2 shim_lock verifier or * Downstream RHEL/Fedora/Debian/Canonical like implementation ?
-------------------------------------------------------------------------------
We use the upstream GRUB2 `shim_lock` verifier.

-------------------------------------------------------------------------------
If bootloader, shim loading is, GRUB2, and previous shims were trusting affected
by CVE-2020-14372, CVE-2020-25632, CVE-2020-25647, CVE-2020-27749,
  CVE-2020-27779, CVE-2021-20225, CVE-2021-20233, CVE-2020-10713,
  CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, CVE-2020-14311, CVE-2020-15705,
  and if you were shipping the shim_lock module CVE-2021-3418
  ( July 2020 grub2 CVE list + March 2021 grub2 CVE list )
  grub2:
* were old shims hashes provided to Microsoft for verification
  and to be added to future DBX update ?
* Does your new chain of trust disallow booting old, affected by CVE-2020-14372,
  CVE-2020-25632, CVE-2020-25647, CVE-2020-27749,
  CVE-2020-27779, CVE-2021-20225, CVE-2021-20233, CVE-2020-10713,
  CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, CVE-2020-14311, CVE-2020-15705,
  and if you were shipping the shim_lock module CVE-2021-3418
  ( July 2020 grub2 CVE list + March 2021 grub2 CVE list )
  grub2 builds ?
-------------------------------------------------------------------------------
1. No
2. Yes, we use a new EV certificate, old GRUBs cannot be booted by the new shim.

-------------------------------------------------------------------------------
If your boot chain of trust includes linux kernel, is
"efi: Restrict efivar_ssdt_load when the kernel is locked down"
upstream commit 1957a85b0032a81e6482ca4aab883643b8dae06e applied ?
Is "ACPI: configfs: Disallow loading ACPI tables when locked down"
upstream commit 75b0cea7bf307f362057cc778efe89af4c615354 applied ?
-------------------------------------------------------------------------------
Yes, they are included in all used kernels.

-------------------------------------------------------------------------------
If you use vendor_db functionality of providing multiple certificates and/or
hashes please briefly describe your certificate setup. If there are allow-listed hashes
please provide exact binaries for which hashes are created via file sharing service,
available in public with anonymous access for verification
-------------------------------------------------------------------------------
The new `vendor_db` functionality is not used.

-------------------------------------------------------------------------------
If you are re-using a previously used (CA) certificate, you will need
to add the hashes of the previous GRUB2 binaries to vendor_dbx in shim
in order to prevent GRUB2 from being able to chainload those older GRUB2
binaries. If you are changing to a new (CA) certificate, this does not
apply. Please describe your strategy.
-------------------------------------------------------------------------------
We use a new EV certificate.

-------------------------------------------------------------------------------
What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as close as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
-------------------------------------------------------------------------------
We use the Dockerfile that is part of our shim-review repository for the build.
The installed program versions are listed in the shim build log (they are printed to stdout via `dpkg -l`).

We want to prevent third parties from launching their `MokManager` and `fallback` binaries via our shim and therefore set `ENABLE_SHIM_CERT=1` for the build.
With this setting, dynamic keys are generated during the build and used to sign the `MokManager` and `fallback` binaries. The public portion of the dynamic keys are compiled into the shim so that it only loads these signed binaries as `MokManager` and `fallback`.
As these keys differ for each build, the shim binary is not completely reproducible.
However, the diff is small and only contains the embedded dynamic certificates.

-------------------------------------------------------------------------------
Which files in this repo are the logs for your build?   This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
-------------------------------------------------------------------------------
The build is executed via `docker build --no-cache --pull -t shim-ecos:15.5 . 2>&1 | tee build.log` in the repository root.
The flags `--no-cache` and `--pull` ensure that `build.log` contains all steps of the build process.
The `build.log` file in root of the repository is the output of our shim build.

-------------------------------------------------------------------------------
Add any additional information you think we may need to validate this shim
-------------------------------------------------------------------------------
