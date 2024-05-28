Confirm the following are included in your repo, checking each box:

 - [x] completed README.md file with the necessary information
 - [x] shim.efi to be signed
 - [x] public portion of your certificate(s) embedded in shim (the file passed to VENDOR_CERT_FILE)
 - [ ] binaries, for which hashes are added to vendor_db ( if you use vendor_db and have hashes allow-listed )
 - [x] any extra patches to shim via your own git tree or as files
 - [x] any extra patches to grub via your own git tree or as files
 - [x] build logs
 - [x] a Dockerfile to reproduce the build of the provided shim EFI binaries

*******************************************************************************
### What is the link to your tag in a repo cloned from rhboot/shim-review?
*******************************************************************************
https://github.com/ecos-platypus/shim-review/tree/shim-review-2024

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
`cfb155df60992a5cee2dff99d75089ee03a578d2d01e7d30b7cf5fc1c67da3b0`

*******************************************************************************
### What is the link to your previous shim review request (if any, otherwise N/A)?
*******************************************************************************
https://github.com/ecos-platypus/shim-review/tree/shim-review-2022

*******************************************************************************
### If no security contacts have changed since verification, what is the link to your request, where they've been verified (if any, otherwise N/A)?
*******************************************************************************
gerald.richter@ecos.de was already verified in https://github.com/ecos-platypus/shim-review/tree/shim-review-2022

https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220628/pgp/gerald.richter.asc