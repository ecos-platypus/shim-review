Confirm the following are included in your repo, checking each box:

 - [x] link to your code branch cloned from rhboot/shim-review in the form user/repo@tag
   - https://github.com/ecos-platypus/shim-review/tree/ECOS_Technology_GmbH-shim-x64-20220224
 - [x] completed README.md file with the necessary information
   - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220224/README.md
 - [x] shim.efi to be signed
   - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220224/shimx64.efi
 - [x] public portion of your certificate(s) embedded in shim (the file passed to VENDOR_CERT_FILE)
   - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220224/ECOS_Tech_Code_signing_Certificate_Globalsign_2022.cer
 - [x] binaries, for which hashes are added to vendor_db ( if you use vendor_db and have hashes allow-listed )
   - `vendor_db` is not used
 - [x] any extra patches to shim via your own git tree or as files
   - https://github.com/ecos-platypus/shim-review/tree/ECOS_Technology_GmbH-shim-x64-20220224/patches-shim
 - [x] any extra patches to grub via your own git tree or as files
   - https://github.com/ecos-platypus/shim-review/tree/ECOS_Technology_GmbH-shim-x64-20220224/patches-grub
 - [x] build logs
    - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220224/build.log
 - [x] a Dockerfile to reproduce the build of the provided shim EFI binaries
   - https://github.com/ecos-platypus/shim-review/blob/ECOS_Technology_GmbH-shim-x64-20220224/Dockerfile

-------------------------------------------------------------------------------
### What is the link to your tag in a repo cloned from rhboot/shim-review?
-------------------------------------------------------------------------------
https://github.com/ecos-platypus/shim-review/tree/ECOS_Technology_GmbH-shim-x64-20220224

-------------------------------------------------------------------------------
### What is the SHA256 hash of your final SHIM binary?
-------------------------------------------------------------------------------
`48c7823dc532c349d602adc76f85715c125f59ebb1246a13528b66ebcd625c65`
