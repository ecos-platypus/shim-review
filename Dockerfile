FROM debian:bullseye

RUN apt-get update -y && apt-get install -y --no-install-recommends build-essential \
        # for `hexdump`
        bsdmainutils \
        # for `git clone`
        ca-certificates git \
        # for `make` with `sbat.ecos.csv`
        dos2unix \
        # for download and extraction of the shim release
        wget tar \
        # reduce image size by cleaning up apt list cache
        && rm -rf /var/lib/apt/lists/*

# Print installed packages and versions
RUN dpkg -l

RUN wget https://github.com/rhboot/shim/releases/download/15.6/shim-15.6.tar.bz2
RUN tar -xf shim-15.6.tar.bz2
RUN mv shim-15.6 /shim
WORKDIR /shim

# Development: Use local copy of shim-review repository
#COPY .git /tmp/.git
#RUN git clone /tmp/.git /shim-review

# Production: Use GitHub fork of shim-review repository (+ dummy step for better build log comparison)
RUN echo 0
RUN git clone -b ECOS_Technology_GmbH-shim-x64-20220608 https://github.com/ecos-platypus/shim-review.git /shim-review

RUN cp /shim-review/ECOS_Tech_Code_signing_Certificate_Globalsign_2022.cer /shim/
RUN cp /shim-review/sbat.ecos.csv /shim/data/

RUN patch < /shim-review/patches-shim/100_disable_allowlist.patch
RUN patch < /shim-review/patches-shim/101_load_default_second_stage.patch
RUN patch < /shim-review/patches-shim/102_force_secure_mode.patch

ENV DEFAULT_LOADER=\\\\ecosx64.efi
ENV VENDOR_CERT_FILE=ECOS_Tech_Code_signing_Certificate_Globalsign_2022.cer

RUN make -j

WORKDIR /
RUN hexdump -Cv /shim/shim*.efi > build
RUN hexdump -Cv /shim-review/$(basename /shim/shim*.efi) > orig
RUN diff -u orig build
RUN sha256sum /shim/shim*.efi /shim-review/$(basename /shim/shim*.efi)
