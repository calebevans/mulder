# libewf: build from source (GIFT PPA lacks arm64 packages)
FROM ubuntu:22.04 AS libewf-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        pkg-config \
        zlib1g-dev \
        libbz2-dev \
        libssl-dev \
        libfuse3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/libyal/libewf/releases/download/20240506/libewf-experimental-20240506.tar.gz \
        -o /tmp/libewf.tar.gz \
    && tar xzf /tmp/libewf.tar.gz -C /tmp \
    && cd /tmp/libewf-20240506 \
    && ./configure --prefix=/opt/libewf \
    && make -j"$(nproc)" \
    && make install

# bulk_extractor: build from source with libewf support
FROM ubuntu:22.04 AS bulk-builder

ENV DEBIAN_FRONTEND=noninteractive

COPY --from=libewf-builder /opt/libewf /opt/libewf

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
        python3 \
        pkg-config \
        autoconf \
        automake \
        flex \
        libtool \
        libssl-dev \
        libre2-dev \
        zlib1g-dev \
        libbz2-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PKG_CONFIG_PATH=/opt/libewf/lib/pkgconfig \
    CPPFLAGS="-I/opt/libewf/include" \
    LDFLAGS="-L/opt/libewf/lib" \
    LD_LIBRARY_PATH=/opt/libewf/lib

RUN git clone --recursive --depth 1 \
        https://github.com/simsong/bulk_extractor.git /tmp/bulk_extractor \
    && cd /tmp/bulk_extractor \
    && ./bootstrap.sh \
    && ./configure --prefix=/opt/bulk_extractor --with-libewf=/opt/libewf \
    && make -j"$(nproc)" \
    && make install

# Eric Zimmerman tools: .NET runtime + forensic parsers
FROM ubuntu:22.04 AS eztools-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet \
        --install-dir /opt/dotnet \
    && rm /tmp/dotnet-install.sh

RUN mkdir -p /opt/zimmermantools && cd /opt/zimmermantools \
    && for tool in AmcacheParser AppCompatCacheParser EvtxECmd JLECmd LECmd MFTECmd PECmd RBCmd RECmd SBECmd SrumECmd; do \
        wget -q "https://download.ericzimmermanstools.com/net9/${tool}.zip" \
            -O "/tmp/${tool}.zip" \
        && unzip -qo "/tmp/${tool}.zip" -d /opt/zimmermantools \
        && rm "/tmp/${tool}.zip"; \
    done

# Volatility 3 symbol tables (data-only; pin to build platform to avoid QEMU)
FROM ubuntu:22.04 AS symbols-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/vol-symbols \
    && wget -q https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip \
        -O /opt/vol-symbols/windows.zip \
    && wget -q https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip \
        -O /opt/vol-symbols/linux.zip

# YARA rule libraries (data-only; pin to build platform to avoid QEMU)
FROM ubuntu:22.04 AS yara-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/Neo23x0/signature-base.git \
        /opt/signature-base

# Hayabusa: Sigma rule engine for Windows EVTX logs.
# amd64: pre-built musl binary (statically linked, no GLIBC dependency).
# arm64: build from source because the pre-built aarch64-gnu binary requires
# GLIBC >= 2.38 while Ubuntu 22.04 ships GLIBC 2.35.
FROM ubuntu:22.04 AS hayabusa-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip git build-essential \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ARG HAYABUSA_VERSION=3.8.1
RUN mkdir -p /opt/hayabusa \
    && if [ "$TARGETARCH" != "arm64" ]; then \
        curl -fsSL "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl.zip" \
            -o /tmp/hayabusa.zip \
        && unzip /tmp/hayabusa.zip -d /opt/hayabusa \
        && chmod +x /opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl \
        && ln -s /opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl /opt/hayabusa/hayabusa \
        && rm /tmp/hayabusa.zip; \
    else \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --default-toolchain stable --profile minimal \
        && export PATH="/root/.cargo/bin:${PATH}" \
        && git clone --depth 1 --branch v${HAYABUSA_VERSION} \
            https://github.com/Yamato-Security/hayabusa.git /tmp/hayabusa-src \
        && cd /tmp/hayabusa-src \
        && cargo build --release \
        && cp target/release/hayabusa /opt/hayabusa/hayabusa \
        && cp -r config rules /opt/hayabusa/ \
        && rm -rf /tmp/hayabusa-src /root/.cargo /root/.rustup; \
    fi

# radare2: fetch release .deb from GitHub (not in Ubuntu 22.04 repos)
FROM ubuntu:22.04 AS radare2-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ARG RADARE2_VERSION=5.9.8
RUN ARCH="$(dpkg --print-architecture)" \
    && curl -fsSL "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_${ARCH}.deb" \
        -o /tmp/radare2.deb

# MITRE ATT&CK Enterprise + ICS STIX data (data-only; pin to build platform to avoid QEMU)
FROM ubuntu:22.04 AS attack-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/attack \
    && curl -fsSL https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
        -o /opt/attack/enterprise-attack.json \
    && curl -fsSL https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json \
        -o /opt/attack/ics-attack.json

# stegdetect: build from source
FROM ubuntu:22.04 AS stegdetect-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
        autoconf \
        automake \
        libtool \
        libjpeg-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/redNixon/stegdetect.git /tmp/stegdetect \
    && cd /tmp/stegdetect \
    && autoreconf -ivf \
    && CFLAGS="-O2 -fcommon" ./configure --prefix=/opt/stegdetect \
    && make -j"$(nproc)" \
    && mkdir -p /opt/stegdetect/bin /opt/stegdetect/share /opt/stegdetect/man/man1 \
    && make install

# CAPA: download pre-built binary (multi-arch)
FROM ubuntu:22.04 AS capa-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ARG CAPA_VERSION=9.4.0
RUN case "${TARGETARCH}" in \
        arm64) CAPA_ARCH="linux-arm64" ;; \
        *)     CAPA_ARCH="linux" ;; \
    esac \
    && curl -fsSL "https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-${CAPA_ARCH}.zip" \
        -o /tmp/capa.zip \
    && unzip /tmp/capa.zip -d /opt/capa \
    && chmod +x /opt/capa/capa \
    && rm /tmp/capa.zip

# FLOSS: download pre-built binary (amd64 only; arm64 uses pip in runtime)
FROM ubuntu:22.04 AS floss-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ARG FLOSS_VERSION=3.1.0
RUN mkdir -p /opt/floss \
    && if [ "$TARGETARCH" = "amd64" ]; then \
        curl -fsSL "https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-linux.zip" \
            -o /tmp/floss.zip \
        && unzip /tmp/floss.zip -d /opt/floss \
        && chmod +x /opt/floss/floss \
        && rm /tmp/floss.zip; \
    fi

# Chainsaw: download pre-built binary (multi-arch), Sigma rules, and mappings
FROM ubuntu:22.04 AS chainsaw-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ARG CHAINSAW_VERSION=2.16.0
RUN case "${TARGETARCH}" in \
        arm64) CHAINSAW_ARCH="aarch64-unknown-linux-gnu" ;; \
        *)     CHAINSAW_ARCH="x86_64-unknown-linux-gnu" ;; \
    esac \
    && curl -fsSL "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_${CHAINSAW_ARCH}.tar.gz" \
        -o /tmp/chainsaw.tar.gz \
    && mkdir -p /opt/chainsaw \
    && tar xzf /tmp/chainsaw.tar.gz -C /opt/chainsaw --strip-components=1 \
    && chmod +x /opt/chainsaw/chainsaw \
    && rm /tmp/chainsaw.tar.gz

RUN git clone --depth 1 --branch v${CHAINSAW_VERSION} \
        https://github.com/WithSecureLabs/chainsaw.git /tmp/chainsaw-repo \
    && cp -r /tmp/chainsaw-repo/mappings /opt/chainsaw/mappings \
    && cp -r /tmp/chainsaw-repo/rules /opt/chainsaw/rules \
    && rm -rf /tmp/chainsaw-repo

ARG SIGMA_VERSION=r2024-09-02
RUN curl -fsSL "https://github.com/SigmaHQ/sigma/archive/refs/tags/${SIGMA_VERSION}.tar.gz" \
        -o /tmp/sigma.tar.gz \
    && mkdir -p /opt/sigma-rules \
    && tar xzf /tmp/sigma.tar.gz -C /opt/sigma-rules --strip-components=1 \
    && rm /tmp/sigma.tar.gz

# Suricata: build from source for arm64 (amd64 uses PPA in runtime)
FROM ubuntu:22.04 AS suricata-builder

ENV DEBIAN_FRONTEND=noninteractive

ARG TARGETARCH
ARG SURICATA_VERSION=7.0.7
RUN mkdir -p /opt/suricata /etc/suricata \
    && if [ "$TARGETARCH" = "arm64" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            build-essential ca-certificates curl pkg-config \
            libpcre2-dev libpcap-dev libyaml-dev libjansson-dev \
            libcap-ng-dev libmagic-dev zlib1g-dev liblz4-dev \
            rustc cargo python3-yaml \
        && rm -rf /var/lib/apt/lists/* \
        && curl -fsSL "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz" \
            -o /tmp/suricata.tar.gz \
        && tar xzf /tmp/suricata.tar.gz -C /tmp \
        && cd /tmp/suricata-${SURICATA_VERSION} \
        && ./configure --prefix=/opt/suricata --sysconfdir=/etc \
            --localstatedir=/var --enable-non-root --disable-geoip \
        && make -j"$(nproc)" \
        && make install \
        && rm -rf /tmp/suricata*; \
    fi

# Runtime image
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DISABLE_AUTOUPDATE=1 \
    DOTNET_ROOT=/usr/local/share/dotnet \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true \
    PATH="/usr/local/share/dotnet:${PATH}"


COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common \
        gnupg \
        ca-certificates \
        curl \
        git \
        gosu \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        afflib-tools \
        sleuthkit \
        yara \
        libssl3 \
        libre2-9 \
        fuse3 \
        libfuse3-dev \
        regripper \
        clamav clamav-freshclam \
        hashdeep \
        foremost \
        libimage-exiftool-perl \
        binutils \
        libvshadow-utils \
        libbde-utils \
        libfvde-utils \
        tcpflow \
        tcpxtract \
        dislocker \
        dc3dd \
        libguestfs-tools \
        pasco \
        pst-utils \
        tshark \
        tcpdump \
        ssdeep \
        scalpel \
        binwalk \
        testdisk \
        chkrootkit \
        outguess \
        libheif-examples \
        p7zip-full \
        python3.12 \
        python3.12-dev \
        python3.12-venv \
        libsqlite3-dev \
        libffi-dev \
    && (freshclam --quiet || true) \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.12 1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bulk-builder /opt/bulk_extractor /usr/local
COPY --from=libewf-builder /opt/libewf /usr/local
COPY --from=eztools-fetch /opt/dotnet /usr/local/share/dotnet
COPY --from=eztools-fetch /opt/zimmermantools /opt/zimmermantools
COPY --from=symbols-fetch /opt/vol-symbols/windows.zip /home/mulder/.cache/volatility3/symbols/windows.zip
COPY --from=symbols-fetch /opt/vol-symbols/linux.zip /home/mulder/.cache/volatility3/symbols/linux.zip
COPY --from=stegdetect-builder /opt/stegdetect/bin/stegdetect /usr/local/bin/stegdetect
COPY --from=stegdetect-builder /opt/stegdetect/bin/stegbreak /usr/local/bin/stegbreak
COPY --from=yara-fetch /opt/signature-base /opt/signature-base
COPY --from=attack-fetch /opt/attack/enterprise-attack.json /opt/attack/enterprise-attack.json
COPY --from=attack-fetch /opt/attack/ics-attack.json /opt/attack/ics-attack.json
COPY --from=hayabusa-fetch /opt/hayabusa /opt/hayabusa
COPY --from=radare2-fetch /tmp/radare2.deb /tmp/radare2.deb
# Keep capa where the asset manifest says it lives, then link it onto PATH --
# same shape as chainsaw below. Copying only the binary to /usr/local/bin
# left /opt/capa absent, so `mulder setup --verify` called capa missing on
# an image where capa works fine.
COPY --from=capa-fetch /opt/capa/ /opt/capa/
RUN ln -sf /opt/capa/capa /usr/local/bin/capa
COPY --from=floss-fetch /opt/floss/ /opt/floss/
COPY --from=chainsaw-fetch /opt/chainsaw/ /opt/chainsaw/
RUN ln -sf /opt/chainsaw/chainsaw /usr/local/bin/chainsaw
COPY --from=chainsaw-fetch /opt/sigma-rules/ /opt/sigma-rules/
COPY --from=suricata-builder /opt/suricata/ /opt/suricata/
COPY --from=suricata-builder /etc/suricata/ /etc/suricata/

RUN dpkg -i /tmp/radare2.deb || apt-get install -yf --no-install-recommends \
    && rm /tmp/radare2.deb

ARG TARGETARCH

# FLOSS: symlink pre-built binary on amd64 (arm64 uses pip entry point)
RUN if [ -x /opt/floss/floss ]; then ln -sf /opt/floss/floss /usr/local/bin/floss; fi

# Suricata: PPA on amd64, link source build on arm64
# python3 now points to 3.12 (deadsnakes), but apt_pkg is compiled for
# the system 3.10, so invoke add-apt-repository via python3.10 explicitly.
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        /usr/bin/python3.10 /usr/bin/add-apt-repository -y ppa:oisf/suricata-stable \
        && apt-get update \
        && apt-get install -y --no-install-recommends suricata \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    elif [ -x /opt/suricata/bin/suricata ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends \
            libpcre3 libpcap0.8 libyaml-0-2 libjansson4 \
            libcap-ng0 libmagic1 liblz4-1 \
        && apt-get clean && rm -rf /var/lib/apt/lists/* \
        && ln -sf /opt/suricata/bin/suricata /usr/bin/suricata; \
    fi

# Download Emerging Threats Open ruleset for Suricata
RUN mkdir -p /etc/suricata/rules \
    && curl -fsSL "https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz" \
        -o /tmp/et-rules.tar.gz \
    && tar xzf /tmp/et-rules.tar.gz -C /etc/suricata/rules --strip-components=1 \
    && rm /tmp/et-rules.tar.gz

# Zeek: install from OBS repository (provides amd64 and arm64 packages).
# Mark as manual so later apt-get autoremove steps do not uninstall it.
RUN echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
        > /etc/apt/sources.list.d/zeek.list \
    && curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key" \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg \
    && apt-get update \
    && apt-get install -y --no-install-recommends zeek \
    && apt-mark manual zeek-core zeekctl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/zeek/bin:/opt/chainsaw:/opt/hayabusa:${PATH}"
RUN ldconfig || true

# Install Python forensic packages that require C compilation, then purge build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make pkg-config python3.12-dev \
        zlib1g-dev libbz2-dev libssl-dev libsqlcipher-dev \
    && uv pip install --system --no-cache \
        volatility3 plaso mvt pysqlcipher3 pyhindsight oletools \
    && if [ "$TARGETARCH" = "arm64" ]; then \
        uv pip install --system --no-cache flare-floss; \
    fi \
    && apt-get purge -y \
        gcc g++ make pkg-config python3.12-dev \
        zlib1g-dev libbz2-dev libssl-dev libsqlcipher-dev \
    && apt-get autoremove -y \
    && apt-get install -y --no-install-recommends libsqlcipher0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install pure Python forensic tool dependencies
RUN uv pip install --system --no-cache \
        stix2 evtx jsonpath-ng colorama tqdm aiohttp lark

# Clone forensic tool repositories
RUN git clone --depth 1 --branch 2.20.0 \
        https://github.com/wagga40/Zircolite.git /opt/zircolite \
    && chmod +x /opt/zircolite/zircolite.py \
    && git clone --depth 1 https://github.com/abrignoni/ALEAPP.git /opt/aleapp \
    && git clone --depth 1 https://github.com/abrignoni/iLEAPP.git /opt/ileapp \
    && git clone --depth 1 \
        https://github.com/DidierStevens/DidierStevensSuite.git \
        /opt/didier-stevens \
    && chmod +x /opt/didier-stevens/pdfid.py /opt/didier-stevens/pdf-parser.py

# Install ALEAPP and iLEAPP Python dependencies; strip version pins and
# filter non-PyPI entries to avoid conflicts between the two projects
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ python3.12-dev \
    && cat /opt/aleapp/requirements.txt /opt/ileapp/requirements.txt \
        | sed 's/[;].*//; s/==.*//; s/>=.*//; s/<=.*//; s/~=.*//' \
        | grep -v '^\s*#' | grep -v '^\s*$' | grep -v '/' | sort -u \
        | xargs uv pip install --system --no-cache \
    && apt-get purge -y gcc g++ python3.12-dev \
    && apt-get autoremove -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Linux Sigma rules for Zircolite
RUN mkdir -p /opt/zircolite/rules/linux \
    && cp -r /opt/sigma-rules/rules/linux/* /opt/zircolite/rules/linux/ 2>/dev/null || true

RUN python3 -c "import pyewf; print('libewf-python', pyewf.get_version())"

RUN useradd -m -s /bin/bash mulder

COPY . /app
RUN uv pip install --system --no-cache -e /app

# LiteLLM proxy in isolated venv (hard dependency conflicts with mulder's
# mcp>=2.0 and rich>=15.0; litellm pins older versions of both).
RUN python3 -m venv /opt/litellm \
    && /opt/litellm/bin/pip install --no-cache-dir 'litellm[proxy]' pyyaml \
    && ln -s /opt/litellm/bin/litellm /usr/local/bin/litellm

RUN mkdir -p /mulder-investigation \
    && cp /app/.mcp.json /mulder-investigation/.mcp.json \
    && cd /mulder-investigation && git init && git config user.email "mulder@local" && git config user.name "mulder" && git add -A && git commit -m "init"

RUN chown -R mulder:mulder /home/mulder /mulder-investigation

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# NOTE: disk image mount operations (mount, ewfmount, guestmount) require
# --privileged or --cap-add SYS_ADMIN when running this container.
# The container runs as non-root user 'mulder'; the entrypoint handles
# credential setup and permission fixups before dropping to that user.

# --cwd defaults to ~/.mulder/workspace on a native install; pin it back to the
# directory this image already creates, populates and git-inits above so
# container behaviour is unchanged.
ENV MULDER_CWD=/mulder-investigation

# The image is already provisioned, so pin the resolver to /opt outright. It is
# exclusive: without it a bind-mounted host $HOME carrying
# ~/.local/share/mulder/assets would silently supplement (and could shadow) the
# image's curated, version-matched tree. `mulder setup` inside the container
# consequently exits 1 -- /opt is root:root 0755 and the process runs as
# `mulder` -- which is correct; there is nothing for it to do here.
ENV MULDER_ASSET_ROOT=/opt

WORKDIR /mulder-investigation
ENTRYPOINT ["entrypoint.sh"]
CMD ["mulder", "investigate"]
