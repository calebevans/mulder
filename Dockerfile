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
    && /tmp/dotnet-install.sh --channel 8.0 --runtime dotnet \
        --install-dir /opt/dotnet \
    && rm /tmp/dotnet-install.sh

RUN mkdir -p /opt/zimmermantools && cd /opt/zimmermantools \
    && for tool in AmcacheParser AppCompatCacheParser EvtxECmd JLECmd LECmd MFTECmd PECmd RBCmd RECmd SBECmd SrumECmd; do \
        wget -q "https://download.ericzimmermanstools.com/${tool}.zip" \
            -O "/tmp/${tool}.zip" \
        && unzip -qo "/tmp/${tool}.zip" -d /opt/zimmermantools \
        && rm "/tmp/${tool}.zip"; \
    done

# Volatility 3 symbol tables (data-only; pin to build platform to avoid QEMU)
FROM --platform=$BUILDPLATFORM ubuntu:22.04 AS symbols-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/vol-symbols \
    && wget -q https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip \
        -O /opt/vol-symbols/windows.zip \
    && wget -q https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip \
        -O /opt/vol-symbols/linux.zip

# YARA rule libraries (data-only; pin to build platform to avoid QEMU)
FROM --platform=$BUILDPLATFORM ubuntu:22.04 AS yara-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/Neo23x0/signature-base.git \
        /opt/signature-base

RUN git clone --depth 1 https://github.com/Yara-Rules/rules.git \
        /opt/yara-rules

# Hayabusa: Sigma rule engine for Windows EVTX logs
FROM ubuntu:22.04 AS hayabusa-fetch

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ARG HAYABUSA_VERSION=3.8.1
RUN case "${TARGETARCH}" in \
        arm64) HAYABUSA_VARIANT="aarch64-gnu" ;; \
        *)     HAYABUSA_VARIANT="x64-musl" ;; \
    esac \
    && curl -fsSL "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-${HAYABUSA_VARIANT}.zip" \
        -o /tmp/hayabusa.zip \
    && mkdir -p /opt/hayabusa \
    && unzip /tmp/hayabusa.zip -d /opt/hayabusa \
    && chmod +x /opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-${HAYABUSA_VARIANT} \
    && ln -s /opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-${HAYABUSA_VARIANT} /opt/hayabusa/hayabusa \
    && rm /tmp/hayabusa.zip

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
FROM --platform=$BUILDPLATFORM ubuntu:22.04 AS attack-fetch

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

# Runtime image
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DISABLE_AUTOUPDATE=1 \
    DOTNET_ROOT=/usr/local/share/dotnet \
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
    && npm install -g @anthropic-ai/claude-code \
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
COPY --from=yara-fetch /opt/yara-rules /opt/yara-rules
COPY --from=yara-fetch /opt/signature-base /opt/signature-base
COPY --from=attack-fetch /opt/attack/enterprise-attack.json /opt/attack/enterprise-attack.json
COPY --from=attack-fetch /opt/attack/ics-attack.json /opt/attack/ics-attack.json
COPY --from=hayabusa-fetch /opt/hayabusa /opt/hayabusa
COPY --from=radare2-fetch /tmp/radare2.deb /tmp/radare2.deb
RUN dpkg -i /tmp/radare2.deb || apt-get install -yf --no-install-recommends \
    && rm /tmp/radare2.deb
ENV PATH="/opt/hayabusa:${PATH}"
RUN ldconfig || true

# Install Python forensic packages that require C compilation, then purge build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make pkg-config python3.12-dev \
        zlib1g-dev libbz2-dev libssl-dev libsqlcipher-dev \
    && uv pip install --system --no-cache volatility3 plaso mvt pysqlcipher3 pyhindsight \
    && apt-get purge -y \
        gcc g++ make pkg-config python3.12-dev \
        zlib1g-dev libbz2-dev libssl-dev libsqlcipher-dev \
    && apt-get autoremove -y \
    && apt-get install -y --no-install-recommends libsqlcipher0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -c "import pyewf; print('libewf-python', pyewf.get_version())"

RUN useradd -m -s /bin/bash mulder

COPY . /app
RUN uv pip install --system --no-cache -e /app

RUN mkdir -p /mulder-investigation/.claude/commands /mulder-investigation/.claude/skills \
    && cp /app/.mcp.json /mulder-investigation/.mcp.json \
    && cp /app/.claude/settings.json /mulder-investigation/.claude/settings.json \
    && cp /app/.claude/skills/investigate.md /mulder-investigation/.claude/skills/investigate.md \
    && cp /app/.claude/commands/investigate.md /mulder-investigation/.claude/commands/investigate.md \
    && cd /mulder-investigation && git init && git config user.email "mulder@local" && git config user.name "mulder" && git add -A && git commit -m "init"

RUN chown -R mulder:mulder /home/mulder /mulder-investigation

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# NOTE: disk image mount operations (mount, ewfmount, guestmount) require
# --cap-add SYS_ADMIN when running this container.

WORKDIR /mulder-investigation
ENTRYPOINT ["entrypoint.sh"]
CMD ["claude"]
