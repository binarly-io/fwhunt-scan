FROM python:3.10

LABEL org.opencontainers.image.source https://github.com/binarly-io/fwhunt-scan

ARG rz_version=v0.6.0

# add library paths
ENV LD_LIBRARY_PATH=/tmp/rizin-$rz_version/build/librz/core

RUN apt-get update
RUN apt-get install -y ninja-build parallel
RUN pip install meson==1.0.0

# add fwhunt_scan unprivileged user
RUN useradd -u 1001 -m fwhunt_scan

# install rizin from source code
WORKDIR /tmp
RUN wget https://github.com/rizinorg/rizin/releases/download/$rz_version/rizin-src-$rz_version.tar.xz
RUN tar -xvf rizin-src-$rz_version.tar.xz

WORKDIR /tmp/rizin-$rz_version
RUN meson build
RUN ninja -C build install

# install fwhunt_scan
COPY fwhunt_scan_analyzer.py /home/fwhunt_scan/app/
COPY requirements.txt /home/fwhunt_scan/app/
COPY fwhunt_scan /home/fwhunt_scan/app/fwhunt_scan

WORKDIR /home/fwhunt_scan/app/
RUN pip install -r requirements.txt

USER fwhunt_scan

ENTRYPOINT ["python3", "fwhunt_scan_analyzer.py"]
