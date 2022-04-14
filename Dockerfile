FROM python:3.9

RUN apt-get update
RUN apt-get install -y ninja-build parallel
RUN pip install meson

WORKDIR /tmp

# install rizin from source code
RUN wget https://github.com/rizinorg/rizin/releases/download/v0.3.4/rizin-src-v0.3.4.tar.xz
RUN tar -xvf rizin-src-v0.3.4.tar.xz

WORKDIR /tmp/rizin-v0.3.4
RUN meson build
RUN ninja -C build install

COPY rz_libfix.sh /tmp/rizin-v0.3.4/
RUN chmod +x rz_libfix.sh
RUN ./rz_libfix.sh

# install uefi_r2
RUN useradd -u 1001 -m uefi_r2
USER uefi_r2

COPY uefi_r2_analyzer.py /home/uefi_r2/app/
COPY requirements.txt /home/uefi_r2/app/
COPY uefi_r2 /home/uefi_r2/app/uefi_r2

WORKDIR /home/uefi_r2/app/

RUN pip install --user -r requirements.txt

ENTRYPOINT ["python3", "uefi_r2_analyzer.py"]
