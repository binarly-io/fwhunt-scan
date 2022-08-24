#!/usr/bin/env bash

RZ_VERSION="0.4.0"

function install_libs {
    for f in $(find /tmp/rizin-v$RZ_VERSION/build/librz -name "*librz_*.so.$RZ_VERSION"); do
        ln -s $f /usr/lib;
    done
}

install_libs
echo "rz_libfix: DONE"
