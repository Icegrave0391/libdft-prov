#!/bin/bash

# intel-pin root location
PIN_ROOT_PATH=/home/chuqiz/local/pin/pin-3.20-98437-gf02b61307-gcc-linux

# tools
PIN=/home/chuqiz/local/pin/pin-3.20-98437-gf02b61307-gcc-linux/pin
LIBDFT_DIR=$(dirname $(readlink -f "$0"))

EXEC=$@

if [ -z $PIN_ROOT ];then
    echo "Intel-Pin not set."
    echo "Setting PIN_ROOT: $PIN_ROOT_PATH"
    export PIN_ROOT=/home/chuqiz/local/pin/pin-3.20-98437-gf02b61307-gcc-linux
fi

echo "Executing with libdft:"
echo $EXEC
$PIN -t $LIBDFT_DIR/tools/obj-intel64/track.so -- $@
