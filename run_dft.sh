#!/bin/bash

# intel-pin root location
PIN_ROOT_PATH=/home/chuqiz/local/pin/pin-3.20-98437-gf02b61307-gcc-linux
TOOLS_ROOT_PATH=$PIN_ROOT_PATH/source/tools
LIBDFT_EXEC=libdft.so #libdft.so  # track.so

# tools
PIN=/home/chuqiz/local/pin/pin-3.20-98437-gf02b61307-gcc-linux/pin
LIBDFT_DIR=$(dirname $(readlink -f "$0"))

EXEC=$@

if [ -z $PIN_ROOT ];then
    echo "Intel-Pin not set."
    echo "Setting PIN_ROOT: $PIN_ROOT_PATH"
    # export PIN_ROOT="$PIN_ROOT_PATH"
    export PIN_ROOT=/home/chuqiz/local/pin/pin-3.20-98437-gf02b61307-gcc-linux
fi

if [ -z $TOOLS_ROOT ];then
    echo "Intel-Pin tools root not set."
    echo "Setting TOOLS_ROOT: $TOOLS_ROOT_PATH"
    export TOOLS_ROOT="$TOOLS_ROOT_PATH"
fi

echo "Executing with libdft -- $EXEC"
$PIN -follow_execv -t $LIBDFT_DIR/tools/obj-intel64/$LIBDFT_EXEC -- $@
#$PIN -follow_execv -pid 401724 -t $LIBDFT_DIR/tools/obj-intel64/$LIBDFT_EXEC
