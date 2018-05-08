#!/bin/bash

# ./ida_start.sh <ida_engine_path> <binary_path> <idb_store_path>

# init idb_store_path
idb_store_dir=$(dirname $3)
if [ ! -d $idb_store_dir ];then
	mkdir -p $idb_store_dir
fi

# get arch and endian
file_type=$(file "$2")
arch=$(echo "$file_type" | cut -d ',' -f 2 | cut -d ' ' -f 2)
endian=$(echo "$file_type" | cut -d ',' -f 1 | cut -d ' ' -f 4)

# reference: www.hex-rays.com/products/ida/support/idadoc/618.shtml
if [ "$arch" == "ARM" ]; then
    if [ "$endian" == "LSB" ]; then
        ARCH=arm
    elif [ "$endian" == "MSB" ]; then
        ARCH=armb
    fi
elif [ "$arch" == "MIPS" ]; then
    if [ "$endian" == "LSB" ]; then
        ARCH=mipsl
    elif [ "$endian" = "MSB" ]; then
        ARCH=mipsb
    fi
elif [ "$arch" == "PPC" ]; then
    if [ "$endian" == "LSB" ]; then
        ARCH="ppcl"
    elif [ "$endian" == "MSB" ]; then
        ARCH="ppc"
    fi
else
    echo "Architecture not support!"
    exit
fi

TVHEADLESS=1 "$1" -B -p"$ARCH" -o"$3" "$2" > /dev/null
