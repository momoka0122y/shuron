#!/bin/bash

# Check if an argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <base64_string>"
    exit 1
fi

# Decode from base64 and then do a hexdump
echo "$1" | base64 -d | hexdump -C

