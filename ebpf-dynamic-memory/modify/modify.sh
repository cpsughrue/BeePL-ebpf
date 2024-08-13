#!/usr/bin/env bash

readonly HEADER_FILE="dynamic_memory.h"

modify() {
    local file=$1
    sed -i 's/\([ ()=]\)malloc(/\1static_malloc(/g' "$file"
    sed -i 's/\([ ;]\)free(/\1static_free(/g' "$file"
}

# check if the first argument is a file or directory
if [ -f "$1" ]; then
    echo "processing file: $1"
    sed -i "1s/^/#include \"$HEADER_FILE\"\n/" "$1"
    modify "$1"
elif [ -d "$1" ]; then
    echo "processing directory: $1"
    for file in $(find "$1" -type f); do
        echo "processing file: $file"
        modify "$file"
    done
else
    echo "usage: ./modify.sh /path/to/c/source/file"
    exit 1
fi

echo "replacement completed"
