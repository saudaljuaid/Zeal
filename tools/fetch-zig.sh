#!/bin/sh
set -eu
directory=build/tools
archive="$directory/zig-0.15.2.tar.xz"
mkdir -p "$directory"
curl -fL --retry 3 https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz -o "$archive"
printf '%s  %s\n' 02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 "$archive" | sha256sum --check --status
tar -xJf "$archive" -C "$directory"
"$directory/zig-x86_64-linux-0.15.2/zig" version
