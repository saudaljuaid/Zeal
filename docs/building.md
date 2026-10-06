# Building Zeal

The supported development host is x86-64 Linux. The boot target is a single
x86-64 CPU with long mode, PAE, and NX, BIOS extended disk reads, a legacy PIC,
PIT, and COM1. The automated target is QEMU with TCG; real hardware has not been
validated. The kernel uses less than 4 MiB of physical memory; test machines have
32–128 MiB.

Install GCC, GNU binutils, Make, Python 3.12+, curl, xz, and QEMU. On Ubuntu:

```sh
sudo apt-get install build-essential binutils python3 curl xz-utils qemu-system-x86
rustup toolchain install 1.90.0 --profile minimal --target x86_64-unknown-none
sh tools/fetch-zig.sh
export PATH="$PWD/build/tools/zig-x86_64-linux-0.15.2:$PATH"
make -j4
make run
```

Install Rust through its official rustup distribution before the rustup command.
`rust-toolchain.toml` pins the toolchain. `fetch-zig.sh` fetches Zig's official
0.15.2 archive and verifies the published SHA-256 before extraction. Builds do
not download dependencies. The Rust policy has no external crates.

`build/default/zeal.img` is a 16 MiB raw BIOS disk image. The boot sector loads
the flat kernel, checks CPU requirements, enables long mode, and calls the
kernel. The kernel embeds four independently linked cell images and the
compiled `build/default/manifest.bin`. Cell linking rejects mutable global
storage; the image checker rejects writable segments, invalid entries, and
out-of-bounds segments. The manifest compiler rejects invalid source records
before linking, and the supervisor validates the embedded bytes again before
booting any cell.

`make run` opens a serial console, exercises crash recovery, prints
`RESEARCH_PASS`, and continues running. Stop QEMU with Ctrl-C. Nothing is written
to a host disk. Use `make clean` to remove generated files.

Each service and the probe can also boot alone with the same manifest format,
supervisor, and ABI:

```sh
make BUILD=build/block SOLO=0 run
make BUILD=build/filesystem SOLO=1 run
make BUILD=build/client SOLO=2 run
make BUILD=build/probe SOLO=3 SCENARIO=7 run
```

A standalone filesystem or client waits for its absent dependencies. These are
independent cell boots inside the supervisor, rather than firmware images with
separate hardware kernels. The `SCENARIO` option selects a fault probe; `TEST=1`
exits QEMU after checking recovery. The research runner creates separate build
directories for each configuration.

Override tools using `RUSTC`, `ZIG`, `QEMU`, and `PYTHON`. Additional emulator
options can be set with `QEMU_FLAGS`. `RESEARCH_REPEAT` changes repeated emulator
runs, defaulting to two. Sanitized C tests require GCC's ASan and UBSan runtimes.
