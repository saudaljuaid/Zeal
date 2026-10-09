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
kernel. The kernel embeds six checked, independently linked images (four roots
and two approved runtime templates) and the
compiled `build/default/manifest.bin`. Cell linking rejects mutable global
storage; the image checker rejects writable segments, invalid entries, and
out-of-bounds segments. The manifest compiler rejects invalid source records
before linking, and the supervisor validates the embedded bytes again before
booting any cell.

`make run` opens a serial console, exercises crash recovery, prints
`RESEARCH_PASS`, and continues running. Stop QEMU with Ctrl-C. Nothing is written
to a host disk. Use `make clean` to remove generated files.

`make interactive` selects scenario 26, builds `build/interactive/zeal.img`, and
opens the plain `zeal>` command console through real COM1 terminal input. It
runs until host termination; `make test-console` separately checks finite real
input acceptance twice and three additional writable profiles. See [console contracts](console.md).

Each service and the probe can also boot alone with the same manifest format,
supervisor, and ABI:

```sh
make BUILD=build/block SOLO=0 run
make BUILD=build/filesystem SOLO=1 run
make BUILD=build/client SOLO=2 run
make BUILD=build/probe SOLO=3 SCENARIO=7 run
make BUILD=build/waits SCENARIO=19 run
make BUILD=build/storage SCENARIO=20 TEST=1 run
make BUILD=build/idle-waits SOLO=3 SCENARIO=19 run
make BUILD=build/hosting-tree SCENARIO=21 TEST=1 run
make BUILD=build/hosting-recovery SCENARIO=22 TEST=1 run
make BUILD=build/hosting-authority SCENARIO=23 TEST=1 run
```

A standalone filesystem or client waits for its absent dependencies. The wait
scenario verifies blocking receive, later message delivery, timeout, and sleep.
Scenario 20 runs writable file round trips and stale-handle recovery across
separate block and filesystem restarts, then exits QEMU when `TEST=1`; the
external oracle also verifies its structured storage evidence. The standalone
wait probe verifies timer wakeups while the supervisor idles. These are
independent cell boots inside the supervisor, rather than firmware images with
separate hardware kernels. The `SCENARIO` option selects a configuration. In the
original research cases, `TEST=1` exits QEMU after checking recovery. Console
acceptance (27) uses acknowledged host QMP shutdown after collecting command
exchanges. The research runner creates separate build
directories for each configuration. The QEMU debug-exit device reports status
1 on a successful test boot, so a direct `make ... TEST=1 run` can report that
nonzero status; `make test` checks it together with the trace oracle.

Hosting scenarios boot the original four roots and create their descendants
only through the checked ring-3 management calls. Scenarios 21–23 select
`cells/hosting.toml`; the default manifest grants no creation authority. The
storage services and root client remain in generation one in these scenarios.
The build runs `tools/footprint.py` after linking and enforces both the BIOS
loaded-byte window and a static supervisor address end below 4 MiB.

Override tools using `RUSTC`, `ZIG`, `QEMU`, and `PYTHON`. Additional emulator
options can be set with `QEMU_FLAGS`. `RESEARCH_REPEAT` changes repeated emulator
runs, defaulting to two. Sanitized C tests require GCC's ASan and UBSan runtimes.
