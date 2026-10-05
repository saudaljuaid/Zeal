<p align="center">
  <img src="assets/zeal.png" width="176" alt="Zeal">
</p>

# Zeal

Zeal is a research operating system exploring a fractal architecture: drivers,
filesystems, and applications are sealed systems that boot, fail, and restart
independently.

The first milestone runs isolated x86-64 cells with a small C kernel, assembly
boot and trap handling, Rust lifecycle policy, and Zig services. Each cell has
private memory and generation-tagged IPC endpoints. A driver fault revokes its
endpoints and cold-boots that cell while healthy cells continue running.

## Build and run

Requires an x86-64 Linux host, GCC, binutils, Make, Python 3.12+, Rust 1.90.0,
Zig 0.15.2, and QEMU.

```sh
make
make run
make test
```

See [building](docs/building.md), [architecture](docs/architecture.md), and
[research tests](docs/testing.md).

## Status

Early research software. The current storage service is RAM-backed and the
filesystem exposes one immutable file. Hardware NVMe, DMA isolation, persistent
storage, SMP, and recursively hosted child systems are future milestones.

## License

Apache-2.0. Copyright 2026 Saud Aljuaid.
