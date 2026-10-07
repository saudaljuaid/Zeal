<p align="center">
  <img src="assets/zeal.png" width="176" alt="Zeal">
</p>

# Zeal

Zeal is an operating system under development with native cell composition:
isolated executable systems, explicit authority, finite resource domains and
observable lifecycles. Drivers, filesystems and applications are sealed cells
that boot, fail and restart independently.

Zeal runs isolated x86-64 cells configured by a versioned boot manifest. Each
cell has private budgeted memory, a lifecycle, and revocable IPC capabilities
with operation rights. Cells can sleep and receive messages with finite tick
deadlines. A fault cold-boots that cell while healthy cells keep running.
Its isolated RAM block and flat filesystem services support bounded writable
files and generation-safe handles.

An explicitly authorized ring-3 controller can create approved supervisor and
worker cells. A supervisor can create workers one level below itself, giving a
bounded root → supervisor → worker hierarchy under one privileged supervisor
and global scheduler. Delegated page/slot allowances, typed lifecycle controls,
atomic creation, cold restart, and subtree cleanup govern these descendants.

A bounded isolated work-contract broker offers actual allocated workers, begins
work only after authenticated acceptance, independently checks scalar results,
and returns worker resources before publishing terminal receipts. Status queries,
checked cancellation, one fresh-authority retry and explicit record reap expose
the relationship between purpose, permission, backing, execution and outcome.
This slice uses two records and one approved pure work profile.

## Build and run

Requires an x86-64 Linux host, GCC, binutils, Make, Python 3.12+, Rust 1.90.0,
Zig 0.15.2, and QEMU.

```sh
make
make run
make test
```

See [building](docs/building.md), [architecture](docs/architecture.md),
[storage contracts](docs/storage.md), [wait contracts](docs/waits.md), and
[hosting contracts](docs/hosting-policy.md), [management ABI](docs/hosting-abi.md),
[native model](docs/zeal-model.md), [work contracts](docs/work-contracts.md),
and [test coverage](docs/testing.md).

## Status

Storage is volatile: four files including read-only `/hello`, 128 bytes per
file, eight open handles, and eight-byte transfer chunks. Hosting has eight
runtime slots: four permanently reserved roots and four descendant slots, at
most two child levels, and 128 private writable pages. Only the approved
supervisor/worker templates support creation. Arbitrary executable loading,
general recursive hosting, hardware NVMe, DMA isolation, persistent storage,
and SMP remain future work.

## License

Apache-2.0. Copyright 2026 Saud Aljuaid.
