CC := gcc
LD := ld
AS := as
OBJCOPY := objcopy
RUSTC ?= rustc
ZIG ?= zig
QEMU ?= qemu-system-x86_64
QEMU_FLAGS ?=
PYTHON ?= python3
BUILD ?= build/default
SCENARIO ?= 0
TEST ?= 0
SOLO ?= -1
COMMON := build/common
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror -ffreestanding -fno-builtin \
          -fno-pie -fno-pic -fno-stack-protector -fno-asynchronous-unwind-tables \
          -ffunction-sections -fdata-sections -mno-red-zone -mgeneral-regs-only -Iinclude
ZFLAGS := -target x86_64-freestanding-none -mcpu=baseline-sse-sse2 -mno-red-zone \
          -fno-stack-check -fno-stack-protector -fno-compiler-rt -O ReleaseSmall \
          -fno-entry -T cells/cell.ld
CELLS := block filesystem client probe
COBJS := $(COMMON)/ipc.o $(COMMON)/runtime.o $(COMMON)/arch.o \
         $(COMMON)/manifest.o $(COMMON)/memory.o $(COMMON)/wait.o
AOBJS := $(COMMON)/entry.o $(COMMON)/traps.o
BOBJS := $(addprefix $(COMMON)/,$(addsuffix .o,$(CELLS)))
HEADERS := $(wildcard include/zeal/*.h)

.PHONY: all run test test-host test-qemu clean FORCE
all: $(BUILD)/zeal.img

$(COMMON) $(BUILD):
	mkdir -p $@

$(COMMON)/ipc.o: kernel/ipc.c $(HEADERS) | $(COMMON)
	$(CC) $(CFLAGS) -c $< -o $@
$(COMMON)/wait.o: kernel/wait.c $(HEADERS) | $(COMMON)
	$(CC) $(CFLAGS) -c $< -o $@
$(COMMON)/manifest.o: kernel/manifest.c $(HEADERS) | $(COMMON)
	$(CC) $(CFLAGS) -c $< -o $@
$(COMMON)/memory.o: kernel/memory.c $(HEADERS) | $(COMMON)
	$(CC) $(CFLAGS) -c $< -o $@
$(COMMON)/runtime.o: kernel/runtime.c | $(COMMON)
	$(CC) $(CFLAGS) -c $< -o $@
$(COMMON)/arch.o: arch/x86_64/arch.c $(HEADERS) | $(COMMON)
	$(CC) $(CFLAGS) -c $< -o $@
$(COMMON)/entry.o: arch/x86_64/entry.S | $(COMMON)
	$(CC) $(CFLAGS) -c $< -o $@
$(COMMON)/traps.o: arch/x86_64/traps.S | $(COMMON)
	$(CC) $(CFLAGS) -c $< -o $@

$(COMMON)/libpolicy.a: policy/lib.rs policy/capability.rs | $(COMMON)
	$(RUSTC) --edition=2021 --crate-type staticlib --target x86_64-unknown-none \
	  -C panic=abort -C opt-level=2 -C debuginfo=2 $< -o $@

$(COMMON)/%.elf: cells/%.zig $(wildcard cells/*.zig) cells/cell.ld | $(COMMON)
	$(ZIG) build-exe $< $(ZFLAGS) -femit-bin=$@
	$(PYTHON) tools/check_cell.py $@
$(COMMON)/%.bin: $(COMMON)/%.elf
	$(OBJCOPY) -O binary $< $@
$(COMMON)/%.o: $(COMMON)/%.bin
	cd $(COMMON) && $(LD) -r -b binary $(notdir $<) -o $(notdir $@)

$(BUILD)/config: FORCE | $(BUILD)
	$(PYTHON) -c 'from pathlib import Path; p=Path("$@"); s="$(SCENARIO) $(TEST) $(SOLO)\n"; p.write_text(s) if not p.exists() or p.read_text()!=s else None'
$(BUILD)/manifest.bin: cells/manifest.toml tools/manifest.py $(BUILD)/config \
	$(COMMON)/block.bin $(COMMON)/filesystem.bin $(COMMON)/client.bin $(COMMON)/probe.bin | $(BUILD)
	$(PYTHON) tools/manifest.py $< $@ $(COMMON)/block.bin $(COMMON)/filesystem.bin \
	  $(COMMON)/client.bin $(COMMON)/probe.bin --scenario $(SCENARIO) --solo $(SOLO)
$(BUILD)/manifest_data.o: $(BUILD)/manifest.bin
	cd $(BUILD) && $(LD) -r -b binary manifest.bin -o manifest_data.o
$(BUILD)/main.o: kernel/main.c $(HEADERS) $(BUILD)/config
	$(CC) $(CFLAGS) -DZ_SCENARIO=$(SCENARIO) -DZ_TEST=$(TEST) -DZ_SOLO=$(SOLO) -c $< -o $@

$(BUILD)/kernel.elf: $(AOBJS) $(COBJS) $(BUILD)/manifest_data.o $(BOBJS) $(BUILD)/main.o $(COMMON)/libpolicy.a arch/x86_64/kernel.ld
	$(LD) -m elf_x86_64 --gc-sections -z noexecstack -T arch/x86_64/kernel.ld \
	  $(AOBJS) $(COBJS) $(BUILD)/main.o $(BOBJS) $(BUILD)/manifest_data.o \
	  $(COMMON)/libpolicy.a -o $@
$(BUILD)/kernel.bin: $(BUILD)/kernel.elf
	$(OBJCOPY) -O binary $< $@
$(BUILD)/boot.bin: boot/boot.S boot/boot.ld $(BUILD)/kernel.bin
	$(AS) --32 --defsym KERNEL_SECTORS=$$((($$(stat -c %s $(BUILD)/kernel.bin)+511)/512)) boot/boot.S -o $(BUILD)/boot.o
	$(LD) -m elf_i386 -T boot/boot.ld $(BUILD)/boot.o -o $@
$(BUILD)/zeal.img: $(BUILD)/boot.bin $(BUILD)/kernel.bin tools/image.py
	$(PYTHON) tools/image.py $(BUILD)/boot.bin $(BUILD)/kernel.bin $@

run: all
	$(QEMU) $(QEMU_FLAGS) -machine pc -accel tcg -cpu max -m 64M -smp 1 \
	  -drive file=$(BUILD)/zeal.img,format=raw,if=ide -display none -serial stdio \
	  -monitor none -nic none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=4

$(COMMON)/libpolicy-host.a: policy/lib.rs policy/capability.rs | $(COMMON)
	$(RUSTC) --edition=2021 --crate-type staticlib -C panic=abort -C opt-level=2 $< -o $@
$(COMMON)/policy-tests: policy/lib.rs policy/capability.rs | $(COMMON)
	$(RUSTC) --edition=2021 --test $< -o $@
$(COMMON)/ipc-tests: tests/ipc.c tests/rust_shim.c kernel/ipc.c $(HEADERS) $(COMMON)/libpolicy-host.a
	$(CC) -std=c11 -g -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer \
	  -fsanitize=address,undefined -fno-pie -no-pie -Iinclude tests/ipc.c tests/rust_shim.c kernel/ipc.c \
	  $(COMMON)/libpolicy-host.a -lpthread -ldl -lm -o $@
$(COMMON)/wait-tests: tests/wait.c tests/rust_shim.c kernel/wait.c kernel/ipc.c kernel/memory.c kernel/manifest.c $(HEADERS) $(COMMON)/libpolicy-host.a
	$(CC) -std=c11 -g -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer \
	  -fsanitize=address,undefined -fno-pie -no-pie -Iinclude \
	  tests/wait.c tests/rust_shim.c kernel/wait.c kernel/ipc.c kernel/memory.c kernel/manifest.c \
	  $(COMMON)/libpolicy-host.a -lpthread -ldl -lm -o $@
$(COMMON)/memory-tests: tests/memory.c kernel/memory.c kernel/manifest.c $(HEADERS)
	$(CC) -std=c11 -g -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer \
	  -fsanitize=address,undefined -fno-pie -no-pie -Iinclude \
	  tests/memory.c kernel/memory.c kernel/manifest.c -o $@
$(COMMON)/manifest-tests: tests/manifest.c kernel/manifest.c $(HEADERS)
	$(CC) -std=c11 -g -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer \
	  -fsanitize=address,undefined -fno-pie -no-pie -Iinclude tests/manifest.c kernel/manifest.c -o $@
test-host: $(COMMON)/policy-tests $(COMMON)/ipc-tests $(COMMON)/wait-tests $(COMMON)/memory-tests $(COMMON)/manifest-tests
	timeout 60s $(COMMON)/policy-tests
	ASAN_OPTIONS=detect_leaks=1 timeout 60s $(COMMON)/ipc-tests
	ASAN_OPTIONS=detect_leaks=1 timeout 60s $(COMMON)/wait-tests
	ASAN_OPTIONS=detect_leaks=1 timeout 60s $(COMMON)/memory-tests
	ASAN_OPTIONS=detect_leaks=1 timeout 60s $(COMMON)/manifest-tests
	timeout 60s $(ZIG) test cells/protocol.zig
	timeout 60s $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
test-qemu: all
	timeout 900s $(PYTHON) tests/research.py
test: test-host test-qemu
clean:
	rm -rf build .zig-cache zig-out

.SECONDARY:
