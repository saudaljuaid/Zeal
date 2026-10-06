#!/usr/bin/env python3
"""Compile a small TOML cell manifest into the fixed v1 boot format."""
import argparse
import pathlib
import re
import struct
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "include/zeal/manifest_schema.def"


def schema_layout():
    text = SCHEMA.read_text()
    constants = {name: int(value, 0) for name, value in
                 re.findall(r"Z_MANIFEST_CONSTANT\((\w+),\s*(0x[0-9a-fA-F]+|\d+)\)", text)}
    required = {"MAGIC", "VERSION", "ABI", "CELL_MAX", "GRANT_MAX", "ARTIFACT_MAX", "PAGE_SIZE",
                "IMAGE_MAX", "STACK_MIN", "STACK_MAX", "HEAP_MAX", "WRITABLE_MAX",
                "POOL_PAGES", "PAGES_PER_CELL", "CONFIG_MAX", "RESTART_LIMIT",
                "RESTART_DELAY", "RIGHTS", "ACTIVE"}
    if not required <= constants.keys():
        raise ValueError(f"unsupported schema constants: {sorted(required - constants.keys())}")
    formats = {}
    current = None
    for line in text.splitlines():
        if match := re.fullmatch(r"Z_MANIFEST_BEGIN\((\w+)\)", line):
            current = ["<"]
        elif match := re.fullmatch(r"Z_MANIFEST_END\((\w+),\s*(\d+)\)", line):
            name, declared = match.group(1), int(match.group(2))
            fmt = "".join(current)
            if struct.calcsize(fmt) != declared:
                raise ValueError(f"schema record {name} declared size does not match its fields")
            formats[name] = fmt
            current = None
        elif current is not None:
            if match := re.fullmatch(r"Z_MANIFEST_U32\((\w+)\)", line):
                current.append("I")
            elif match := re.fullmatch(r"Z_MANIFEST_U64\((\w+)\)", line):
                current.append("Q")
            elif match := re.fullmatch(r"Z_MANIFEST_BYTES\((\w+),\s*(\d+)\)", line):
                current.append(f"{int(match.group(2))}s")
            elif line.strip():
                raise ValueError(f"unsupported manifest field declaration: {line}")
    if set(formats) != {"header", "cell", "grant"}:
        raise ValueError("manifest schema must define exactly the v1 header, cell, and grant records")
    return constants, formats


def operation_rights(mask):
    abi = (ROOT / "include/zeal/abi.h").read_text()
    match = re.search(r"enum z_operation\s*\{([^}]*)\}", abi, re.S)
    if not match:
        raise ValueError("ABI does not define enum z_operation")
    result, next_value = {}, 0
    for item in match.group(1).split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, raw = map(str.strip, item.split("=", 1))
            next_value = int(raw, 0)
        else:
            name = item
        result[name.removeprefix("Z_").lower()] = 1 << (next_value - 1)
        next_value += 1
    result["delegate"] = mask & ~((1 << (next_value - 1)) - 1)
    if not result["delegate"] or result["delegate"] & (result["delegate"] - 1):
        raise ValueError("manifest schema must reserve one delegation bit")
    return result


def u(value, bits, field):
    if type(value) is not int or value < 0 or value >= 1 << bits:
        raise ValueError(f"{field} is outside u{bits}")
    return value


def compile_manifest(source, output, image_paths, scenario=0, solo=-1):
    constants, formats = schema_layout()
    rights_by_name = operation_rights(constants["RIGHTS"])
    header_size = struct.calcsize(formats["header"])
    cell_size = struct.calcsize(formats["cell"])
    grant_size = struct.calcsize(formats["grant"])
    if len(image_paths) != 4:
        raise ValueError("exactly four sealed image paths are required")
    document = tomllib.loads(source.read_text())
    cells = document.get("cell")
    grants = document.get("grant")
    if document.get("version") != constants["VERSION"] or not isinstance(cells, list) or not isinstance(grants, list):
        raise ValueError("manifest must contain version=1, [[cell]], and [[grant]] records")
    if not 1 <= len(cells) <= constants["CELL_MAX"] or len(grants) > constants["GRANT_MAX"] or not 0 <= solo < len(cells) and solo != -1:
        raise ValueError("cell, grant, or standalone selection exceeds the schema")
    images = {}
    for image_id, path in enumerate(image_paths, 1):
        data = path.read_bytes()
        if not data or len(data) > constants["IMAGE_MAX"]:
            raise ValueError(f"image {image_id} is empty or exceeds {constants['IMAGE_MAX']} bytes")
        images[image_id] = (len(data), 0x40000000)
    identities, records = set(), []
    pages = 0
    for index, item in enumerate(cells):
        ident = u(item.get("identity"), 32, "identity")
        image = u(item.get("image"), 32, "image")
        name = item.get("name")
        if ident == 0 or ident in identities:
            raise ValueError("cell identities must be nonzero and unique")
        identities.add(ident)
        if not isinstance(name, str) or not 1 <= len(name.encode()) <= 15 or not name.isascii() or not all(c.isalnum() or c in "_-" for c in name):
            raise ValueError("cell name must be 1..15 ASCII letters, digits, '_' or '-'")
        abi = u(item.get("abi"), 32, "abi")
        entry = u(item.get("entry"), 64, "entry")
        image_budget = u(item.get("image_budget"), 32, "image_budget")
        stack = u(item.get("stack_budget"), 32, "stack_budget")
        writable = u(item.get("writable_budget"), 32, "writable_budget")
        config = scenario if image == 4 or (image == 3 and scenario == 19) else u(item.get("boot_config"), 32, "boot_config")
        restart_limit = u(item.get("restart_limit"), 32, "restart_limit")
        restart_delay = u(item.get("restart_delay"), 32, "restart_delay")
        if image not in images or entry != images[image][1] or image_budget < images[image][0] or image_budget > 65536:
            raise ValueError(f"cell {name}: unknown image, entry mismatch, or image budget exceeded")
        if abi != constants["ABI"] or config > constants["CONFIG_MAX"] or restart_limit != constants["RESTART_LIMIT"] or restart_delay != constants["RESTART_DELAY"]:
            raise ValueError(f"cell {name}: unsupported ABI, boot config, or lifecycle policy")
        if not constants["STACK_MIN"] <= stack <= constants["STACK_MAX"] or not stack <= writable <= constants["WRITABLE_MAX"] or writable - stack > constants["HEAP_MAX"]:
            raise ValueError(f"cell {name}: writable memory budget is outside supported limits")
        stack_pages = (stack + constants["PAGE_SIZE"] - 1) // constants["PAGE_SIZE"]
        heap_pages = (writable - stack + constants["PAGE_SIZE"] - 1) // constants["PAGE_SIZE"]
        pages += stack_pages + heap_pages
        if stack_pages + heap_pages > constants["PAGES_PER_CELL"] or pages > constants["POOL_PAGES"]:
            raise ValueError("cell memory budgets exceed the fixed private page pool")
        flags = 1 if solo < 0 or index == solo else 0
        records.append(struct.pack(formats["cell"], ident, image, abi, flags, entry,
                                   image_budget, stack, writable, config, restart_limit,
                                   restart_delay, name.encode() + bytes(16 - len(name.encode()))))
    if pages > constants["POOL_PAGES"] or not any(struct.unpack_from("<I", row, 12)[0] & constants["ACTIVE"] for row in records):
        raise ValueError("manifest has no active cell or exceeds physical memory")
    grants_out, seen = [], set()
    for item in grants:
        holder = u(item.get("holder"), 32, "grant holder")
        target = u(item.get("target"), 32, "grant target")
        names = item.get("rights")
        if holder not in identities or target not in identities or not isinstance(names, list):
            raise ValueError("grant references an unknown cell or malformed rights")
        key = (holder, target)
        if key in seen:
            raise ValueError("duplicate grant holder/target pair")
        seen.add(key)
        rights = 0
        for name in names:
            if name not in rights_by_name:
                raise ValueError(f"unsupported or duplicate right {name!r}")
            bit = rights_by_name[name]
            if rights & bit:
                raise ValueError(f"duplicate right {name!r}")
            rights |= bit
        if not rights & (constants["RIGHTS"] & ~rights_by_name["delegate"]) or rights & ~constants["RIGHTS"]:
            raise ValueError("grant must contain operation rights and no unknown bits")
        grants_out.append(struct.pack(formats["grant"], holder, target, rights, 0))
    size = header_size + cell_size * len(records) + grant_size * len(grants_out)
    if size > constants["ARTIFACT_MAX"]:
        raise ValueError("compiled manifest exceeds the schema artifact limit")
    artifact = struct.pack(formats["header"], constants["MAGIC"], constants["VERSION"], size, len(records),
                           len(grants_out), 0, 0, 0) + b"".join(records) + b"".join(grants_out)
    output.write_bytes(artifact)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("images", nargs=4, type=pathlib.Path)
    parser.add_argument("--scenario", type=int, default=0)
    parser.add_argument("--solo", type=int, default=-1)
    args = parser.parse_args()
    try:
        compile_manifest(args.source, args.output, args.images, args.scenario, args.solo)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
