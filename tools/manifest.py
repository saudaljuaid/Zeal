#!/usr/bin/env python3
"""Compile Zeal's bounded little-endian v2 root/template/domain manifest."""
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
                "POOL_PAGES", "ROOT_POOL_PAGES", "PAGES_PER_CELL", "CONFIG_MAX", "RESTART_LIMIT",
                "RESTART_DELAY", "RIGHTS", "ACTIVE", "IMAGE_COUNT_MAX", "TEMPLATE_MAX", "DOMAIN_MAX",
                "DYNAMIC_SLOTS", "DYNAMIC_PAGES", "DEPTH_MAX", "BOOTSTRAP_RPC", "BOOTSTRAP_SNAPSHOT"}
    if not required <= constants.keys():
        raise ValueError(f"unsupported schema constants: {sorted(required - constants.keys())}")
    formats, current = {}, None
    for line in text.splitlines():
        if re.fullmatch(r"Z_MANIFEST_BEGIN\((\w+)\)", line):
            current = ["<"]
        elif match := re.fullmatch(r"Z_MANIFEST_END\((\w+),\s*(\d+)\)", line):
            name, declared = match.group(1), int(match.group(2))
            fmt = "".join(current)
            if struct.calcsize(fmt) != declared:
                raise ValueError(f"schema record {name} declared size does not match its fields")
            formats[name], current = fmt, None
        elif current is not None:
            if re.fullmatch(r"Z_MANIFEST_U32\((\w+)\)", line):
                current.append("I")
            elif re.fullmatch(r"Z_MANIFEST_U64\((\w+)\)", line):
                current.append("Q")
            elif match := re.fullmatch(r"Z_MANIFEST_BYTES\((\w+),\s*(\d+)\)", line):
                current.append(f"{int(match.group(2))}s")
            elif line.strip():
                raise ValueError(f"unsupported manifest field declaration: {line}")
    if set(formats) != {"header", "cell", "grant", "template", "domain"}:
        raise ValueError("manifest schema must define the v2 header, root, grant, template, and domain records")
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


def fields(item, expected, kind):
    if not isinstance(item, dict) or set(item) != set(expected):
        raise ValueError(f"{kind} must contain exactly {', '.join(expected)}")


def private_pages(stack, writable, constants):
    if not constants["STACK_MIN"] <= stack <= constants["STACK_MAX"] or not stack <= writable <= constants["WRITABLE_MAX"] or writable - stack > constants["HEAP_MAX"]:
        raise ValueError("writable memory budget is outside supported limits")
    stack_pages = (stack + constants["PAGE_SIZE"] - 1) // constants["PAGE_SIZE"]
    heap_pages = (writable - stack + constants["PAGE_SIZE"] - 1) // constants["PAGE_SIZE"]
    if stack_pages + heap_pages > constants["PAGES_PER_CELL"]:
        raise ValueError("independently rounded stack and heap exceed the per-cell page bound")
    return stack_pages + heap_pages


def image_configuration(item, images, constants, config):
    image = u(item.get("image"), 32, "image")
    abi = u(item.get("abi"), 32, "abi")
    entry = u(item.get("entry"), 64, "entry")
    image_budget = u(item.get("image_budget"), 32, "image_budget")
    stack = u(item.get("stack_budget"), 32, "stack_budget")
    writable = u(item.get("writable_budget"), 32, "writable_budget")
    source_config = u(item.get("boot_config"), 32, "source boot_config")
    if source_config > constants["CONFIG_MAX"]:
        raise ValueError("unsupported source boot configuration")
    config = u(config, 32, "boot_config")
    restart_limit = u(item.get("restart_limit"), 32, "restart_limit")
    restart_delay = u(item.get("restart_delay"), 32, "restart_delay")
    if image not in images or entry != images[image][1] or not images[image][0] <= image_budget <= constants["IMAGE_MAX"]:
        raise ValueError("unknown image, entry mismatch, or image budget exceeded")
    if abi != constants["ABI"] or config > constants["CONFIG_MAX"] or restart_limit != constants["RESTART_LIMIT"] or restart_delay != constants["RESTART_DELAY"]:
        raise ValueError("unsupported ABI, boot config, or lifecycle policy")
    pages = private_pages(stack, writable, constants)
    return (image, abi, entry, image_budget, stack, writable, config, restart_limit, restart_delay), pages


def compile_manifest(source, output, image_paths, scenario=0, solo=-1):
    constants, formats = schema_layout()
    rights_by_name = operation_rights(constants["RIGHTS"])
    if not constants["CELL_MAX"] <= len(image_paths) <= constants["IMAGE_COUNT_MAX"]:
        raise ValueError("four to eight sealed image paths are required")
    if type(scenario) is not int or not 0 <= scenario <= constants["CONFIG_MAX"]:
        raise ValueError("unsupported scenario")
    document = tomllib.loads(source.read_text())
    if set(document) - {"version", "cell", "grant", "template", "domain"}:
        raise ValueError("unknown manifest document field")
    cells, grants = document.get("cell"), document.get("grant")
    templates, domains = document.get("template", []), document.get("domain", [])
    if u(document.get("version"), 32, "manifest version") != constants["VERSION"] or not all(isinstance(rows, list) for rows in (cells, grants, templates, domains)):
        raise ValueError("manifest must contain version=2, [[cell]], and [[grant]] records")
    if not 1 <= len(cells) <= constants["CELL_MAX"] or len(grants) > constants["GRANT_MAX"] or len(templates) > constants["TEMPLATE_MAX"] or len(domains) > constants["DOMAIN_MAX"] or type(solo) is not int or not (solo == -1 or 0 <= solo < len(cells)):
        raise ValueError("manifest records or standalone selection exceed the schema")
    if domains and (solo != -1 or len(cells) != constants["CELL_MAX"]):
        raise ValueError("hosting creation authority requires all four original roots active")
    images = {}
    for image_id, path in enumerate(image_paths, 1):
        data = path.read_bytes()
        if not data or len(data) > constants["IMAGE_MAX"]:
            raise ValueError(f"image {image_id} is empty or exceeds {constants['IMAGE_MAX']} bytes")
        images[image_id] = (len(data), 0x40000000)
    image_fields = ("image", "abi", "entry", "image_budget", "stack_budget", "writable_budget", "boot_config", "restart_limit", "restart_delay")
    identities, records, creators = set(), [], {}
    pages = 0
    for index, item in enumerate(cells):
        fields(item, ("identity", "name") + image_fields, "root cell")
        ident = u(item["identity"], 32, "identity")
        image = u(item["image"], 32, "image")
        name = item["name"]
        if ident == 0 or ident in identities:
            raise ValueError("cell identities must be nonzero and unique")
        identities.add(ident)
        if not isinstance(name, str) or not 1 <= len(name.encode()) <= 15 or not name.isascii() or not all(c.isalnum() or c in "_-" for c in name):
            raise ValueError("cell name must be 1..15 ASCII letters, digits, '_' or '-'")
        if image > constants["CELL_MAX"]:
            raise ValueError("dynamic sealed images cannot become manifest root services")
        config = scenario if scenario == 20 or image == 4 or (image == 3 and (scenario == 19 or scenario >= 21)) else item["boot_config"]
        # A standalone hosting source still needs an explicit selected controller branch.
        if image == 4 and scenario == 0 and domains:
            config = item["boot_config"]
        values, own_pages = image_configuration(item, images, constants, config)
        image, abi, entry, budget, stack, writable, config, limit, delay = values
        pages += own_pages
        if pages > constants["ROOT_POOL_PAGES"]:
            raise ValueError("root budgets exceed the reserved 80-page allocation")
        flags = constants["ACTIVE"] if solo < 0 or index == solo else 0
        creators[ident] = (image, config, flags)
        records.append(struct.pack(formats["cell"], ident, image, abi, flags, entry, budget,
                                   stack, writable, config, limit, delay, name.encode() + bytes(16 - len(name))))
    grants_out, seen = [], set()
    for item in grants:
        fields(item, ("holder", "target", "rights"), "grant")
        holder, target = u(item["holder"], 32, "grant holder"), u(item["target"], 32, "grant target")
        names = item["rights"]
        if holder not in identities or target not in identities or not isinstance(names, list):
            raise ValueError("grant references an unknown root cell or malformed rights")
        if (holder, target) in seen:
            raise ValueError("duplicate grant holder/target pair")
        seen.add((holder, target))
        rights = 0
        for name in names:
            if not isinstance(name, str) or name not in rights_by_name or rights & rights_by_name[name]:
                raise ValueError(f"unsupported or duplicate right {name!r}")
            rights |= rights_by_name[name]
        if not rights & (constants["RIGHTS"] & ~rights_by_name["delegate"]) or rights & ~constants["RIGHTS"]:
            raise ValueError("grant must contain operation rights and no unknown bits")
        grants_out.append(struct.pack(formats["grant"], holder, target, rights, 0))
    templates_out, template_mask, recipes, child_masks = [], 0, {}, []
    for item in templates:
        fields(item, ("identity",) + image_fields + ("max_descendant_depth", "child_template_mask", "bootstrap_recipe"), "template")
        ident = u(item["identity"], 32, "template identity")
        if not 1 <= ident <= constants["TEMPLATE_MAX"] or template_mask & (1 << (ident - 1)):
            raise ValueError("template identities must be unique and within 1..8")
        template_mask |= 1 << (ident - 1)
        config = scenario if scenario >= 21 else item["boot_config"]
        values, _ = image_configuration(item, images, constants, config)
        image, abi, entry, budget, stack, writable, config, limit, delay = values
        if image <= constants["CELL_MAX"]:
            raise ValueError("templates require purpose-built dynamic sealed images")
        depth = u(item["max_descendant_depth"], 32, "template depth")
        mask = u(item["child_template_mask"], 32, "template child mask")
        recipe = u(item["bootstrap_recipe"], 32, "bootstrap recipe")
        if depth >= constants["DEPTH_MAX"] or recipe not in (constants["BOOTSTRAP_RPC"], constants["BOOTSTRAP_SNAPSHOT"]) or ((depth == 0) != (mask == 0)):
            raise ValueError("unsupported template depth, child entitlement, or bootstrap recipe")
        if recipe == constants["BOOTSTRAP_SNAPSHOT"] and (config != 25 or
                (ident, image, depth, mask) not in ((5, 5, 1, 32), (6, 6, 0, 0))):
            raise ValueError("snapshot recipe requires explicitly approved scenario25 templates5/6")
        if recipe == constants["BOOTSTRAP_RPC"] and config == 25:
            raise ValueError("scenario25 requires explicit snapshot recipe; old templates remain unchanged")
        child_masks.append(mask)
        recipes[ident] = recipe
        templates_out.append(struct.pack(formats["template"], ident, image, abi, 0, entry, budget,
                                        stack, writable, config, limit, delay, depth, mask, recipe, 0))
    if any(mask & ~template_mask for mask in child_masks):
        raise ValueError("template child mask references an unapproved template")
    domains_out, owners = [], set()
    reserved_pages = reserved_slots = 0
    for item in domains:
        fields(item, ("owner_identity", "template_mask", "slot_limit", "page_limit", "max_depth", "bootstrap_recipe"), "root creation domain")
        owner = u(item["owner_identity"], 32, "domain owner")
        mask = u(item["template_mask"], 32, "domain template mask")
        slots = u(item["slot_limit"], 32, "domain slot limit")
        allowance = u(item["page_limit"], 32, "domain page limit")
        depth = u(item["max_depth"], 32, "domain depth")
        recipe = u(item["bootstrap_recipe"], 32, "domain bootstrap recipe")
        if owner not in creators or mask == 0 or mask & ~template_mask:
            raise ValueError("domain references an unknown root or unapproved template")
        image, config, flags = creators[owner]
        if owner != 400 or image != 4 or flags != constants["ACTIVE"] or not 21 <= config <= constants["CONFIG_MAX"] or owner in owners or not 1 <= slots <= constants["DYNAMIC_SLOTS"] or not 1 <= allowance <= constants["DYNAMIC_PAGES"] or not 1 <= depth <= constants["DEPTH_MAX"] or recipe not in (constants["BOOTSTRAP_RPC"], constants["BOOTSTRAP_SNAPSHOT"]):
            raise ValueError("unsupported root creator, scenario, or descendant allowance")
        if recipe == constants["BOOTSTRAP_SNAPSHOT"] and (config != 25 or mask != 48):
            raise ValueError("snapshot domain requires explicit scenario25 template entitlement")
        if any(recipe != value for ident, value in recipes.items() if mask & (1 << (ident - 1))):
            raise ValueError("root domain and allowed templates require the same explicit bootstrap recipe")
        owners.add(owner)
        reserved_pages += allowance
        reserved_slots += slots
        if reserved_pages > constants["DYNAMIC_PAGES"] or reserved_slots > constants["DYNAMIC_SLOTS"] or pages + reserved_pages > constants["POOL_PAGES"]:
            raise ValueError("creation reservations exceed the bounded global slot/page allowance")
        domains_out.append(struct.pack(formats["domain"], owner, mask, slots, allowance, depth, recipe, 0, 0))
    if scenario >= 21 and not domains_out:
        raise ValueError("hosting scenarios require an explicit root400 creation domain")
    groups = [("cell", records), ("grant", grants_out), ("template", templates_out), ("domain", domains_out)]
    size = struct.calcsize(formats["header"]) + sum(struct.calcsize(formats[name]) * len(rows) for name, rows in groups)
    if size > constants["ARTIFACT_MAX"]:
        raise ValueError("compiled manifest exceeds the schema artifact limit")
    artifact = struct.pack(formats["header"], constants["MAGIC"], constants["VERSION"], size, len(records),
                           len(grants_out), len(templates_out), len(domains_out), 0, 0, 0)
    output.write_bytes(artifact + b"".join(row for _, rows in groups for row in rows))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("images", nargs="+", type=pathlib.Path)
    parser.add_argument("--scenario", type=int, default=0)
    parser.add_argument("--solo", type=int, default=-1)
    args = parser.parse_args()
    try:
        compile_manifest(args.source, args.output, args.images, args.scenario, args.solo)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
