#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# UTILITIES.
# sanitize_identifier(...)
# to_hex_str(...)
# require_str(...)
# require_uint_64(...)
# require_uint_32(...)


def sanitize_identifier(s: str, upper: bool = False) -> str:
    out = s.upper() if upper else s
    out = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in out)
    if out and out[0].isdigit():
        out = "_" + out
    return out


def to_hex_str(v: int) -> str:
    return "0x" + format(v, "X")


def require_str(v: Any, ctx: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"Expected string for {ctx}")
    return v


def require_uint_64(v: Any, ctx: str) -> int:
    if isinstance(v, int):
        if v < 0:
            raise ValueError(f"Negative value not allowed for {ctx}")
        return v
    if isinstance(v, str):
        s = v.replace("_", "").replace("'", "")
        try:
            n = int(s, 0)  # supports 0x / 0o / 0b
        except Exception:
            raise ValueError(f"Invalid numeric literal for {ctx}: {v}")
        if n < 0:
            raise ValueError(f"Negative value not allowed for {ctx}")
        return n
    raise ValueError(f"Expected unsigned integer for {ctx}")


def require_uint_32(v: Any, ctx: str) -> int:
    n = require_uint_64(v, ctx)
    if not (0 <= n <= 0xFFFFFFFF):
        raise ValueError(f"Unsigned integer is too large for {ctx}")
    return n

# JSON REGISTER PARSER.
# parse_policy(...)
# parse_field(...)
# parse_register(...)
# parse_spec(...)


BARRIER_MAP = {
    "none": "none",
    "isb": "isb",
    "dmb ish": "dmb ish",
    "dsb ishst": "dsb ishst",
    "dsb ish": "dsb ish",
    "dsb sy": "dsb sy",
}


def parse_policy(obj: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if obj is None:
        return {
            "pre_read": None, "post_read": None,
            "pre_write": None, "post_write": None,
            "imm_map": {}
        }

    # -- { "post_x": "nnn", "pre_x": "mmm", ... } --
    # (Optional)
    def pbar(key: str) -> Optional[str]:
        v = obj.get(key)
        if v is None:
            return None
        s = require_str(v, f"policy.{key}").strip().lower()
        if s not in BARRIER_MAP:
            raise ValueError(f"Unknown barrier for policy.{key}: {v}")
        return BARRIER_MAP[s]

    # -- { ..., "immediate_bits": { "name": u32, ... } } --
    imm_map: Dict[str, int] = {}
    bits = obj.get("immediate_bits")
    if bits is not None:
        if not isinstance(bits, dict):
            raise ValueError("policy.immediate_bits must be a dict")

        for k, vv in bits.items():
            name_k = require_str(k, "policy.immediate_bits key")
            val_k = require_uint_32(vv, f"policy.immediate_bits.{name_k}")
            if name_k in imm_map:
                raise ValueError(f"Duplicate immediate name: {name_k}")
            imm_map[name_k] = val_k

        if not imm_map:
            raise ValueError("policy.immediate_bits is empty")

    return {
        "pre_read":  pbar("pre_read"),
        "post_read": pbar("post_read"),
        "pre_write": pbar("pre_write"),
        "post_write": pbar("post_write"),
        "imm_map":   imm_map,
    }


def parse_field(obj: Dict[str, Any], reg_width: int) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("Field must be a dict")

    whole = False

    # -- { ..., "lsb": u32, ... } --
    # (Required)
    lsb = require_uint_32(obj.get("lsb", 0), f"field.lsb")
    # -- { ..., "width": u32, ... } --
    # (Required)
    width = require_uint_32(obj.get("width", reg_width), f"field.width")
    if width == 0:
        raise ValueError(f"field.width must be > 0")
    if lsb + width > reg_width:
        raise ValueError(f"field exceeds register width")

    # Whole-register detection
    whole = (lsb == 0 and width == reg_width)

    if not whole:
        # -- { "name": "nnn", ... } --
        # (Required)
        name = require_str(obj.get("name"), "field.name")
    else:
        name = ""

    # -- { ..., "access": "nn", ... } --
    # (Required)
    acc = require_str(obj.get("access"), f"{name}.access")
    if acc in ("rw", "RW"):
        readable, writable = True, True
    elif acc in ("ro", "RO", "r"):
        readable, writable = True, False
    elif acc in ("wo", "WO", "w"):
        readable, writable = False, True
    else:
        raise ValueError(f"Unknown access mode: {acc}")

    # -- { ..., "description": "nnn", ... } --
    # (Optional)
    desc = obj.get("description")
    description = desc if desc is not None and isinstance(desc, str) else ""

    # -- { ..., "enum_values": { "nnn": u64, ... } } --
    # (Optional)
    enums_map: Dict[str, int] = {}
    ev = obj.get("enum_values")
    if ev is not None:
        if not isinstance(ev, dict):
            raise ValueError("enum_values must be a dict")

        for k, vv in ev.items():
            name_k = require_str(k, f"{name}.enum_values key")
            val_k = require_uint_64(vv, f"{name}.enum_values")
            if name_k in enums_map:
                raise ValueError(f"Duplicate enum name in {name}: {name_k}")
            enums_map[name_k] = val_k

    return {
        "name": name,
        "lsb": lsb,
        "width": width,
        "readable": readable,
        "writable": writable,
        "description": description,
        "enums_map": enums_map,
    }


def parse_register(obj: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("Register must be a dict")

    # -- { "encoding": "nnn", ... } --
    # (Required)
    encoding = require_str(obj.get("encoding"), "register.encoding")

    # -- { ..., "width": 32, ... } --
    # (required)
    width_bits = require_uint_32(obj.get("width"), "register.width")
    if width_bits not in (32, 64):
        raise ValueError(f"Register '{encoding}' width must be 32 or 64 bits")

    # -- { ..., "policy": { ... }, ... } --
    # (Optional)
    policy = parse_policy(obj.get("policy"))

    # -- { ..., "fields": [ ... ] } --
    # (Required, optional if immediate_bits)
    fields_node = obj.get("fields")
    if fields_node is None:
        fields_node = []
    if not isinstance(fields_node, list):
        raise ValueError("\"fields\" must be an array")

    fields = [parse_field(f, width_bits) for f in fields_node]
    if not fields and not policy["imm_map"]:
        raise ValueError(f"Register '{encoding}' has no fields")

    return {
        "encoding": encoding,
        "width_bits": width_bits,
        "policy": policy,
        "fields": fields
    }


def parse_spec(obj: Dict[str, Any], source: Path) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("Top-level JSON must be a dict")

    # -- { "namespace": "nnn", ... } --
    ns = obj.get("namespace", "xino::reg::generated")

    # -- { ..., "macro_prefix": "nnn", ... } --
    mp = obj.get("macro_prefix", "XINO")

    # -- { ..., "description": "nnn", ... } --
    desc = obj.get("description", "Auto-generated register accessors")

    # -- { ..., "registers": [ ... ], ... } --
    regs = obj.get("registers")
    if not isinstance(regs, list):
        raise ValueError("\"registers\" must be an array")
    regs_parsed = [parse_register(r) for r in regs]
    if not regs_parsed:
        raise ValueError("At least one register must be defined")

    return {
        "ns": ns,
        "desc": desc,
        "mp": mp,
        "regs": regs_parsed,
        "source": str(source)
    }


# CODE WRITER.
# emit_preamble(...)
# emit_barrier(...)
# emit_register(...)
# generate(...)


class CodeWriter:
    def __init__(self):
        self.buf: List[str] = []
        self.ind = 0

    def line(self, s: str = ""):
        self.buf.append(("  " * self.ind) + s if s else "")

    def indent(self): self.ind += 1
    def outdent(self): self.ind = max(0, self.ind - 1)

    def text(self) -> str:
        return "\n".join(self.buf) + "\n"

# MODIFY BASE and emit_register(...) for different C++ code.
# BASE is the base class for register feilds.
# Register feild is an instance of field_base or inherited from it. 

BASE = r"""
template <typename T, unsigned LSB, unsigned WIDTH> class field_base {
  static_assert(WIDTH > 0, "Field width must be > 0");

private:
  static constexpr T all_ones() { return ~T{0}; }

  static constexpr unsigned digits() noexcept {
    return std::numeric_limits<T>::digits;
  }

  static constexpr T mask_from_width(unsigned width) {
    return (width == 0)        ? T{0}
           : (width >= digits) ? all_ones()
                               : static_cast<T>(all_ones() >> (digits - width));
  }

public:
  static inline constexpr unsigned lsb = LSB;
  static inline constexpr unsigned width = WIDTH;
  static inline constexpr T mask_unshifted = mask_from_width(WIDTH);
  static inline constexpr T mask = static_cast<T>(mask_unshifted << LSB);

  static constexpr T encode(T v) {
    return static_cast<T>((v & mask_unshifted) << LSB);
  }

  static constexpr T insert(T orig, T v) {
    return static_cast<T>((orig & ~mask) | encode(v));
  }

  [[nodiscard]] static constexpr T extract(T r) {
    return static_cast<T>((r & mask) >> LSB);
  }
};
"""


def emit_preamble(w: CodeWriter, spec: Dict[str, Any]) -> None:
    w.line("/**")
    w.line(" * @file")
    w.line(" * @brief ''aarch64'' system register accessors.")
    w.line(" * @details Generated by xino_regtool.py.")
    w.line(f" *  Source: `{spec['source']}`")
    w.line(" */")
    w.line()
    w.line("#pragma once")
    w.line("#include <cstdint>")
    w.line("#include <cstddef>")
    w.line("#include <type_traits>")
    w.line("#include <limits>")
    w.line()
    w.line("#ifndef __aarch64__")
    w.line('# error "This header only supports aarch64 targets"')
    w.line("#endif")
    w.line()
    w.line(f"namespace {spec['ns']} {{")
    w.line()
    w.line(BASE.strip())
    w.line()


def emit_barrier(w: CodeWriter, b: Optional[str]) -> None:
    if b and b != "none":
        w.line(f'asm volatile("{b}" ::: "memory");')


def emit_register(w: CodeWriter, spec: Dict[str, Any], reg: Dict[str, Any]) -> None:
    can_read = any(f["readable"] for f in reg["fields"])
    can_write = (not reg["policy"]["imm_map"]) and any(
        f["writable"] for f in reg["fields"])
    has_imm = bool(reg["policy"]["imm_map"])

    w.line(f"/* -- {sanitize_identifier(reg["encoding"], True)} -- */")
    w.line()

    tname = "uint32_t" if reg["width_bits"] <= 32 else "uint64_t"
    sname = sanitize_identifier(reg["encoding"])

    # Immediate-only registers (MSR <alias>, #imm)
    if has_imm:
        # Union of all allowable immediate bits (bitwise OR of values).
        imm_all = 0
        for _, vv in reg["policy"]["imm_map"].items():
            imm_all |= int(vv)

        w.line(f"class {sname} {{")

        # Public API:
        w.line("public:")
        w.indent()

        w.line(
            f"static inline constexpr unsigned width_bits = {reg['width_bits']};")
        w.line("static inline constexpr bool readable = false;")
        w.line("static inline constexpr bool writable = true;")
        w.line()

        w.line(f"enum class flags : {tname} {{")
        w.indent()
        items = sorted(reg["policy"]["imm_map"].items(), key=lambda kv: kv[1])
        for i, (nm, vv) in enumerate(items):
            comma = "" if i + 1 == len(items) else ","
            w.line(f"{sanitize_identifier(nm)} = static_cast<{tname}>({vv}){comma}")
        w.outdent()
        w.line("};")
        w.line()

        # '|' and '&' operators
        w.line("friend constexpr flags operator|(flags a, flags b) {")
        w.indent()
        w.line(
            f"return static_cast<flags>(static_cast<{tname}>(a) | static_cast<{tname}>(b));")
        w.outdent()
        w.line("}")
        w.line("friend constexpr flags operator&(flags a, flags b) {")
        w.indent()
        w.line(
            f"return static_cast<flags>(static_cast<{tname}>(a) & static_cast<{tname}>(b));")
        w.outdent()
        w.line("}")
        w.line()

        # Public typed entrypoint delegates to private raw writer
        w.line("static inline void write_mask(flags flags) {")
        w.indent()
        w.line(f"write_mask(static_cast<{tname}>(flags));")
        w.outdent()
        w.line("}")
        w.line()

        # Private:
        w.outdent()
        w.line("private:")
        w.indent()

        w.line(
            f"static inline constexpr {tname} imm_all_mask = static_cast<{tname}>({imm_all});")
        w.line()

        w.line(f"static inline void write_mask({tname} mask) {{")
        w.indent()
        w.line(
            f"const {tname} imm = static_cast<{tname}>(mask & imm_all_mask);")
        w.line("if (!imm) return;")
        emit_barrier(w, reg["policy"]["pre_write"])
        w.line("switch (imm) {")
        w.indent()
        # Emit only valid immediate subsets (bits entirely within imm_all), up to 31.
        for v in range(1, 32):
            if v & ~imm_all:
                continue
            w.line(
                f'case {v}: asm volatile("msr {reg["encoding"]}, #{v}"); break;')
        w.line("default: break;")
        w.outdent()
        w.line("}")
        emit_barrier(w, reg["policy"]["post_write"])
        w.outdent()  # write_mask
        w.line("}")

        w.outdent()
        w.line("};")
        return  # No fields / bulk helpers for immediate-only aliases.

    # Normal (R/M/W) system registers
    w.line(f"class {sname} {{")

    # Public API:
    w.line("public:")
    w.indent()
    w.line(
        f"static inline constexpr unsigned width_bits = {reg['width_bits']};")
    w.line(
        f"static inline constexpr bool readable = {'true' if can_read else 'false'};")
    w.line(
        f"static inline constexpr bool writable = {'true' if can_write else 'false'};")
    w.line()

    # Field aliases / wrappers
    for f in reg["fields"]:
        fname = sanitize_identifier(f["name"])
        if not fname:
            continue
        if not f["enums_map"]:
            w.line(
                f"using {fname} = field_base<{tname}, {f['lsb']}, {f['width']}>;")
            w.line()
        else:
            w.line(
                f"struct {fname} : field_base<{tname}, {f['lsb']}, {f['width']}> {{")
            w.indent()
            w.line(f"enum : {tname} {{")
            w.indent()
            items = list(f["enums_map"].items())
            for i, (en, ev) in enumerate(items):
                comma = "" if i + 1 == len(items) else ","
                w.line(f"{sanitize_identifier(en)} = {to_hex_str(ev)}{comma}")
            w.outdent()
            w.line("};")
            w.outdent()
            w.line("};")
            w.line()

    # Convenience per-field accessors
    for f in reg["fields"]:
        fname = sanitize_identifier(f["name"])
        if not fname:
            continue
        if f["readable"] and can_read:
            w.line(f"[[nodiscard]] static inline {tname} read_{fname}() {{")
            w.indent()
            w.line(f"return {fname}::extract(read());")
            w.outdent()
            w.line("}")
            w.line()
        if f["writable"] and can_read and can_write:
            w.line(f"static inline void write_{fname}({tname} value) {{")
            w.indent()
            w.line(f"{tname} tmp = {fname}::insert(read(), value);")
            w.line("write(tmp);")
            w.outdent()
            w.line("}")
            w.line()

    # Bulk helpers
    if can_read:
        w.line(
            f"[[nodiscard]] static inline {tname} read_bits({tname} mask) {{")
        w.indent()
        w.line(f"return static_cast<{tname}>(read() & mask);")
        w.outdent()
        w.line("}")
        w.line()

    if can_read and can_write:
        w.line(f"static inline void write_bits({tname} set_mask) {{")
        w.indent()
        w.line(f"update_bits(set_mask, static_cast<{tname}>(0));")
        w.outdent()
        w.line("}")
        w.line()

        w.line(
            f"static inline void update_bits({tname} set_mask, {tname} clear_mask) {{")
        w.indent()
        w.line(f"{tname} v = read();")
        w.line(f"v = static_cast<{tname}>((v | set_mask) & ~clear_mask);")
        w.line("write(v);")
        w.outdent()
        w.line("}")
        w.line()

    # Private:
    w.outdent()
    w.line("private:")
    w.indent()

    # Read / write primitives
    if can_read:
        w.line(f"[[nodiscard]] static inline {tname} read() {{")
        w.indent()
        emit_barrier(w, reg["policy"]["pre_read"])
        w.line("uint64_t tmp;")
        w.line(f'asm volatile("mrs %0, {reg["encoding"]}" : "=r"(tmp));')
        emit_barrier(w, reg["policy"]["post_read"])
        w.line(f"return static_cast<{tname}>(tmp);")
        w.outdent()  # read
        w.line("}")
        w.line()

    if can_write:
        w.line(f"static inline void write({tname} value) {{")
        w.indent()
        emit_barrier(w, reg["policy"]["pre_write"])
        w.line("uint64_t tmp = static_cast<uint64_t>(value);")
        w.line(f'asm volatile("msr {reg["encoding"]}, %0" :: "r"(tmp));')
        emit_barrier(w, reg["policy"]["post_write"])
        w.outdent()  # write
        w.line("}")

    w.outdent()
    w.line("};")


def generate(spec: Dict[str, Any]) -> str:
    w = CodeWriter()
    emit_preamble(w, spec)
    for r in spec["regs"]:
        w.line()
        emit_register(w, spec, r)
    w.line()
    w.line(f"}}  // namespace {spec['ns']}")
    return w.text()


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Generate single-file AArch64 register header from JSON")
    ap.add_argument("-i", "--input", required=True, help="JSON spec")
    ap.add_argument("-o", "--output", required=True, help="Output header path")
    ap.add_argument("-n", "--namespace", help="Override C++ namespace")
    args = ap.parse_args(argv)

    spec_path = Path(args.input)
    out_path = Path(args.output)

    try:
        data = spec_path.read_text(encoding="utf-8");
        if not data.strip():
            out_path.write_text("", encoding="utf-8", newline="\n")
            return 0

        spec = parse_spec(json.loads(data), spec_path)
        if args.namespace:
            spec["ns"] = args.namespace
        out_path.write_text(generate(spec), encoding="utf-8", newline="\n")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
