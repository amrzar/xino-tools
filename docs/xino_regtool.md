# xino-regtools.py

## Quick example

```json
{
  "namespace": "xino::reg::sys",
  "description": "Example AArch64 registers",
  "registers": [
    {
      "encoding": "sctlr_el2",
      "width": 64,
      "policy": {
        "post_write": "isb"
      },
      "fields": [
        {
          "name": "m",
          "lsb": 0,
          "width": 1,
          "access": "rw",
          "description": "MMU enable"
        },
        {
          "name": "ee",
          "lsb": 25,
          "width": 1,
          "access": "rw",
          "enum_values": {
            "LITTLE_ENDIAN": 0,
            "BIG_ENDIAN": 1
          }
        }
      ]
    }
  ]
}
```

## Command-line usage

```bash
./xino_regtool.py -i spec.json -o regs.hpp
./xino_regtool.py -i spec.json -o regs.hpp -n my::override::ns
```

- **-i / --input** : JSON spec file (required).
- **-o / --output** : Output header file (required).
- **-n / --namespace** : Override the namespace from JSON.

## Top-level JSON structure

The root of the JSON file must be an object:

```json
{
  "namespace": "xino::reg::generated",
  "macro_prefix": "XINO",
  "description": "Auto-generated register accessors",
  "registers": [ /* array of register objects */ ]
}
```

### namespace (string, optional)

- C++ namespace used for all generated types.
- Default: **xino::reg::generated**.
- Can be overridden from the command line using **-n/--namespace**.

### macro_prefix (string, optional)

- Currently parsed but not used by the generator.
- Reserved for future use.
- Default: **XINO**.

### description (string, optional)

- Human-readable description of this spec.
- Default: **Auto-generated register accessors**.

### registers (array, required)

- Non-empty array of register objects.
- If registers is missing, not an array, or empty, the tool fails.
- Each element is a register object.

## Numeric literal syntax

Several fields accept unsigned integers (u32 or u64). They can be:

```json
"lsb": 3,
"width": 5
```

### JSON strings (base-0 parsing)

Strings are parsed using C-style base-0 rules after removing _ and ':

- Hex: "0x1F", "0X1f".
- Binary: "0b1010".
- Octal: "0o77".
- Decimal: "12345".

Separators allowed in strings:

- Underscore: "0xFF_00".
- Apostrophe: "1'000'000".

Both are removed before parsing.

### Constraints

- Values must be non-negative.
- For 32-bit fields, values must be *<= 0xFFFFFFFF*.
- For 64-bit fields, values must be *<= 0xFFFFFFFFFFFFFFFF*.

## Register object
Each register object must have the following structure:

```json
{
  "encoding": "sctlr_el2",
  "width": 64,
  "policy": { /* optional policy object */ },
  "fields": [ /* array of field objects */ ]
}
```

### *encoding* (string, required)

- The encoding name of the register (e.g., "sctlr_el2").
- Used in generated assembly instructions.

```asm
asm volatile("mrs %0, sctlr_el2" : "=r"(tmp));
asm volatile("msr sctlr_el2, %0" :: "r"(tmp));
```

### *width* (u32, required)

- Width of the register in bits.
- Must be either 32 or 64.

### *policy* (object, optional)

- Controls barriers and immediate-only encodings; see [policy object](#policy-object).

### *fields* (array, required, unused for immediate-only registers)

- May be omitted or empty only if policy.immediate_bits is present and non-empty.
- If present, must be an array of field objects; see [field object](#field-object).

## Register kinds

The tool supports two main kinds of registers:

### Normal register

- Width is 32 or 64.
- *Policy.immediate_bits* is absent or empty.
- Fields is a non-empty array.

### Immediate-only register (MSR alias with #imm)

- Width is 32 or 64.
- *Policy.immediate_bits* is a non-empty object.
- Fields may be empty or omitted; they are not used in codegen.

## Policy object

The optional policy object configures memory barriers and, if present, immediate-only behavior.

```json
{
  "pre_read": "dsb_sy",
  "post_read": "isb",
  "pre_write": "dsb_sy",
  "post_write": "isb",
  "immediate_bits": {
    "field_name_1": 1,
    "field_name_2": 3
  }
}
```

All keys are optional; the whole policy object may be omitted.

### Barrier fields

Allowed values:

- *"none"*
- *"isb"*
- *"dmb ish"*
- *"dsb ishst"*
- *"dsb ish"*
- *"dsb sy"*

These map directly to inline assembly such as:

```asm
asm volatile("isb" ::: "memory");
asm volatile("dsb ishst" ::: "memory");
```

Supported keys:

- *pre_read* - barrier inserted before mrs.
- *post_read* - barrier inserted after mrs.
- *pre_write* - barrier inserted before msr.
- *post_write* - barrier inserted after msr.

If a field is omitted or set to *"none"*, no barrier is emitted at that point.

### immediate_bits - immediate-only registers

*immediate_bits* describes MSR aliases that take an immediate mask
instead of a general register operand, e.g. *msr DAIFSet, #imm*.

```json
"immediate_bits": {
  "DEBUG":  0x8,
  "SERROR": 0x4,
  "IRQ":    0x2,
  "FIQ":    0x1
}
```

If immediate_bits is non-empty, the register is treated as **immediate-only**:

## Field object

```json
"fields": [
  {
    "name": "m",
    "lsb": 0,
    "width": 1,
    "access": "rw",
    "description": "MMU enable"
  },
  {
    "name": "ee",
    "bit": 25,
    "access": "rw",
    "enum_values": {
      "LITTLE_ENDIAN": 0,
      "BIG_ENDIAN": 1
    }
  }
]
```
### *bit* (u32, required, optional if *lsb* and *width* are present)

- Bit index of a single-bit field (0-based).
- If present, *lsb* and *width* are ignored.

### *lsb* (u32, required, optional if *bit* is present)

- Bit index of the least significant bit (0-based).
- Default if omitted: 0.

### *width* (u32, required, optional if *bit* is present)

- Number of bits in the field.
- Default if omitted: full register width (32 or 64).
- **lsb + width <= register.width**, otherwise error.

### *name* (string, required)

- Required unless the field covers the entire register.
- A field is a "whole-register field" if **lsb == 0 and width == register.width**

### *access* (string, required)

- "rw", "RW" - readable and writable.
- "ro", "RO", "r" - readable, not writable.
- "wo", "WO", "w" - writable, not readable.

### *description* (string, optional)

- Parsed but not used in generated C++.

### *enum_values* (object, optional)

```json
"enum_values": {
  "OFF": 0,
  "ON":  1
}
```

Generated C++ shape:

- If enum_values is **absent**:

```cpp
using EE = field_base<uint64_t, 25, 1>;
```

- If enum_values is **present**:

```cpp
struct EE : field_base<uint64_t, 25, 1> {
  enum : uint64_t {
    OFF = 0x0,
    ON  = 0x1,
  };
};
```

## Samples

### Minimal spec with a single 64-bit register

```json
{
  "description": "Minimal example",
  "registers": [
    {
      "encoding": "tpidr_el2",
      "width": 64,
      "fields": [
        {
          "access": "rw"
        }
      ]
    }
  ]
}
```

### 32-bit register with mixed access and enums

```json
{
  "namespace": "xino::reg::timers",
  "registers": [
    {
      "encoding": "cntv_ctl_el0",
      "width": 32,
      "policy": {
        "post_write": "isb"
      },
      "fields": [
        {
          "name": "enable",
          "lsb": 0,
          "width": 1,
          "access": "rw",
          "description": "Timer enable"
        },
        {
          "name": "imask",
          "lsb": 1,
          "width": 1,
          "access": "rw",
          "enum_values": {
            "UNMASKED": 0,
            "MASKED":   1
          }
        },
        {
          "name": "istatus",
          "lsb": 2,
          "width": 1,
          "access": "ro",
          "description": "Timer interrupt status"
        }
      ]
    }
  ]
}
```

### Register with write barriers only

```json
{
  "registers": [
    {
      "encoding": "ttbr0_el2",
      "width": 64,
      "policy": {
        "pre_write": "dsb ishst",
        "post_write": "isb"
      },
      "fields": [
        {
          "name": "base",
          "lsb": 0,
          "width": 48,
          "access": "rw",
          "description": "Base address"
        },
        {
          "name": "asids",
          "lsb": 48,
          "width": 16,
          "access": "rw"
        }
      ]
    }
  ]
}
```

### Immediate-only register (DAIFSet-style)

```json
{
  "registers": [
    {
      "encoding": "daifset",
      "width": 32,
      "policy": {
        "pre_write": "dsb ishst",
        "post_write": "isb",
        "immediate_bits": {
          "DEBUG":  0x8,
          "SERROR": 0x4,
          "IRQ":    0x2,
          "FIQ":    0x1
        }
      }
    }
  ]
}
```
