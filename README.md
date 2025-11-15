# x8086 Assembler/Disassembler

A Python-based assembler and disassembler for a subset of the Intel 8086 instruction set, focusing on the `MOV` register-to-register instruction.

This project is part of the **Performance-aware Programming** series.

## Overview

This project implements a bidirectional converter between x86 assembly code and machine code for the 8086 architecture. It can:

- **Assemble**: Convert x86 assembly language (`.asm` files) into machine code (binary format)
- **Disassemble**: Convert machine code back into x86 assembly language

Currently, it supports the `MOV` instruction for register-to-register operations in 16-bit mode.

## Features

- Assembles x86 `MOV` instructions to 16-bit Intel 8086 machine code
- Disassembles machine code back to readable assembly
- Detailed logging for debugging binary encoding/decoding
- Command-line interface for easy operation
- Support for all 8086 general-purpose registers (8-bit and 16-bit variants)

## Project Structure

```
.
├── main.py                   # Main assembler/disassembler script
├── README.md                 # This file
├── .vscode/
│   └── launch.json           # VS Code debug configurations
└── examples/
    ├── listing_0037_single_register_mov.asm      # Simple MOV example
    ├── listing_0037_single_register_mov          # Compiled binary
    ├── listing_0038_many_register_mov.asm        # Multiple MOV examples
    └── listing_0038_many_register_mov            # Compiled binary
```

## Supported Registers

The assembler supports all 8086 general-purpose registers in both 8-bit and 16-bit variants:

| 16-bit | 8-bit (high) | 8-bit (low) |
|--------|-------------|------------|
| AX     | AH          | AL         |
| BX     | BH          | BL         |
| CX     | CH          | CL         |
| DX     | DH          | DL         |
| SP     | -           | -          |
| BP     | -           | -          |
| SI     | -           | -          |
| DI     | -           | -          |

## Usage

### Command Line

```bash
python main.py -a <action> -i <input_path> -o <output_path>
```

**Arguments:**
- `-a, --action`: Choose operation: `A` for assemble, `D` for disassemble (required)
- `-i, --input`: Path to input file (required)
- `-o, --output`: Path to output file (optional, defaults to `result`)

### Examples

**Assemble assembly code to machine code:**
```bash
python main.py -a A -i examples/listing_0037_single_register_mov.asm -o output_file
```

**Disassemble machine code back to assembly:**
```bash
python main.py -a D -i output_file -o disassembled
```

This creates `disassembled.asm` with the reconstructed assembly code.

## VS Code Integration

The `.vscode/launch.json` file includes four debug configurations:

1. **Assemble (simple)** - Assembles single instruction example
2. **Disassemble (simple)** - Disassembles the simple example back
3. **Assemble (multiple)** - Assembles multiple instructions example
4. **Disassemble (multiple)** - Disassembles the complex example back

Press `F5` to run debug configurations.

## Assembly Format

Assembly files must follow this format:

```nasm
bits 16
mov <destination>, <source>
; More instructions...
```

**Requirements:**
- Start with `bits 16` directive
- One instruction per line
- Comments start with `;`
- Operands are comma-separated register names
- Currently only `mov` instruction is supported

### Example

```nasm
bits 16
mov cx, bx
mov ch, ah
mov dx, bx
```

## Machine Code Format

Generated machine code uses the Intel 8086 MOV instruction encoding:

```
Byte 1: [1 0 0 0 1 0] [D] [W]
Byte 2: [MOD] [REG] [R/M]
```

Where:
- **D (Direction)**: 0 = to REG, 1 = from REG
- **W (Width)**: 0 = 8-bit, 1 = 16-bit
- **MOD**: Mode bits (currently always `11` for register-to-register)
- **REG**: Register field (3 bits)
- **R/M**: Register/Memory field (3 bits)

## Logging

The script includes detailed debug logging. Enable logging to see:
- Instruction identification
- Opcode encoding details
- Register field mappings
- Binary representation of instructions

Output appears with timestamps and log levels in the terminal.

## Examples

### Simple Example (listing_0037)

Input:
```nasm
bits 16
mov cx, bx
```

Binary encoding: `10001100 11001011` → Decimal: `142 203`

### Multiple Instructions (listing_0038)

The `listing_0038_many_register_mov.asm` file demonstrates encoding multiple `MOV` instructions with various register combinations.

## Limitations

- Only supports `MOV` register-to-register instructions
- Only supports 16-bit addressing mode (`MOD = 11`)
- No support for:
  - Immediate values
  - Memory addressing modes
  - Other instruction types
  - Instruction operands beyond register-to-register moves

## Future Enhancements

Potential areas for expansion:
- Support for additional instruction types (ADD, SUB, etc.)
- Memory addressing modes (direct, indexed, based)
- Immediate operands
- Segment override prefixes
- More comprehensive error handling and validation

## Requirements

- Python 3.7+
- No external dependencies (uses only Python standard library)

## License

References: Computer Enhance course materials - https://computerenhance.com
