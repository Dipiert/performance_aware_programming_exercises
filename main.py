from enum import Enum
import logging
import argparse
import sys
import re
from pathlib import Path
from typing import Dict, Tuple, Optional, List, Any


def setup_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# Constants
WORD_SIZE: int = 2  # bytes
BYTE_WIDTH: int = 8  # bits
MOD_REGISTER_TO_REGISTER: str = "11"

class Instructions(str, Enum):
    MOV = "mov"

instruction_map: Dict[str, Instructions] = {
    "100010": Instructions.MOV
}

def invert_map(mapping: Dict[Any, Any]) -> Dict[Any, Any]:
    """Create reverse mapping from values to keys."""
    return {v: k for k, v in mapping.items()}

inv_instruction_map: Dict[Instructions, str] = invert_map(instruction_map)

reg_field_encoding: Dict[Tuple[str, str], str] = {
    # (REG, W) 
    ("000", "0"): "al",
    ("000", "1"): "ax",
    ("001", "0"): "cl",
    ("001", "1"): "cx",
    ("010", "0"): "dl",
    ("010", "1"): "dx",
    ("011", "0"): "bl",
    ("011", "1"): "bx",
    ("100", "0"): "ah",
    ("100", "1"): "sp",
    ("101", "0"): "ch",
    ("101", "1"): "bp",
    ("110", "0"): "dh",
    ("110", "1"): "si",
    ("111", "0"): "bh",
    ("111", "1"): "di",
}

inv_reg_field_encoding: Dict[str, Tuple[str, str]] = invert_map(reg_field_encoding)


def _parse_instruction_line(line: str, line_num: int) -> Optional[Tuple[str, str, str]]:
    """Parse a source line into (instruction, lhs, rhs).
    - Normalizes to lower-case
    - Splits on commas and whitespace so `mov cx,bx` and `mov cx, bx` both work
    - Raises ValueError on malformed input or unexpected extra tokens
    """
    tokens: List[str] = [t for t in re.split(r"[,\s]+", line) if t]
    if not tokens:
        return None

    if len(tokens) < 3:
        raise ValueError(f"Line {line_num}: Invalid instruction format: {line}")

    instruction_name, lhs, rhs, *rest = (t.lower() for t in tokens)
    if rest:
        raise ValueError(f"Line {line_num}: Unexpected tokens in instruction: {' '.join(rest)}")

    return instruction_name, lhs, rhs


def assemble(input_path: str, output_path: str) -> None:
    """Assemble x86 assembly code to machine code."""
    logger.info("Assembling. Will generate a file called %s", output_path)
    
    input_file: Path = Path(input_path)
    if not input_file.exists():
        logger.error("Input file not found: %s", input_path)
        sys.exit(1)
    
    output_bytes: bytearray = bytearray()
    try:
        with open(input_file) as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip()
                
                if not line:
                    logger.debug("Line %d: Skipping empty/blank line", line_num)
                    continue

                if line.strip().lower() == "bits 16":
                    logger.debug("Line %d: Skipping directive: %s", line_num, line.strip())
                    continue

                if line.lstrip().startswith(";"):
                    logger.debug("Line %d: Skipping comment line", line_num)
                    continue
                
                try:
                    parsed = _parse_instruction_line(line, line_num)
                except ValueError as e:
                    logger.error(str(e))
                    sys.exit(1)

                if parsed is None:
                    logger.debug("Line %d: Skipping line after parsing (blank or directive)", line_num)
                    continue

                instruction_name, lhs, rhs = parsed

                if instruction_name == Instructions.MOV:
                    logger.debug("Line %d: Identified %s instruction", line_num, instruction_name)

                    try:
                        reg, w = inv_reg_field_encoding[rhs]
                        rm, _ = inv_reg_field_encoding[lhs]
                    except KeyError as e:
                        logger.error("Line %d: Invalid register: %s", line_num, e)
                        sys.exit(1)

                    opcode_int: int = int(inv_instruction_map[Instructions.MOV], 2)
                    d_int: int = 0  # direction: 0 = to REG
                    w_int: int = int(w, 2)  # width bit (0 or 1)
                    reg_int: int = int(reg, 2)  # 3-bit reg field
                    rm_int: int = int(rm, 2)  # 3-bit r/m field

                    first_byte: int = (opcode_int << 2) | (d_int << 1) | w_int
                    mod_int: int = int(MOD_REGISTER_TO_REGISTER, 2)
                    second_byte: int = (mod_int << 6) | (reg_int << 3) | rm_int

                    if not (0 <= first_byte <= 0xFF and 0 <= second_byte <= 0xFF):
                        logger.error("Line %d: Encoded bytes out of range: %d, %d", 
                                   line_num, first_byte, second_byte)
                        sys.exit(1)

                    output_bytes.extend([first_byte, second_byte])

                    debug_bin: str = format(first_byte, '08b') + format(second_byte, '08b')
                    logger.debug("Line %d: Encoded bytes (binary): %s", line_num, debug_bin)
                    logger.debug("Direction: %d, Width: %d", d_int, w_int)
                    logger.debug("Mode: %s, Reg: %s (%s), R/M: %s (%s)", 
                               MOD_REGISTER_TO_REGISTER, reg, rhs, rm, lhs)
                else:
                    logger.warning("Line %d: Unsupported instruction: %s", line_num, instruction_name)
        
        logger.debug("Output bytes: %d total", len(output_bytes))
        
        with open(output_path, "wb") as result:
            result.write(output_bytes)
        
        logger.info("Generated file: %s", output_path)
        
    except IOError as e:
        logger.error("File I/O error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error during assembly: %s", e)
        sys.exit(1)


def disassemble(input_path: str, output_path: str) -> None:
    """Disassemble machine code to x86 assembly."""
    logger.info("Disassembling - Will write %s.asm", output_path)
    
    input_file: Path = Path(input_path)
    if not input_file.exists():
        logger.error("Input file not found: %s", input_path)
        sys.exit(1)
    
    try:
        with open(f"{output_path}.asm", "w") as result:
            result.write("bits 16\n")
            with open(input_file, "rb") as f:
                instruction_count = 0
                while word := f.read(WORD_SIZE):
                    if len(word) != WORD_SIZE:
                        logger.warning("Incomplete word at end of file, skipping")
                        continue
                    
                    instruction_count += 1
                    first_byte = format(word[0], '08b')
                    second_byte = format(word[1], '08b')
                    logger.debug("Instruction %d - First byte: %s", instruction_count, first_byte)
                    logger.debug("Instruction %d - Second byte: %s", instruction_count, second_byte)
                    
                    opcode = bin(word[0] >> 2)[2:].zfill(6)
                    
                    if instruction := instruction_map.get(opcode):
                        logger.debug("Instruction %d: Identified %s instruction", instruction_count, instruction.value)
                        
                        if instruction == Instructions.MOV:
                            d = format((word[0] >> 1) & 1, '01b')
                            w = format(word[0] & 1, '01b')
                            logger.debug("Direction: %s, Width: %s", d, w)
                            
                            mod = format(word[1] >> 6, '02b')
                            reg_bin = format((word[1] >> 3) & 0b111, '03b')
                            reg = reg_field_encoding.get((reg_bin, w))
                            rm_bin = format(word[1] & 0b111, '03b')
                            rm = reg_field_encoding.get((rm_bin, w))
                            
                            logger.debug("Mode: %s, Register: %s (%s), R/M: %s (%s)", 
                                       mod, reg_bin, reg, rm_bin, rm)
                            
                            if not reg or not rm:
                                logger.error("Instruction %d: Invalid register encoding", instruction_count)
                                sys.exit(1)
                            
                            if d == "0":
                                result.write(f"{instruction} {rm}, {reg}\n")
                            elif d == "1":
                                result.write(f"{instruction} {reg}, {rm}\n")
                    else:
                        logger.warning("Unknown opcode: %s", opcode)
        
        logger.info("Generated file: %s.asm", output_path)
        
    except IOError as e:
        logger.error("File I/O error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error during disassembly: %s", e)
        sys.exit(1)
            
if __name__ == '__main__':
    cli_parser = argparse.ArgumentParser(
        description="x8086 Assembler/Disassembler for MOV register-to-register instructions"
    )
    cli_parser.add_argument(
        "-i", "--input",
        metavar='<input path>',
        type=str,
        required=True,
        help="Input file path (assembly or binary)"
    )
    cli_parser.add_argument(
        "-a", "--action",
        choices=["A", "D"],
        required=True,
        help="A for assemble (ASM to binary), D for disassemble (binary to ASM)"
    )
    cli_parser.add_argument(
        "-o", "--output",
        metavar='<output path>',
        type=str,
        default="result",
        help="Output file path (default: result)"
    )
    
    args = cli_parser.parse_args()
    
    try:
        if args.action == "A":
            assemble(args.input, args.output)
        elif args.action == "D":
            disassemble(args.input, args.output)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        sys.exit(1)