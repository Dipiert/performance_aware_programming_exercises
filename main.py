from enum import Enum
import logging
import argparse
import sys
from pathlib import Path


def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# Constants
WORD_SIZE = 2  # bytes
BYTE_WIDTH = 8  # bits
MOD_REGISTER_TO_REGISTER = "11"

class Instructions(str, Enum):
    MOV = "mov"

instruction_map = {
    "100010": Instructions.MOV
}

def invert_map(mapping):
    """Create reverse mapping from values to keys."""
    return {v: k for k, v in mapping.items()}
    
inv_instruction_map = invert_map(instruction_map)

reg_field_encoding = {
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

inv_reg_field_encoding = invert_map(reg_field_encoding)


def assemble(input_path, output_path):
    """Assemble x86 assembly code to machine code."""
    logger.info("Assembling. Will generate a file called %s", output_path)
    
    # Validate input file exists
    input_file = Path(input_path)
    if not input_file.exists():
        logger.error("Input file not found: %s", input_path)
        sys.exit(1)
    
    output = ["0b"]
    try:
        with open(input_file) as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip()
                
                # Skip empty lines, directives, and comments
                if not line or line in ("bits 16",) or line.startswith(";"):
                    continue
                
                instruction_name = line.split()[0].lower()
                
                if instruction_name == Instructions.MOV:
                    logger.debug("Line %d: Identified %s instruction", line_num, instruction_name)
                    
                    try:
                        operands = line.split(Instructions.MOV)[1].split(",")
                        if len(operands) != 2:
                            logger.error("Line %d: Invalid operand count for MOV instruction", line_num)
                            sys.exit(1)
                        
                        lhs, rhs = operands[0].strip(), operands[1].strip()
                    except (IndexError, ValueError) as e:
                        logger.error("Line %d: Failed to parse operands: %s", line_num, e)
                        sys.exit(1)
                    
                    output.append(inv_instruction_map[Instructions.MOV])
                    output.append("0")  # direction: 0 = to REG
                    logger.debug("Direction: 0")
                    
                    try:
                        reg, w = inv_reg_field_encoding[rhs]
                        rm, _ = inv_reg_field_encoding[lhs]
                    except KeyError as e:
                        logger.error("Line %d: Invalid register: %s", line_num, e)
                        sys.exit(1)
                    
                    output.append(w)
                    logger.debug("Width: %s", w)
                    
                    output.append(MOD_REGISTER_TO_REGISTER)
                    logger.debug("Mode: %s", MOD_REGISTER_TO_REGISTER)
                    
                    output.append(reg)
                    logger.debug("Reg: %s (%s)", reg, rhs)
                    
                    output.append(rm)
                    logger.debug("R/M: %s (%s)", rm, lhs)
                else:
                    logger.warning("Line %d: Unsupported instruction: %s", line_num, instruction_name)
        
        logger.debug("Output: %s", "".join(output))
        
        binary_str = "".join(output)
        with open(output_path, "wb") as result:
            # Skip the "0b" prefix and convert in 8-bit chunks
            for i in range(2, len(binary_str), BYTE_WIDTH):
                byte_str = binary_str[i : i + BYTE_WIDTH]
                if len(byte_str) == BYTE_WIDTH:
                    chunk = int(byte_str, 2).to_bytes(1, 'big')
                    result.write(chunk)
        
        logger.info("Generated file: %s", output_path)
        
    except IOError as e:
        logger.error("File I/O error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error during assembly: %s", e)
        sys.exit(1)


def disassemble(input_path, output_path):
    """Disassemble machine code to x86 assembly."""
    logger.info("Disassembling - Will write %s.asm", output_path)
    
    input_file = Path(input_path)
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
                                result.write(f"{Instructions.MOV} {rm}, {reg}\n")
                            elif d == "1":
                                result.write(f"{Instructions.MOV} {reg}, {rm}\n")
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