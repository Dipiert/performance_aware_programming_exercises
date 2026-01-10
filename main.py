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

class MODFieldEncoding(str, Enum):
    REGISTER_TO_REGISTER = "11"
    REGISTER_TO_MEMORY_NO_DISP = "00"
    REGISTER_TO_MEMORY_8BIT_DISP = "01"
    REGISTER_TO_MEMORY_16BIT_DISP = "10"

class Instructions(str, Enum):
    MOV = "mov"

class MOVTypes(str, Enum):
    RM_FT_R = "MOV: Register/memory to/from register"
    I_T_RM = "MOV: Immediate to register/memory"
    I_T_R = "MOV: Immediate to register"


class _8bitRegisters(str, Enum):
    AL = "al"
    AH = "ah"
    BL = "bl"
    BH = "bh"
    CL = "cl"
    CH = "ch"
    DL = "dl"
    DH = "dh"
    
class _16bitRegisters(str, Enum):
    AX = "ax"
    BX = "bx"
    CX = "cx"
    DX = "dx"
    SP = "sp"
    BP = "bp"
    SI = "si"
    DI = "di"

_8BIT_REGS = {r.value for r in _8bitRegisters}
_16BIT_REGS = {r.value for r in _16bitRegisters}
REGISTERS = _8BIT_REGS | _16BIT_REGS

# instruction_map: Dict[str, Instructions] = {
#     ("100010", MOVTypes.RM_FT_R): Instructions.MOV,
#     ("1100011", MOVTypes.I_T_RM): Instructions.MOV,
#     ("1011", MOVTypes.I_T_R): Instructions.MOV
# }

instruction_map : Dict[str, Instructions] = {
    "100010": MOVTypes.RM_FT_R,
    "1100011": MOVTypes.I_T_RM,
    "1011": MOVTypes.I_T_R,
}

def is_mov_type(value):
    try:
        MOVTypes(value)
        return True
    except Exception as e:
        return False

def derive_mov_type(lhs, rhs):
    """
    Derive the MOV type based on the operands and the shift needed.
    Depending on the MOV type, the following shift amounts are needed:
    2 bits are needed for d and w,
    4 bits are needed for w and reg or
    1 bit is needed for w.
    """    
    if lhs in REGISTERS and rhs in REGISTERS:
        return inv_instruction_map[Instructions.MOV][MOVTypes.RM_FT_R], 2
    if (lhs in REGISTERS) and is_int(rhs):
        return inv_instruction_map[Instructions.MOV][MOVTypes.I_T_R], 4
    if ("[" in lhs or is_int(lhs)) and is_int(rhs):
        return inv_instruction_map[Instructions.MOV][MOVTypes.I_T_RM], 1
    if (rhs in REGISTERS) and ("[" in lhs or is_int(lhs)):
        return inv_instruction_map[Instructions.MOV][MOVTypes.RM_FT_R], 2
    if (lhs in REGISTERS) and ("[" in rhs or is_int(rhs)):
        return inv_instruction_map[Instructions.MOV][MOVTypes.RM_FT_R], 2
    raise ValueError("Unable to derive MOV type from operands.")

inv_instruction_map = {
    Instructions.MOV: {
        MOVTypes.RM_FT_R: "100010",
        MOVTypes.I_T_RM: "1100011",
        MOVTypes.I_T_R: "1011"
    }
}
def invert_map(mapping: Dict[Any, Any]) -> Dict[Any, Any]:
    """Create reverse mapping from values to keys."""
    return {v: k for k, v in mapping.items()}

reg_field_encoding: Dict[Tuple[str, str], str] = {
    # (REG, W) 
    ("000", "0"): _8bitRegisters.AL.value,
    ("000", "1"): _16bitRegisters.AX.value,
    ("001", "0"): _8bitRegisters.CL.value,
    ("001", "1"): _16bitRegisters.CX.value,
    ("010", "0"): _8bitRegisters.DL.value,
    ("010", "1"): _16bitRegisters.DX.value,
    ("011", "0"): _8bitRegisters.BL.value,
    ("011", "1"): _16bitRegisters.BX.value,
    ("100", "0"): _8bitRegisters.AH.value,
    ("100", "1"): _16bitRegisters.SP.value,
    ("101", "0"): _8bitRegisters.CH.value,
    ("101", "1"): _16bitRegisters.BP.value,
    ("110", "0"): _8bitRegisters.DH.value,
    ("110", "1"): _16bitRegisters.SI.value,
    ("111", "0"): _8bitRegisters.BH.value,
    ("111", "1"): _16bitRegisters.DI.value,
}

eff_addr_encoding= {
    # (Register1, Register2): R/M
    (_16bitRegisters.BX.value, _16bitRegisters.SI.value): "000",
    (_16bitRegisters.BX.value, _16bitRegisters.DI.value): "001",
    (_16bitRegisters.BP.value, _16bitRegisters.SI.value): "010",
    (_16bitRegisters.BP.value, _16bitRegisters.DI.value): "011",
    (_16bitRegisters.SI.value, None): "100",
    (_16bitRegisters.DI.value, None): "101",
    (_16bitRegisters.BX.value, None): "110",        
    (_16bitRegisters.BP.value, None): "111",        
}

inv_reg_field_encoding: Dict[str, Tuple[str, str]] = invert_map(reg_field_encoding)


def _parse_instruction_line(line: str, line_num: int) -> Optional[Tuple[str, str, str]]:
    """Parse a source line into (instruction, lhs, rhs).
    - Normalizes to lower-case
    - Splits on commas and whitespace so `mov cx,bx` and `mov cx, bx` both work
    - Raises ValueError on malformed input
    """
    dest_calc, src_calc = False, False

    before_comma, after_comma = line.split(",")
    if "[" in before_comma:
        dest_calc = True
    elif "[" in after_comma:
        src_calc = True

    tokens: List[str] = [t for t in re.split(r"[,\s]+", line) if t]
    if not tokens:
        return None

    if len(tokens) < 3:
        raise ValueError(f"Line {line_num}: Invalid instruction format: {line}")

    if len(tokens) > 3:
        if src_calc:
            tokens = tokens[:2] + [''.join(tokens[2:])]
        elif dest_calc:
            tokens = tokens[:1] + [''.join(tokens[1:-1])] + [tokens[-1]]
        else:
            raise ValueError(f"Line {line_num}: Invalid instruction format: {line}")


    instruction_name, lhs, rhs = (t.lower() for t in tokens)
    #if rest:
    #     raise ValueError(f"Line {line_num}: Unexpected tokens in instruction: {' '.join(rest)}")

    return instruction_name, lhs, rhs

def is_int(s: str) -> bool:
    """Check if a string represents an integer."""
    try:
        int(s)
        return True
    except ValueError:
        return False

def derive_mod_field(lhs, rhs) -> str:
    """Derive the MOD field based on the operands."""
    if lhs in REGISTERS and rhs in REGISTERS:
        logger.debug("Register Mode (no displacement)")
        return MODFieldEncoding.REGISTER_TO_REGISTER.value
    
    if "[" in lhs or is_int(lhs):
        if rhs in _8BIT_REGS:
            logger.debug("Memory Mode, 8-bit displacement")
            return MODFieldEncoding.REGISTER_TO_MEMORY_8BIT_DISP.value
        elif rhs in _16BIT_REGS:
            logger.debug("Memory Mode, 16-bit displacement")
            return MODFieldEncoding.REGISTER_TO_MEMORY_16BIT_DISP.value
    
    if "[" in rhs or is_int(rhs):
        if lhs in _8BIT_REGS:
            logger.debug("Memory Mode, 8-bit displacement")
            return MODFieldEncoding.REGISTER_TO_MEMORY_8BIT_DISP.value
        elif lhs in _16BIT_REGS:
            logger.debug("Memory Mode, 16-bit displacement")
            return MODFieldEncoding.REGISTER_TO_MEMORY_16BIT_DISP.value
        
    logger.debug("Memory Mode, no displacement (except when R/M = 110, then 16-bit displacement)")
    return MODFieldEncoding.REGISTER_TO_MEMORY_NO_DISP.value

    

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
                        reg, w = inv_reg_field_encoding.get(rhs, (None, None))
                        if reg is None:
                            reg, w = inv_reg_field_encoding.get(lhs, (None, None))
                            
                        if reg is None:
                            reg = "000"
                            logger.debug("[MOV] Immediate to register/memory") # not necessarily, it could be dest addres calc

                            if "[" in rhs and "]" in rhs:
                               logger.debug("Src address calc required")
                               m = re.search(r'\[(.*?)\]', rhs)
                               if m:
                                in_brackets = m.group(1)
                                if in_brackets.count('+') == 1:
                                    src_add_calc_lhs, src_add_calc_rhs = in_brackets.split('+')
                                    reg = eff_addr_encoding.get((src_add_calc_lhs, src_add_calc_rhs))
                                elif in_brackets.count('+') == 2:
                                    src_add_calc_lhs, src_add_calc_rhs, disp = in_brackets.split('+')
                                    reg = eff_addr_encoding.get((src_add_calc_lhs, src_add_calc_rhs))
                                elif in_brackets in (REGISTERS.SI.value, REGISTERS.DI.value, REGISTERS.BX.value, REGISTERS.BP.value):
                                    reg = eff_addr_encoding.get((in_brackets, None))
                                else:
                                    raise ValueError(f"Line: {line_num}, Invalid instruction: {line}")
                            else:
                                int(rhs)
                        else:
                            logger.debug("[MOV] Register/memory to/from register") 
                            try:
                                if "[" in lhs:
                                    lhs = lhs.replace("[", "")
                                    lhs = lhs.replace("]", "")
                                    reg = eff_addr_encoding.get(tuple(lhs.split("+")))
                                else:
                                    reg = inv_reg_field_encoding[lhs][0]
                            except ValueError:
                                raise KeyError(f"Invalid register: {rhs}")
                        w = "1" if lhs[-1] == "x" else "0"
                        #rm, _ = inv_reg_field_encoding.get(lhs, tuple()) # rm != reg when disassembling. Is it relevant when assembling?
                    except KeyError as e:
                        logger.error("Line %d: Invalid register: %s", line_num, e)
                        sys.exit(1)

                    mov_type, left_shift = derive_mov_type(lhs, rhs)
                    opcode_int: int = int(mov_type, 2)  
                    d_int: int = 0  # direction: 0 = to REG
                    w_int: int = int(w, 2)  # width bit (0 or 1)
                    reg_int: int = int(reg, 2) 
                    #rm_int: int = int(rm, 2)
                    first_byte = 0
                    if mov_type == inv_instruction_map[Instructions.MOV][MOVTypes.RM_FT_R]:
                        first_byte: int = (opcode_int << left_shift) | (d_int << 1) | w_int # this only works for Register to register
                    elif mov_type == inv_instruction_map[Instructions.MOV][MOVTypes.I_T_RM]:
                        first_byte: int = (opcode_int << left_shift) | w_int | reg_int
                    mod_type = derive_mod_field(lhs, rhs)
                    mod_int: int = int(mod_type, 2)
                    second_byte: int = (mod_int << 6) | (reg_int << 3) #| rm_int

                    if not (0 <= first_byte <= 0xFF and 0 <= second_byte <= 0xFF):
                        logger.error("Line %d: Encoded bytes out of range: %d, %d", 
                                   line_num, first_byte, second_byte)
                        sys.exit(1)

                    output_bytes.extend([first_byte, second_byte])

                    debug_bin: str = format(first_byte, '08b') + format(second_byte, '08b')
                    logger.debug("Line %d: Encoded bytes (binary). First byte: %s, Second byte: %s", line_num, debug_bin[:8], debug_bin[8:])
                    logger.debug("Direction: %d, Width: %d", d_int, w_int)
                    logger.debug("Mode: %s, Reg: %s (%s)", 
                               mod_type, reg, rhs)
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
                    if instruction := instruction_map.get(opcode): # disassembly breaks here - re-visit this now that MOV may have diff opcodes
                        logger.debug("Instruction %d: Identified %s instruction", instruction_count, instruction.value)
                        
                        if is_mov_type(instruction):
                            instruction = "mov" # this must be wrong, the instruction type needs must need to be used at some point.
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