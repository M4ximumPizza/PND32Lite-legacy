# Instruction Set Architecture (ISA) Specification

## Overview

This document provides the complete ISA specification for the computer architecture simulator.

## Register File

### General Purpose Registers (R0-R12)
- 16-bit wide, general purpose storage
- No restrictions on usage
- Caller-saved by convention

### Special Registers
- **R13 (SP)**: Stack Pointer
- **R14 (LR)**: Link Register (stores return address)
- **R15 (PC)**: Program Counter

### Control Registers
- **CR0**: Flags and privilege level
  - Bits [0]: Privilege level (0=Kernel, 1=User)
  - Bits [3:1]: Comparison flags (equal, less, greater)
  - Bits [7:4]: Reserved

- **CR1**: Interrupt Vector Table base address

- **CR2**: User mode stack pointer (for context switching)

- **CR3**: Exception Program Counter (stores PC during exception)

## Instruction Encoding

### Format R (Register Operations)
```
31      26 25    22 21    18 17    14 13         0
[Opcode] [Rd]    [Rs1]   [Rs2]   [Reserved]
```

- **Opcode** (6 bits): Instruction type
- **Rd** (4 bits): Destination register
- **Rs1** (4 bits): Source register 1
- **Rs2** (4 bits): Source register 2

### Format I (Immediate Operations)
```
31      26 25    22 21    18 17              0
[Opcode] [Rd]    [Rs]    [Immediate (18-bit)]
```

- **Opcode** (6 bits): Instruction type
- **Rd** (4 bits): Destination register
- **Rs** (4 bits): Source register
- **Immediate** (18 bits): Sign-extended immediate value

### Format J (Jump Operations)
```
31      26 25                                0
[Opcode] [Target Address (26-bit)]
```

- **Opcode** (6 bits): Instruction type
- **Target** (26 bits): Jump target address

## Instruction Descriptions

### Category: No Operation

#### NOP (0x00)
```
Encoding: R-type with all zeros
Syntax:   NOP
Effect:   No operation, advances PC
Flags:    None
Cycles:   1
```

### Category: Halt/Control

#### HLT (0x01)
```
Encoding: R-type with all zeros
Syntax:   HLT
Effect:   Stops CPU execution
Flags:    Sets running flag to 0
Cycles:   1 (final)
```

### Category: Data Movement

#### MOV (0x02)
```
Encoding: R-type
Syntax:   MOV Rd, Rs1
Effect:   Rd ← Rs1
Flags:    None
Cycles:   1
```

#### MOVI (0x03)
```
Encoding: I-type
Syntax:   MOVI Rd, Imm
Effect:   Rd ← sign_extend_18(Imm)
Flags:    None
Cycles:   1
Range:    -131072 to 131071
```

#### MOVIH (0x04)
```
Encoding: I-type
Syntax:   MOVIH Rd, Imm
Effect:   Rd[47:30] ← Imm (high half load)
Flags:    None
Cycles:   1
```

### Category: Arithmetic Operations

#### ADD (0x09)
```
Encoding: R-type
Syntax:   ADD Rd, Rs1, Rs2
Effect:   Rd ← Rs1 + Rs2
Flags:    Carry, Overflow (if supported)
Cycles:   1
Overflow: Wraps on overflow (modulo 2^64)
```

#### ADDI (0x0A)
```
Encoding: I-type
Syntax:   ADDI Rd, Rs, Imm
Effect:   Rd ← Rs + sign_extend_18(Imm)
Flags:    Carry, Overflow
Cycles:   1
```

#### SUB (0x0B)
```
Encoding: R-type
Syntax:   SUB Rd, Rs1, Rs2
Effect:   Rd ← Rs1 - Rs2
Flags:    Carry, Borrow
Cycles:   1
```

#### SUBI (0x0C)
```
Encoding: I-type
Syntax:   SUBI Rd, Rs, Imm
Effect:   Rd ← Rs - sign_extend_18(Imm)
Flags:    Carry, Borrow
Cycles:   1
```

#### MUL (0x0D)
```
Encoding: R-type
Syntax:   MUL Rd, Rs1, Rs2
Effect:   Rd ← Rs1 * Rs2 (lower 64 bits)
Flags:    Overflow (if result exceeds 64 bits)
Cycles:   3 (pipelined)
Note:     Unsigned multiplication
```

#### MULI (0x0E)
```
Encoding: I-type
Syntax:   MULI Rd, Rs, Imm
Effect:   Rd ← Rs * sign_extend_18(Imm)
Flags:    Overflow
Cycles:   3 (pipelined)
```

#### DIV (0x0F)
```
Encoding: R-type
Syntax:   DIV Rd, Rs1, Rs2
Effect:   Rd ← Rs1 / Rs2 (integer division)
Flags:    Division by zero → exception
Cycles:   5 (iterative)
Note:     Signed integer division
Exception: EXC_ILLEGAL_OP on divide by zero
```

#### DIVI (0x10)
```
Encoding: I-type
Syntax:   DIVI Rd, Rs, Imm
Effect:   Rd ← Rs / sign_extend_18(Imm)
Flags:    Division by zero → exception
Cycles:   5
```

#### MOD (0x11)
```
Encoding: R-type
Syntax:   MOD Rd, Rs1, Rs2
Effect:   Rd ← Rs1 % Rs2 (modulo operation)
Flags:    Division by zero → exception
Cycles:   5
```

#### MODI (0x12)
```
Encoding: I-type
Syntax:   MODI Rd, Rs, Imm
Effect:   Rd ← Rs % sign_extend_18(Imm)
Flags:    Division by zero → exception
Cycles:   5
```

### Category: Logic Operations

#### AND (0x13)
```
Encoding: R-type
Syntax:   AND Rd, Rs1, Rs2
Effect:   Rd ← Rs1 & Rs2 (bitwise AND)
Flags:    Zero flag
Cycles:   1
```

#### ANDI (0x14)
```
Encoding: I-type
Syntax:   ANDI Rd, Rs, Imm
Effect:   Rd ← Rs & Imm
Flags:    Zero flag
Cycles:   1
```

#### OR (0x15)
```
Encoding: R-type
Syntax:   OR Rd, Rs1, Rs2
Effect:   Rd ← Rs1 | Rs2 (bitwise OR)
Flags:    Zero flag
Cycles:   1
```

#### ORI (0x16)
```
Encoding: I-type
Syntax:   ORI Rd, Rs, Imm
Effect:   Rd ← Rs | Imm
Flags:    Zero flag
Cycles:   1
```

#### XOR (0x17)
```
Encoding: R-type
Syntax:   XOR Rd, Rs1, Rs2
Effect:   Rd ← Rs1 ^ Rs2 (bitwise XOR)
Flags:    Zero flag
Cycles:   1
```

#### XORI (0x18)
```
Encoding: I-type
Syntax:   XORI Rd, Rs, Imm
Effect:   Rd ← Rs ^ Imm
Flags:    Zero flag
Cycles:   1
```

#### NOT (0x19)
```
Encoding: R-type
Syntax:   NOT Rd, Rs1
Effect:   Rd ← ~Rs1 (bitwise NOT)
Flags:    Zero flag
Cycles:   1
```

### Category: Shift Operations

#### SHL (0x1A)
```
Encoding: R-type
Syntax:   SHL Rd, Rs1, Rs2
Effect:   Rd ← Rs1 << Rs2 (logical shift left)
Flags:    Carry flag (last bit shifted out)
Cycles:   1
Note:     Shifts by Rs2 amount, zero-fills
```

#### SRL (0x1B)
```
Encoding: R-type
Syntax:   SRL Rd, Rs1, Rs2
Effect:   Rd ← Rs1 >> Rs2 (logical shift right)
Flags:    Carry flag
Cycles:   1
Note:     Zero-fills on right
```

#### SAR (0x1C)
```
Encoding: R-type
Syntax:   SAR Rd, Rs1, Rs2
Effect:   Rd ← Rs1 >> Rs2 (arithmetic shift right)
Flags:    Carry flag
Cycles:   1
Note:     Sign-extends on right
```

#### SRA (0x3D)
```
Encoding: R-type
Syntax:   SRA Rd, Rs1, Rs2
Effect:   Rd ← Rs1 >> Rs2 (register shift right arithmetic)
Flags:    Carry flag
Cycles:   1
```

### Category: Memory Operations

#### LDR (0x1D)
```
Encoding: I-type
Syntax:   LDR Rd, Rs, Imm
Effect:   Rd ← Mem[Rs + sign_extend_18(Imm)] (word)
Flags:    None (exception on fault)
Cycles:   3 (load-to-use latency)
Access:   Read word (4 bytes)
Exception: EXC_MEM_FAULT on invalid address
```

#### STR (0x1E)
```
Encoding: I-type
Syntax:   STR Rd, Rs, Imm
Effect:   Mem[Rs + sign_extend_18(Imm)] ← Rd (word)
Flags:    None (exception on fault)
Cycles:   3
Access:   Write word (4 bytes)
Exception: EXC_MEM_FAULT on invalid address
```

#### LDB (0x1F)
```
Encoding: I-type
Syntax:   LDB Rd, Rs, Imm
Effect:   Rd ← Mem[Rs + sign_extend_18(Imm)] (byte, zero-extended)
Flags:    None
Cycles:   3
Access:   Read byte (1 byte), zero-extend to 64 bits
```

#### STB (0x20)
```
Encoding: I-type
Syntax:   STB Rd, Rs, Imm
Effect:   Mem[Rs + sign_extend_18(Imm)] ← Rd[7:0] (byte)
Flags:    None
Cycles:   3
Access:   Write byte (1 byte)
```

#### LDH (0x31)
```
Encoding: I-type
Syntax:   LDH Rd, Rs, Imm
Effect:   Rd ← Mem[Rs + sign_extend_18(Imm)] (half-word, zero-extended)
Flags:    None
Cycles:   3
Access:   Read half-word (2 bytes)
```

#### STH (0x32)
```
Encoding: I-type
Syntax:   STH Rd, Rs, Imm
Effect:   Mem[Rs + sign_extend_18(Imm)] ← Rd[15:0] (half-word)
Flags:    None
Cycles:   3
Access:   Write half-word (2 bytes)
```

#### LDRS (0x38)
```
Encoding: I-type
Syntax:   LDRS Rd, Rs, Imm
Effect:   Rd ← sign_extend(Mem[Rs + Imm]) (word, signed)
Flags:    None
Cycles:   3
Note:     Sign-extends loaded value
```

#### LDBS (0x39)
```
Encoding: I-type
Syntax:   LDBS Rd, Rs, Imm
Effect:   Rd ← sign_extend(Mem[Rs + Imm][7:0]) (byte, signed)
Flags:    None
Cycles:   3
```

#### LDHS (0x3A)
```
Encoding: I-type
Syntax:   LDHS Rd, Rs, Imm
Effect:   Rd ← sign_extend(Mem[Rs + Imm][15:0]) (half-word, signed)
Flags:    None
Cycles:   3
```

#### PUSH (0x21)
```
Encoding: R-type
Syntax:   PUSH Rs
Effect:   Mem[--SP] ← Rs; SP decremented by 8
Flags:    None
Cycles:   3
Note:     Pre-decrement stack pointer
```

#### POP (0x22)
```
Encoding: R-type
Syntax:   POP Rd
Effect:   Rd ← Mem[SP]; SP incremented by 8
Flags:    None
Cycles:   3
Note:     Post-increment stack pointer
```

#### LEA (0x24)
```
Encoding: I-type
Syntax:   LEA Rd, Rs, Imm
Effect:   Rd ← Rs + sign_extend_18(Imm) (no memory access)
Flags:    None
Cycles:   1
Note:     Load Effective Address - useful for address computation
```

### Category: Comparison

#### CMP (0x25)
```
Encoding: R-type
Syntax:   CMP Rs1, Rs2
Effect:   Sets comparison flags based on Rs1 - Rs2
Flags:    Equal, Less, Greater (in CR0[3:1])
Cycles:   1
Note:     Does not modify registers, only sets flags
```

#### CMPI (0x26)
```
Encoding: I-type
Syntax:   CMPI Rs, Imm
Effect:   Sets comparison flags based on Rs - Imm
Flags:    Equal, Less, Greater
Cycles:   1
Note:     Immediate compared is sign-extended
```

### Category: Branch Operations

#### B (0x27)
```
Encoding: J-type
Syntax:   B Target
Effect:   PC ← Target
Flags:    None
Cycles:   1 (+ pipeline flush)
Note:     Unconditional absolute branch
Prediction: BTB entry updated
```

#### BL (0x2C)
```
Encoding: J-type
Syntax:   BL Target
Effect:   LR ← PC + 4; PC ← Target
Flags:    None
Cycles:   1 (+ pipeline flush)
Note:     Branch and Link - subroutine call
```

#### BEQ (0x28)
```
Encoding: I-type (target is offset)
Syntax:   BEQ Offset
Effect:   If equal flag set: PC ← PC + Offset
Flags:    None (reads equal flag)
Cycles:   1 or 3 (depends on branch taken)
Note:     Relative branch, 18-bit signed offset
```

#### BNE (0x29)
```
Encoding: I-type
Syntax:   BNE Offset
Effect:   If not equal flag set: PC ← PC + Offset
Flags:    None
Cycles:   1 or 3
```

#### BGT (0x2A)
```
Encoding: I-type
Syntax:   BGT Offset
Effect:   If greater flag set: PC ← PC + Offset
Flags:    None
Cycles:   1 or 3
```

#### BGE (0x37)
```
Encoding: I-type
Syntax:   BGE Offset
Effect:   If greater-or-equal flag set: PC ← PC + Offset
Flags:    None
Cycles:   1 or 3
```

#### BLT (0x2B)
```
Encoding: I-type
Syntax:   BLT Offset
Effect:   If less flag set: PC ← PC + Offset
Flags:    None
Cycles:   1 or 3
```

#### BLE (0x36)
```
Encoding: I-type
Syntax:   BLE Offset
Effect:   If less-or-equal flag set: PC ← PC + Offset
Flags:    None
Cycles:   1 or 3
```

#### BX (0x2D)
```
Encoding: R-type
Syntax:   BX Rs1
Effect:   PC ← Rs1
Flags:    None
Cycles:   1 (+ pipeline flush)
Note:     Indirect branch via register
```

#### BLX (0x2E)
```
Encoding: R-type
Syntax:   BLX Rs1
Effect:   LR ← PC + 4; PC ← Rs1
Flags:    None
Cycles:   1 (+ pipeline flush)
Note:     Indirect branch and link
```

#### JALR (0x3C)
```
Encoding: I-type
Syntax:   JALR Rd, Rs, Imm
Effect:   Rd ← PC + 4; PC ← Rs + Imm
Flags:    None (ROP check if Rd=LR)
Cycles:   1 (+ pipeline flush)
Note:     Jump and Link Register with offset
Security: Shadow stack validation if Rs=LR
```

### Category: Exception Handling

#### SVC (0x2F)
```
Encoding: J-type
Syntax:   SVC Imm
Effect:   Triggers supervisor call exception
Flags:    Switches to kernel mode
Cycles:   3 (exception handler latency)
Exception: EXC_SYS_CALL
Vector:   CR1 + EXC_SYS_CALL
```

#### SYS (0x3E)
```
Encoding: J-type
Syntax:   SYS
Effect:   Triggers system exception
Flags:    Switches to kernel mode
Cycles:   3
Exception: EXC_SYS_CALL (generic system call)
```

#### RFE (0x30)
```
Encoding: R-type
Syntax:   RFE
Effect:   PC ← CR3 (EPC); Restores user mode
Flags:    Privilege ← User
Cycles:   1 (+ pipeline flush)
Privilege: Kernel only
Exception: EXC_PRIV_VIOL if user mode
```

#### ERET (0x3F)
```
Encoding: R-type
Syntax:   ERET
Effect:   PC ← CR3; Return from exception
Flags:    Restores previous privilege
Cycles:   1 (+ pipeline flush)
Privilege: Kernel only
Note:     Alternative to RFE
```

### Category: Control Register Operations

#### MCR (0x05)
```
Encoding: R-type
Syntax:   MCR Rd, Rs1
Effect:   CR[Rd] ← Rs1 (write to control register)
Flags:    None
Cycles:   1
Privilege: Kernel only
Exception: EXC_PRIV_VIOL if user mode
```

#### MRC (0x06)
```
Encoding: R-type
Syntax:   MRC Rd, Rs1
Effect:   Rd ← CR[Rs1] (read from control register)
Flags:    None
Cycles:   1
Privilege: Kernel only
Exception: EXC_PRIV_VIOL if user mode
```

#### IEV (0x35)
```
Encoding: R-type
Syntax:   IEV
Effect:   Sets interrupt vector table address
Flags:    None
Cycles:   1
Privilege: Kernel only
```

#### CLI (0x33)
```
Encoding: R-type
Syntax:   CLI
Effect:   Disables hardware interrupts
Flags:    Interrupt enable flag ← 0
Cycles:   1
Privilege: Kernel only
Exception: EXC_PRIV_VIOL if user mode
```

#### STI (0x34)
```
Encoding: R-type
Syntax:   STI
Effect:   Enables hardware interrupts
Flags:    Interrupt enable flag ← 1
Cycles:   1
Privilege: Kernel only
Exception: EXC_PRIV_VIOL if user mode
```

#### TLBIV (0x23)
```
Encoding: R-type
Syntax:   TLBIV
Effect:   Invalidates all TLB entries
Flags:    None
Cycles:   1
Privilege: Kernel only
Exception: EXC_PRIV_VIOL if user mode
```

### Category: Security Operations

#### CPYT (0x07)
```
Encoding: R-type
Syntax:   CPYT Rd, Rs1
Effect:   Rd_taint ← Rs1_taint (copy taint metadata)
Flags:    None
Cycles:   1
Note:     Out-of-band taint propagation
```

#### CLRT (0x08)
```
Encoding: R-type
Syntax:   CLRT Rd
Effect:   Clear taint flag on Rd
Flags:    None
Cycles:   1
Note:     Marks register as untainted
```

#### CLZ (0x3B)
```
Encoding: R-type
Syntax:   CLZ Rd, Rs1
Effect:   Rd ← count_leading_zeros(Rs1)
Flags:    None
Cycles:   1
Note:     Counts leading zero bits
```

## Exception Vector Table

The exception vector table is located at address CR1 with the following offsets:

| Offset | Exception | Number | Cause |
|--------|-----------|--------|-------|
| 0      | Memory Fault | 0 | Invalid memory access |
| 4      | Illegal Opcode | 1 | Undefined instruction |
| 8      | Privilege Violation | 2 | User mode privileged instruction |
| 12     | Syscall | 3 | SVC or SYS instruction |
| 16     | Taint Fault | 4 | Tainted data security violation |
| 20     | NX Fault | 5 | Execute from non-executable memory |
| 24     | CFI Fault | 6 | Control flow integrity violation |
| 28     | MTE Fault | 7 | Memory tag mismatch |
| 32     | Page Fault | 8 | Virtual memory translation miss |

## Encoding Rules

### Immediate Sign-Extension
All 18-bit immediates are sign-extended to 64 bits:
```c
int64_t sign_extend_18bit(int64_t imm) {
    imm &= 0x3FFFF;           // Mask to 18 bits
    if (imm & 0x020000) {     // Check sign bit
        imm |= 0xFFFFFFFFFFFC0000LL;  // Fill with 1s
    }
    return imm;
}
```

### Register Operands
- Registers are specified as 0-15 (R0-R15)
- Invalid registers cause assembly error
- Assembler validates register ranges

### Immediate Ranges
- **I-type**: -131,072 to 131,071 (18-bit signed)
- **J-type**: 0 to 67,108,863 (26-bit unsigned)

## Assembler Syntax

### Labels
```
label:     # Defines a label at current address
BL label   # References the label
```

### Comments
```
; This is a comment (to end of line)
```

### Operand Syntax
```
register:     R0-R15
immediate:    123, 0x1A, 0b1010, -456
```

### Examples
```asm
start:
    MOVI R0, 100     ; Load 100 into R0
    ADD R1, R0, R0   ; Add R0 to itself
    BL loop
    HLT
loop:
    ...
```

---

**Note**: This ISA is designed for educational purposes and includes advanced security features for studying modern architecture protection mechanisms.
