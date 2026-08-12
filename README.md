# Pandimonium 32 bit (PND32 Lite)

This project is a computer architecture simulator featuring a fully implemented ISA, assembler, and disassembler. It was designed primarily for educational purposes and security research whiched provided me a platform for experimenting with processor architecture, instruction sets, and hardware-level security concepts.

Development of this third-generation version has been discontinued in favor of a new architecture, **PNDX**, with the fourth generation planned as **PNDX-64**.

The third-generation simulator has several limitations and architectural issues that led to its retirement. The full, non-Lite version includes additional hardware simulation features, such as a functional branch predictor and a simulated LED display rather than relying solely on terminal-based output. These features, along with other planned improvements, are being carried forward into the next generation of the architecture. The lite implys that it does not have a functional drawable screen along with more advanced decoding and lack of more atomic instructions.

## Features

- **Custom ISA**: 64 instructions covering arithmetic, logic, memory, control flow, and security
- **5-Stage Pipeline**: IF, ID, EX, MEM, WB with hazard detection
- **Security Features**:
  - ROP (Return-Oriented Programming) protection via shadow stack
  - CFI (Control-Flow Integrity) enforcement
  - Taint tracking for data flow analysis
  - MTE (Memory Tagging Extension)
  - Virtual memory with MMU and TLB
  - Privilege levels (Kernel/User)

- **Assembler**: Complete two-pass assembler with proper error reporting
- **Disassembler**: Full binary-to-assembly translation\

## Building

### Requirements
- GCC (or compatible C compiler)
- Make
- Bash (for test suite)

### Compilation
```bash
make              # Build release version
```

### Output
- `assembler` - Assembler binary
- `diassembler` - Disassembler binary
- `main` - Binary

## Usage

### Assembling Code
```bash
./assembler program.asm program.bin
```

### Disassembling Binaries
```bash
./disassembler program.bin
```

## ISA Architecture

### Instruction Formats

#### R-Type (Register)
```
Bits [31:26] - Opcode (6 bits)
Bits [25:22] - Destination Register (4 bits)
Bits [21:18] - Source Register 1 (4 bits)
Bits [17:14] - Source Register 2 (4 bits)
Bits [13:0]  - Reserved
```

Operations: ADD, SUB, MUL, DIV, MOD, AND, OR, XOR, SHL, SRL, SAR, etc.

#### I-Type (Immediate)
```
Bits [31:26] - Opcode (6 bits)
Bits [25:22] - Destination Register (4 bits)
Bits [21:18] - Source Register (4 bits)
Bits [17:0]  - Immediate (18 bits, sign-extended)
```

Operations: ADDI, SUBI, MOVI, LDR, STR, LDB, STB, CMPI, Conditional Branches, etc.

#### J-Type (Jump/Target)
```
Bits [31:26] - Opcode (6 bits)
Bits [25:0]  - Target Address (26 bits)
```

Operations: B, BL, SVC, SYS, etc.

### Register File

| Register | Name | Purpose |
|----------|------|---------|
| R0-R12 | General Purpose | User data storage |
| R13 | SP | Stack Pointer |
| R14 | LR | Link Register (return address) |
| R15 | PC | Program Counter |

### Control Registers

| Register | Name | Purpose |
|----------|------|---------|
| CR0 | Flags | Status flags and privilege level |
| CR1 | IVT | Interrupt Vector Table base |
| CR2 | User SP | User mode stack pointer |
| CR3 | EPC | Exception Program Counter |

## Examples

### Example 1: Simple Arithmetic
```asm
start:
    MOVI R0, 10          ; Load 10 into R0
    MOVI R1, 20          ; Load 20 into R1
    ADD R2, R0, R1       ; R2 = 30
    HLT                  ; Halt
```

### Example 2: Branching
```asm
start:
    MOVI R0, 5
    MOVI R1, 3
    CMP R0, R1
    BGT greater
    MOVI R2, 0
    B end
greater:
    MOVI R2, 1
end:
    HLT
```

### Example 3: Bitwise Operations
```asm
start:
    MOVI R0, 0xFF
    MOVI R1, 0x0F
    AND R2, R0, R1       ; R2 = 0x0F
    OR R3, R0, R1        ; R3 = 0xFF
    XOR R4, R0, R1       ; R4 = 0xF0
    HLT
```

## Instruction Set Reference

### Arithmetic Operations
- `ADD Rd, Rs1, Rs2` - Rd = Rs1 + Rs2
- `ADDI Rd, Rs, Imm` - Rd = Rs + Imm
- `SUB Rd, Rs1, Rs2` - Rd = Rs1 - Rs2
- `SUBI Rd, Rs, Imm` - Rd = Rs - Imm
- `MUL Rd, Rs1, Rs2` - Rd = Rs1 * Rs2
- `MULI Rd, Rs, Imm` - Rd = Rs * Imm
- `DIV Rd, Rs1, Rs2` - Rd = Rs1 / Rs2
- `DIVI Rd, Rs, Imm` - Rd = Rs / Imm
- `MOD Rd, Rs1, Rs2` - Rd = Rs1 % Rs2
- `MODI Rd, Rs, Imm` - Rd = Rs % Imm

### Logic Operations
- `AND Rd, Rs1, Rs2` - Rd = Rs1 & Rs2
- `ANDI Rd, Rs, Imm` - Rd = Rs & Imm
- `OR Rd, Rs1, Rs2` - Rd = Rs1 | Rs2
- `ORI Rd, Rs, Imm` - Rd = Rs | Imm
- `XOR Rd, Rs1, Rs2` - Rd = Rs1 ^ Rs2
- `XORI Rd, Rs, Imm` - Rd = Rs ^ Imm
- `NOT Rd, Rs1` - Rd = ~Rs1

### Shift Operations
- `SHL Rd, Rs1, Rs2` - Rd = Rs1 << Rs2
- `SRL Rd, Rs1, Rs2` - Rd = Rs1 >> Rs2 (logical)
- `SAR Rd, Rs1, Rs2` - Rd = Rs1 >> Rs2 (arithmetic)
- `SRA Rd, Rs1, Rs2` - Rd = Rs1 >> Rs2 (register)

### Memory Operations
- `LDR Rd, Rs, Imm` - Rd = Mem[Rs + Imm] (word)
- `STR Rd, Rs, Imm` - Mem[Rs + Imm] = Rd (word)
- `LDB Rd, Rs, Imm` - Rd = Mem[Rs + Imm] (byte, zero-ext)
- `STB Rd, Rs, Imm` - Mem[Rs + Imm] = Rd (byte)
- `LDH Rd, Rs, Imm` - Rd = Mem[Rs + Imm] (half-word)
- `STH Rd, Rs, Imm` - Mem[Rs + Imm] = Rd (half-word)

### Control Flow
- `B Target` - Unconditional branch
- `BL Target` - Branch and link (subroutine call)
- `BEQ Offset` - Branch if equal
- `BNE Offset` - Branch if not equal
- `BGT Offset` - Branch if greater than
- `BGE Offset` - Branch if greater or equal
- `BLT Offset` - Branch if less than
- `BLE Offset` - Branch if less or equal
- `BX Rs1` - Branch indirect (PC = Rs1)
- `BLX Rs1` - Branch and link indirect
- `JALR Rd, Rs1, Imm` - Jump and link with register
- `RFE` - Return from exception
- `ERET` - Exception return

### System Operations
- `NOP` - No operation
- `HLT` - Halt execution
- `MOV Rd, Rs1` - Rd = Rs1
- `MOVI Rd, Imm` - Rd = Imm (sign-extended)
- `MOVIH Rd, Imm` - Rd[47:30] = Imm (high half)
- `LEA Rd, Rs, Imm` - Rd = Rs + Imm (address)
- `CMP Rs1, Rs2` - Set flags (Rs1 vs Rs2)
- `CMPI Rs, Imm` - Set flags (Rs vs Imm)
- `PUSH Rs` - Push register to stack
- `POP Rd` - Pop stack to register
- `CLZ Rd, Rs1` - Rd = count leading zeros in Rs1
- `SVC Imm` - Supervisor call
- `SYS` - System call
- `MCR Rd, Rs1` - Control register write
- `MRC Rd, Rs1` - Control register read
- `CLI` - Clear interrupts
- `STI` - Set interrupts
- `TLBIV` - Invalidate TLB

### Security Operations
- `CPYT Rd, Rs1` - Copy taint from Rs1 to Rd
- `CLRT Rd` - Clear taint on Rd

## Documentation

### ISA Specification
See `ISA.md` for detailed instruction set documentation.

### Architecture Overview
See `ARCHITECTURE.md` for pipeline details, security features, and memory layout.

## Security Considerations

This simulator implements several security features:

1. **Shadow Stack (ROP Protection)**
   - Maintains parallel stack for return addresses
   - Validates return target against shadow stack

2. **CFI (Control-Flow Integrity)**
   - Enforces landing pad checks on indirect calls
   - Detects non-sanctioned branch targets

3. **Taint Tracking**
   - Tracks data flow from untrusted sources
   - Prevents use of tainted data in sensitive operations

4. **Virtual Memory**
   - MMU with TLB for address translation
   - Per-page permissions (read/write/execute)
   - Privilege level isolation

5. **MTE (Memory Tagging Extension)**
   - 4-bit tags per 16-byte granule
   - Detects use-after-free and buffer overflow

## Performance Notes

- All operations are single-cycle except load/store (3 cycles)
- Branch prediction via 64-entry Branch Target Buffer
- Hazard detection prevents data corruption
- No speculative execution (for simplicity)

## License

Open Source - See LICENSE file
