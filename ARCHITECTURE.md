# Computer Architecture - System Design

This document describes the architecture, design decisions, and implementation details of the computer architecture lab.

## System Components

### 1. Assembler (compiler.c)
Converts human-readable assembly language to binary machine code.

#### Two-Pass Assembly
- **Pass 1**: Tokenization and symbol table construction
  - Scan all instructions
  - Collect label definitions
  - Validate syntax
  
- **Pass 2**: Code generation
  - Resolve all label references
  - Generate binary instructions
  - Output to binary file

#### Features
- Proper error reporting with line numbers
- Label resolution for branches
- Three instruction formats (R, I, J)
- Sign-extended 18-bit immediates

### 2. Disassembler (decompiler.c)
Converts binary machine code back to assembly language.

#### Decoding Process
1. Read 32-bit instruction
2. Extract opcode (bits 31:26)
3. Determine instruction format
4. Extract operands based on format
5. Print assembly representation

#### Features
- Consistent with assembler encoding
- Proper sign-extension of immediates
- Supports all 64 instructions
- Clean formatted output

### 3. Instruction Pipeline

The CPU implements a classic 5-stage pipeline:

```
┌─────┐
│ IF  │  Instruction Fetch
├─────┤
│ ID  │  Instruction Decode
├─────┤
│ EX  │  Execute
├─────┤
│ MEM │  Memory Access
├─────┤
│ WB  │  Write Back
└─────┘
```

#### Stage Details

##### Instruction Fetch (IF)
- Reads instruction from memory at PC
- Checks memory protection
- Updates PC
- Supports branch prediction via BTB

##### Instruction Decode (ID)
- Extracts opcode and operands
- Performs privilege checks
- Detects data hazards
- Performs taint security checks

##### Execute (EX)
- Performs arithmetic/logic operations
- Calculates addresses
- Handles branches and jumps
- Maintains shadow stack for ROP protection

##### Memory (MEM)
- Performs load/store operations
- Accesses virtual memory
- Handles memory protection
- Supports MTE (memory tagging)

##### Write Back (WB)
- Writes results to register file
- Updates program counter
- Commits instruction

#### Pipeline Hazards

**Data Hazards (Load-to-Use)**
```c
LDR R1, R0, 0    /* Load from R0 into R1 */
ADD R2, R1, R3   /* Use R1 - HAZARD! */
```

Solution: Stall pipeline for 1 cycle

**Control Hazards (Branches)**
```c
BEQ R0, R1, target
NOP               /* Delay slot simulation */
ADD R2, R3, R4
```

Solution: Flush pipeline on branch, use BTB for prediction

**Implementation**
```c
/* Hazard Detection Unit */
if (cpu.id_ex.active && op_is_load(cpu.id_ex.op)) {
    if (cpu.id_ex.rd == rs1 || cpu.id_ex.rd == rs2) {
        cpu.hazard_stall = 1;  /* Insert bubble */
    }
}
```

## Memory Architecture

### Memory Layout

```
Address Space (40KB Sandbox)
┌─────────────────┐
│  0x0000-0x1FFF  │  Kernel Space (8KB, protected)
├─────────────────┤
│  0x2000-0x9FFF  │  User Space (28KB)
├─────────────────┤
│  0xA000-0xFFFF  │  Reserved/Available
└─────────────────┘
```

### Memory Protection Unit (MPU)

Per-byte permission tracking:
- **Read**: Accessible for loads
- **Write**: Accessible for stores
- **Execute**: Can fetch instructions

### Virtual Memory (MMU/TLB)

**Address Translation**
```
Virtual Address (64-bit)
│ Page Number (52) │ Offset (12) │
        ↓
    TLB Lookup
        ↓
Physical Address (40-bit)
│ Frame Number (28) │ Offset (12) │
```

**TLB Structure**
- 32 entries
- 2-level page table hierarchy
- LRU replacement policy
- Per-process translation

### Memory Tagging Extension (MTE)

**Granule-Based Tagging**
- 16-byte granules
- 4-bit tags per granule
- 2 tags packed per byte
- Total: 2560 granules × 4 bits = 1280 bytes tag storage

**Tag Storage**
```c
memory_tags[MTE_TAG_TABLE_SIZE]    /* Metadata */
register_mte_tags[NUM_REGISTERS]   /* Register tags */
```

## Security Architecture

### 1. Shadow Stack (ROP Protection)

**Purpose**: Protect return addresses from tampering

**Implementation**
```c
int64_t shadow_stack[1024];
int ssp;  /* Shadow Stack Pointer */

/* On function call (BL/JALR with LR) */
shadow_stack[ssp++] = pc + 4;

/* On function return (via LR) */
if (ssp > 0) {
    expected = shadow_stack[--ssp];
    if (actual_return != expected) {
        trigger_exception(cpu, EXC_ROP_FAULT, pc);
    }
}
```

### 2. Control-Flow Integrity (CFI)

**Purpose**: Enforce valid indirect branch targets

**Landing Pads**
- Marked with NOP at target location
- Checked before indirect calls
- Prevents jumps to arbitrary code

**Implementation**
```c
if (target_addr is valid) {
    read target_instruction();
    if (target_op != OP_NOP) {
        trigger_exception(cpu, EXC_CFI_FAULT, pc);
    }
}
```

### 3. Taint Tracking

**Purpose**: Track data flow from untrusted sources

**Per-Register Taint Bits**
```c
uint8_t taint_regs[NUM_REGISTERS];  /* 1 bit per register */

/* Propagate taint on operations */
if (taint_regs[rs1] || taint_regs[rs2]) {
    taint_regs[rd] = 1;
}

/* Block tainted pointers */
if (taint_regs[rs] && op_is_memory(op)) {
    trigger_exception(cpu, EXC_TAINT_FAULT, pc);
}
```

### 4. Pointer Authentication Code (PAC)

**Purpose**: Detect pointer corruption

**Key Storage**
```c
typedef struct {
    uint64_t key;
    int valid;
} PACKey;

PACKey pac_keys[4];
uint64_t pac_nonce = 0xDEADBEEFCAFEBABE;
```

### 5. Privilege Level Isolation

**Kernel Mode (Ring 0)**
- Full hardware access
- Can execute privileged instructions
- Can access memory protection registers
- Can modify interrupt handling

**User Mode (Ring 1)**
- Restricted instruction set
- Separate stack pointer
- Memory access controlled by MPU
- Cannot disable interrupts or modify control registers

**Enforcement**
```c
if (get_privilege_level(cpu) == PRIV_USER) {
    if (op == OP_MCR || op == OP_RFE || op == OP_CLI || 
        op == OP_STI || op == OP_IEV || op == OP_TLBIV) {
        trigger_exception(cpu, EXC_PRIV_VIOL, pc);
    }
}
```

## Control Registers

### CR0: Status and Flags
```
Bits [0]:     Privilege level (0=Kernel, 1=User)
Bits [3:1]:   Comparison flags (EQ, LT, GT)
Bits [4]:     Interrupt enable flag
Bits [7:5]:   Reserved
```

### CR1: Interrupt Vector Table
- Base address of exception handlers
- Aligned to 32-byte boundary
- Provides offsets for each exception type

### CR2: User Stack Pointer
- Alternate stack pointer for user mode
- Swapped when entering/leaving user mode
- Protects kernel stack from user access

### CR3: Exception Program Counter
- Saved PC when exception occurs
- Used by RFE to return from exception
- Set by exception handler entry

## Exception Handling

### Exception Types

| Vector | Offset | Exception | Handler |
|--------|--------|-----------|---------|
| 0 | 0 | Memory Fault | Access violation |
| 1 | 4 | Illegal Opcode | Undefined instruction |
| 2 | 8 | Privilege Violation | User mode privileged op |
| 3 | 12 | Syscall | SVC/SYS instruction |
| 4 | 16 | Taint Fault | Security violation |
| 5 | 20 | NX Fault | Execute from non-exec |
| 6 | 24 | CFI Fault | Invalid indirect branch |
| 7 | 28 | MTE Fault | Tag mismatch |
| 8 | 32 | Page Fault | Virtual memory miss |

### Exception Entry Sequence

```c
void trigger_exception(CPUContext *cpu, int exc_type, int64_t fault_addr) {
    /* Save exception context */
    cpu->cr[3] = cpu->regs[15];  /* Save PC in EPC */
    cpu->cr[2] = cpu->regs[13];  /* Save SP */
    
    /* Get handler address from IVT */
    int64_t handler = cpu->cr[1] + exc_type;
    
    /* Jump to handler */
    cpu->regs[15] = handler;
    
    /* Switch to kernel mode */
    cpu->cr[0] &= ~PRIV_USER;
    
    /* Flush pipeline */
    cpu->control_flush = 1;
}
```

### Exception Return

```asm
RFE                  /* Load PC from CR3 */
                     /* Switch to user mode */
                     /* Restore stack pointer */
```

## Performance Metrics

### Cycle Counting
```c
typedef struct {
    unsigned long total_cycles;
    unsigned long cache_hits;
    unsigned long cache_misses;
    unsigned long btb_hits;
    unsigned long btb_misses;
    unsigned long speculative_exec;
    unsigned long mispredicted_branches;
} SideChannelMetrics;
```

### Tracking

- Each instruction increments cycle counter
- Loads add 2 additional cycles
- Branches add pipeline flush penalty
- Branch prediction tracked for analysis

## Design Decisions

### 1. Fixed Register File
**Decision**: 16 registers (R0-R15)

**Rationale**:
- Sufficient for typical workloads
- 4-bit encoding in instructions
- Matches common ISAs (ARM, RISC-V)
- Balance between expressiveness and encoding

### 2. 18-Bit Immediate Field
**Decision**: Sign-extended 18-bit immediates

**Rationale**:
- Covers -131K to +131K range
- Sufficient for most constants
- Leaves room for other instruction fields
- Sign-extension handles both positive/negative

### 3. 5-Stage Pipeline
**Decision**: Classic IF, ID, EX, MEM, WB stages

**Rationale**:
- Good balance of complexity vs. throughput
- Educational clarity
- Allows hazard demonstration
- Manageable complexity for simulation

### 4. Memory Sandbox
**Decision**: 40KB isolated memory space (Just a temp size. Could be much bigger)

**Rationale**:
- Large enough for meaningful programs
- Small enough for simulation performance
- Prevents memory exhaustion attacks
- Allows per-byte permission tracking

### 5. Security-First Design
**Decision**: Include ROP, CFI, taint, MTE from start

**Rationale**:
- Teaches modern security concepts
- Research-relevant protection mechanisms
- Can be disabled for baseline comparisons
- Reflects modern CPU design trends

## Performance Characteristics

### Typical Instruction Times

| Instruction | Cycles | Notes |
|-------------|--------|-------|
| NOP/MOV/ADD | 1 | Single cycle ALU |
| MUL | 3 | Pipelined multiply |
| DIV | 5 | Iterative divide |
| LDR | 3 | Load-to-use latency |
| STR | 3 | Store through cache |
| Branch | 1 | With BTB prediction |
| Branch Mispredict | 3 | Pipeline flush |

### Memory Performance

- Cache hit: 1 cycle
- Cache miss: 3 cycles
- TLB hit: 1 cycle (transparent)
- TLB miss: 5 cycles (with page walk)

### Research Applications
- Security architecture evaluation
- Cache side-channel analysis
- Speculative execution attacks/defenses
- Privilege escalation demonstration
- Memory protection testing
- Taint analysis research

## References

### Key Papers/Concepts
- 5-Stage Pipeline: Classic architecture design
- Virtual Memory: Memory management techniques
- Memory Tagging: ARM MTE (Memory Tagging Extension)
- Pointer Authentication: ARM PAC (Pointer Authentication Code)
- Control-Flow Integrity: Microsoft's CFG, Google's Shadow Stack
- Taint Tracking: Information flow security

### Related Standards
- RISC-V ISA Specification
- ARM Architecture Reference Manual
- x86-64 Architecture Specification
- MIPS ISA Documentation

---