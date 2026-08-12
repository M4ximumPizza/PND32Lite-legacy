#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================================
 * ISA OPCODE DEFINITIONS
 * ============================================================================
 */
#define OP_NOP    0x00  /* No Operation */
#define OP_HLT    0x01  /* Halt execution */
#define OP_MOV    0x02  /* rd = rs1 */
#define OP_MOVI   0x03  /* rd = sign_extend(imm18) */
#define OP_MOVIH  0x04  /* rd_hi = imm18 */
#define OP_MCR    0x05  /* cr[rd] = rs1 */
#define OP_MRC    0x06  /* rd = cr[rs1] */
#define OP_CPYT   0x07  /* Copy taint metadata rs1 -> rd */
#define OP_CLRT   0x08  /* Clear taint on rd */
#define OP_ADD    0x09  /* rd = rs1 + rs2 */
#define OP_ADDI   0x0A  /* rd = rs1 + sign_extend(imm18) */
#define OP_SUB    0x0B  /* rd = rs1 - rs2 */
#define OP_SUBI   0x0C  /* rd = rs1 - sign_extend(imm18) */
#define OP_MUL    0x0D  /* rd = rs1 * rs2 */
#define OP_MULI   0x0E  /* rd = rs1 * sign_extend(imm18) */
#define OP_DIV    0x0F  /* rd = rs1 / rs2 */
#define OP_DIVI   0x10  /* rd = rs1 / sign_extend(imm18) */
#define OP_MOD    0x11  /* rd = rs1 % rs2 */
#define OP_MODI   0x12  /* rd = rs1 % sign_extend(imm18) */
#define OP_AND    0x13  /* rd = rs1 & rs2 */
#define OP_ANDI   0x14  /* rd = rs1 & imm18 */
#define OP_OR     0x15  /* rd = rs1 | rs2 */
#define OP_ORI    0x16  /* rd = rs1 | imm18 */
#define OP_XOR    0x17  /* rd = rs1 ^ rs2 */
#define OP_XORI   0x18  /* rd = rs1 ^ imm18 */
#define OP_NOT    0x19  /* rd = ~rs1 */
#define OP_SHL    0x1A  /* rd = rs1 << rs2 */
#define OP_SRL    0x1B  /* rd = rs1 >> rs2 (logical) */
#define OP_SAR    0x1C  /* rd = rs1 >> rs2 (arithmetic) */
#define OP_LDR    0x1D  /* rd = mem[rs1 + imm18] (word) */
#define OP_STR    0x1E  /* mem[rs1 + imm18] = rd (word) */
#define OP_LDB    0x1F  /* rd = mem[rs1 + imm18] (byte, zero-ext) */
#define OP_STB    0x20  /* mem[rs1 + imm18] = rd (byte) */
#define OP_PUSH   0x21  /* stack[--sp] = rs1 */
#define OP_POP    0x22  /* rd = stack[sp++] */
#define OP_TLBIV  0x23  /* Invalidate TLB */
#define OP_LEA    0x24  /* rd = rs1 + imm18 (address computation) */
#define OP_CMP    0x25  /* Set flags based on rs1 vs rs2 */
#define OP_CMPI   0x26  /* Set flags based on rs1 vs imm18 */
#define OP_B      0x27  /* Unconditional branch (26-bit target) */
#define OP_BEQ    0x28  /* Branch if equal */
#define OP_BNE    0x29  /* Branch if not equal */
#define OP_BGT    0x2A  /* Branch if greater than */
#define OP_BLT    0x2B  /* Branch if less than */
#define OP_BL     0x2C  /* Branch and link (store return address) */
#define OP_BX     0x2D  /* Branch indirect (PC = rs1) */
#define OP_BLX    0x2E  /* Branch and link indirect */
#define OP_SVC    0x2F  /* Supervisor call (software interrupt) */
#define OP_RFE    0x30  /* Return from exception */
#define OP_LDH    0x31  /* Load half-word */
#define OP_STH    0x32  /* Store half-word */
#define OP_CLI    0x33  /* Clear interrupts (disable) */
#define OP_STI    0x34  /* Set interrupts (enable) */
#define OP_IEV    0x35  /* Set interrupt vector table */
#define OP_BLE    0x36  /* Branch if less than or equal */
#define OP_BGE    0x37  /* Branch if greater than or equal */
#define OP_LDRS   0x38  /* Load word (sign-extended) */
#define OP_LDBS   0x39  /* Load byte (sign-extended) */
#define OP_LDHS   0x3A  /* Load half-word (sign-extended) */
#define OP_CLZ    0x3B  /* Count leading zeros */
#define OP_JALR   0x3C  /* Jump and link via register */
#define OP_SRA    0x3D  /* Shift right arithmetic (register) */
#define OP_SYS    0x3E  /* System call (kernel trap) */
#define OP_ERET   0x3F  /* Exception return */

/* Privilege levels */
#define PRIV_KERNEL 0
#define PRIV_USER   1

/* Memory boundaries */
#define KERNEL_BOUNDARY 8192  /* First 8KB is kernel space */
#define SANDBOX_SIZE    40960 /* Total sandbox memory 40KB */

/* Exception vectors */
#define EXC_ROP_FAULT    24  /* Shadow stack integrity violation */

/* Branch target buffer */
#define BTB_SIZE 64

/* Register count */
#define NUM_REGISTERS 16

/* ============================================================================
 * INSTRUCTION FORMAT STRUCTURES
 * ============================================================================
 */

typedef struct {
    int64_t pc;
    uint32_t instr;
    int active;
} IF_ID_Reg;

typedef struct {
    int64_t src_pc;
    int64_t target_pc;
    int history;
    int valid;
} BTBEntry;

typedef struct {
    int64_t pc;
    uint8_t op, rd, rs1, rs2;
    int64_t imm;
    int target;
    int64_t val_rs1, val_rs2;
    int active;
} ID_EX_Reg;

typedef struct {
    int64_t pc;
    uint8_t op, rd;
    int64_t alu_result;
    int64_t store_data;
    int active;
} EX_MEM_Reg;

typedef struct {
    int64_t pc;
    uint8_t op, rd;
    int64_t val_wb;
    int active;
} MEM_WB_Reg;

/* ============================================================================
 * CPU CONTEXT STRUCTURE
 * ============================================================================
 */

typedef struct {
    int64_t regs[NUM_REGISTERS];        /* R0-R12: GPR, R13: SP, R14: LR, R15: PC */
    int64_t cr[4];                      /* CR0: Flags, CR1: IVT, CR2: User SP, CR3: EPC */
    uint8_t memory[SANDBOX_SIZE];       /* 40KB execution sandbox */
    uint8_t taint_regs[NUM_REGISTERS];  /* Taint tracking metadata */

    int64_t shadow_stack[1024];         /* ROP protection shadow stack */
    int ssp;                            /* Shadow stack pointer */

    BTBEntry btb[BTB_SIZE];             /* Branch target buffer */

    /* Pipeline latches */
    IF_ID_Reg  if_id;
    ID_EX_Reg  id_ex;
    EX_MEM_Reg ex_mem;
    MEM_WB_Reg mem_wb;

    int hazard_stall;      /* Stall signal for pipeline */
    int control_flush;     /* Flush signal on branch/exception */
} CPUContext;

#endif /* COMMON_H */