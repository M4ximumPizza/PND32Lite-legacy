#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"

/* ============================================================================
 * OPCODE TO MNEMONIC LOOKUP
 * ============================================================================
 */

static const char* get_mnemonic(uint8_t op) {
    switch (op) {
        case OP_NOP:   return "NOP";
        case OP_HLT:   return "HLT";
        case OP_MOV:   return "MOV";
        case OP_MOVI:  return "MOVI";
        case OP_MOVIH: return "MOVIH";
        case OP_MCR:   return "MCR";
        case OP_MRC:   return "MRC";
        case OP_CPYT:  return "CPYT";
        case OP_CLRT:  return "CLRT";
        case OP_ADD:   return "ADD";
        case OP_ADDI:  return "ADDI";
        case OP_SUB:   return "SUB";
        case OP_SUBI:  return "SUBI";
        case OP_MUL:   return "MUL";
        case OP_MULI:  return "MULI";
        case OP_DIV:   return "DIV";
        case OP_DIVI:  return "DIVI";
        case OP_MOD:   return "MOD";
        case OP_MODI:  return "MODI";
        case OP_AND:   return "AND";
        case OP_ANDI:  return "ANDI";
        case OP_OR:    return "OR";
        case OP_ORI:   return "ORI";
        case OP_XOR:   return "XOR";
        case OP_XORI:  return "XORI";
        case OP_NOT:   return "NOT";
        case OP_SHL:   return "SHL";
        case OP_SRL:   return "SRL";
        case OP_SAR:   return "SAR";
        case OP_LDR:   return "LDR";
        case OP_STR:   return "STR";
        case OP_LDB:   return "LDB";
        case OP_STB:   return "STB";
        case OP_PUSH:  return "PUSH";
        case OP_POP:   return "POP";
        case OP_TLBIV: return "TLBIV";
        case OP_LEA:   return "LEA";
        case OP_CMP:   return "CMP";
        case OP_CMPI:  return "CMPI";
        case OP_B:     return "B";
        case OP_BEQ:   return "BEQ";
        case OP_BNE:   return "BNE";
        case OP_BGT:   return "BGT";
        case OP_BLT:   return "BLT";
        case OP_BL:    return "BL";
        case OP_BX:    return "BX";
        case OP_BLX:   return "BLX";
        case OP_SVC:   return "SVC";
        case OP_RFE:   return "RFE";
        case OP_LDH:   return "LDH";
        case OP_STH:   return "STH";
        case OP_CLI:   return "CLI";
        case OP_STI:   return "STI";
        case OP_IEV:   return "IEV";
        case OP_BLE:   return "BLE";
        case OP_BGE:   return "BGE";
        case OP_LDRS:  return "LDRS";
        case OP_LDBS:  return "LDBS";
        case OP_LDHS:  return "LDHS";
        case OP_CLZ:   return "CLZ";
        case OP_JALR:  return "JALR";
        case OP_SRA:   return "SRA";
        case OP_SYS:   return "SYS";
        case OP_ERET:  return "ERET";
        default:       return "UNKNOWN";
    }
}

/* ============================================================================
 * 18-BIT IMMEDIATE SIGN-EXTENSION
 * ============================================================================
 * Handles proper sign-extension for 18-bit immediates:
 * If bit 17 is set (0x020000), the value is negative.
 */

static int64_t sign_extend_18bit(int64_t imm) {
    /* Mask to 18 bits */
    imm &= 0x3FFFF;
    
    /* Check sign bit (bit 17) */
    if (imm & 0x020000) {
        /* Negative number - sign extend with 1s */
        imm |= 0xFFFFFFFFFFFC0000LL;
    }
    
    return imm;
}

/* ============================================================================
 * DISASSEMBLY ENGINE
 * ============================================================================
 */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Disassembler - Convert binary to assembly\n");
        printf("Usage: %s <binary.bin>\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        perror("Failed to open binary file");
        return 1;
    }

    uint32_t instr;
    int offset = 0;

    printf("=================================================================\n");
    printf("  OFFSET    HEX VALUE    MNEMONIC    OPERANDS\n");
    printf("=================================================================\n");

    while (fread(&instr, sizeof(uint32_t), 1, in) == 1) {
        /* Extract opcode (upper 6 bits) */
        uint8_t op = (instr >> 26) & 0x3F;
        const char *mnemonic = get_mnemonic(op);

        printf("0x%04X:    0x%08X    ", offset, instr);

        /* Decode based on instruction format */

        /* J-type: B, BL, SVC, SYS */
        if (op == OP_B || op == OP_BL || op == OP_SVC || op == OP_SYS) {
            int32_t target = instr & 0x3FFFFFF;
            printf("%-6s %d\n", mnemonic, target);
        }
        /* R-type: No operands */
        else if (op == OP_NOP || op == OP_HLT || op == OP_RFE ||
                 op == OP_TLBIV || op == OP_CLI || op == OP_STI ||
                 op == OP_SYS || op == OP_ERET) {
            printf("%s\n", mnemonic);
        }
        /* R-type: Single register operand */
        else if (op == OP_CLRT || op == OP_BX || op == OP_BLX) {
            uint8_t rd = (instr >> 22) & 0x0F;
            uint8_t rs1 = (instr >> 18) & 0x0F;
            int reg = rd ? rd : rs1;
            printf("%-6s R%d\n", mnemonic, reg);
        }
        /* R-type: Two register operands */
        else if (op == OP_MOV || op == OP_MCR || op == OP_MRC ||
                 op == OP_CPYT || op == OP_NOT || op == OP_CMP ||
                 op == OP_CLZ) {
            uint8_t rd = (instr >> 22) & 0x0F;
            uint8_t rs1 = (instr >> 18) & 0x0F;
            printf("%-6s R%d R%d\n", mnemonic, rd, rs1);
        }
        /* R-type: Three register operands */
        else if (op == OP_ADD || op == OP_SUB || op == OP_MUL ||
                 op == OP_DIV || op == OP_MOD || op == OP_AND ||
                 op == OP_OR || op == OP_XOR || op == OP_SHL ||
                 op == OP_SRL || op == OP_SAR || op == OP_SRA) {
            uint8_t rd = (instr >> 22) & 0x0F;
            uint8_t rs1 = (instr >> 18) & 0x0F;
            uint8_t rs2 = (instr >> 14) & 0x0F;
            printf("%-6s R%d R%d R%d\n", mnemonic, rd, rs1, rs2);
        }
        /* I-type: Instructions */
        else {
            uint8_t rd = (instr >> 22) & 0x0F;
            uint8_t rs1 = (instr >> 18) & 0x0F;
            int64_t imm = sign_extend_18bit(instr & 0x3FFFF);

            /* I-type: rd, imm */
            if (op == OP_MOVI || op == OP_MOVIH) {
                printf("%-6s R%d %lld\n", mnemonic, rd, (long long)imm);
            }
            /* I-type: rs1, imm (compare with immediate) */
            else if (op == OP_CMPI) {
                printf("%-6s R%d %lld\n", mnemonic, rs1, (long long)imm);
            }
            /* I-type: imm only (branch with immediate) */
            else if (op == OP_BEQ || op == OP_BNE || op == OP_BGT ||
                     op == OP_BLT || op == OP_BLE || op == OP_BGE) {
                printf("%-6s %lld\n", mnemonic, (long long)imm);
            }
            /* I-type: rd, rs1, imm (standard loads/stores, LEA, JALR) */
            else {
                printf("%-6s R%d R%d %lld\n", mnemonic, rd, rs1, (long long)imm);
            }
        }

        offset += 4;
    }

    fclose(in);
    printf("=================================================================\n");
    return 0;
}