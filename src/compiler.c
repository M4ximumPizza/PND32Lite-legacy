#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "common.h"

#define MAX_INSTRUCTIONS 8192
#define MAX_LABELS       1024
#define MAX_TOKEN_LEN    128
#define MAX_LINE_LEN     256

#define IMM18_MIN (-131072)
#define IMM18_MAX (131071)
#define IMM26_MASK (0x3FFFFFF)

typedef enum {
    TOKEN_MNEMONIC,
    TOKEN_REGISTER,
    TOKEN_IMMEDIATE,
    TOKEN_LABEL_DEF,
    TOKEN_LABEL_REF
} TokenType;

typedef struct {
    char text[MAX_TOKEN_LEN];
    TokenType type;
    int64_t value;
} Token;

typedef struct {
    char name[64];
    int address;
} Label;

typedef struct {
    char mnemonic[32];
    Token operands[3];
    int operand_count;
    int line_num;
    int byte_address;
    char original_line[MAX_LINE_LEN];
} ParsedInstruction;

static Label symbol_table[MAX_LABELS];
static int label_count = 0;
static ParsedInstruction intermediate_rep[MAX_INSTRUCTIONS];
static int instruction_count = 0;
static const char *current_filename = "source.asm";

/* ============================================================================
 * ERROR REPORTING
 * ============================================================================
 */

static void print_diagnostic_error(const char *error_type, const char *message,
                                   int line_num, const char *raw_line,
                                   const char *offending_token) {
    fprintf(stderr, "\033[1;31m%s Error\033[0m in %s:%d: %s\n",
            error_type, current_filename, line_num, message);
    
    if (raw_line && strlen(raw_line) > 0) {
        fprintf(stderr, "    %d | %s", line_num, raw_line);
        if (raw_line[strlen(raw_line) - 1] != '\n') {
            fprintf(stderr, "\n");
        }

        fprintf(stderr, "      | ");
        if (offending_token) {
            const char *token_pos = strstr(raw_line, offending_token);
            if (token_pos) {
                size_t offset = token_pos - raw_line;
                for (size_t i = 0; i < offset; i++) {
                    fprintf(stderr, "%c", (raw_line[i] == '\t') ? '\t' : ' ');
                }
                fprintf(stderr, "\033[1;32m^");
                size_t tok_len = strlen(offending_token);
                for (size_t i = 1; i < tok_len; i++) {
                    fprintf(stderr, "~");
                }
                fprintf(stderr, "\033[0m\n");
            } else {
                fprintf(stderr, "\033[1;32m^\033[0m\n");
            }
        }
    }
}

/* ============================================================================
 * SYMBOL TABLE MANAGEMENT
 * ============================================================================
 */

static void add_label(const char *name, int byte_address, int line,
                      const char *raw_line) {
    if (label_count >= MAX_LABELS) {
        print_diagnostic_error("Fatal", "Symbol table exhausted",
                             line, raw_line, name);
        exit(1);
    }

    for (int i = 0; i < label_count; i++) {
        if (strcmp(symbol_table[i].name, name) == 0) {
            char error_msg[MAX_LINE_LEN];
            snprintf(error_msg, sizeof(error_msg),
                    "Duplicate label definition: '%s'", name);
            print_diagnostic_error("Linker", error_msg, line, raw_line, name);
            exit(1);
        }
    }

    strncpy(symbol_table[label_count].name, name, 63);
    symbol_table[label_count].name[63] = '\0';
    symbol_table[label_count].address = byte_address;
    label_count++;
}

static int find_label(const char *name) {
    for (int i = 0; i < label_count; i++) {
        if (strcmp(symbol_table[i].name, name) == 0) {
            return symbol_table[i].address;
        }
    }
    return -1;
}

/* ============================================================================
 * LEXICAL ANALYSIS
 * ============================================================================
 */

static void clean_line(char *dest, const char *src) {
    char *line_start = dest;
    
    while (*src) {
        if (*src == ';') {
            break;  /* Comment - stop processing line */
        }
        
        if (isspace((unsigned char)*src) || *src == ',') {
            if (dest > line_start && *(dest - 1) != ' ') {
                *dest++ = ' ';
            }
        } else {
            *dest++ = *src;
        }
        src++;
    }
    
    *dest = '\0';
    
    /* Remove trailing whitespace */
    if (dest > line_start && *(dest - 1) == ' ') {
        *(dest - 1) = '\0';
    }
}

static int64_t parse_immediate(const char *str, int line, const char *raw_line) {
    char *endptr;
    int64_t val = 0;

    if (!str || strlen(str) == 0) {
        print_diagnostic_error("Warning", "Empty immediate value",
                             line, raw_line, str);
        return 0;
    }

    /* Binary literal */
    if (strncmp(str, "0b", 2) == 0 || strncmp(str, "0B", 2) == 0) {
        val = strtoll(str + 2, &endptr, 2);
    } else {
        /* Decimal or hex (0x prefix) */
        val = strtoll(str, &endptr, 0);
    }

    if (*endptr != '\0') {
        char warn_msg[MAX_LINE_LEN];
        snprintf(warn_msg, sizeof(warn_msg),
                "Malformed numeric constant '%s'", str);
        print_diagnostic_error("Warning", warn_msg, line, raw_line, str);
    }

    return val;
}

static void tokenize_string(char *line, int line_num) {
    char raw_backup[MAX_LINE_LEN];
    strncpy(raw_backup, line, MAX_LINE_LEN - 1);
    raw_backup[MAX_LINE_LEN - 1] = '\0';

    char cleaned[512];
    clean_line(cleaned, line);
    
    if (strlen(cleaned) == 0) {
        return;  /* Empty or comment-only line */
    }

    char *token_strings[8];
    int t_count = 0;
    char *ptr = strtok(cleaned, " ");

    while (ptr && t_count < 8) {
        token_strings[t_count++] = ptr;
        ptr = strtok(NULL, " ");
    }

    if (t_count == 0) {
        return;
    }

    int current_idx = 0;
    int current_byte_address = instruction_count * 4;

    /* Check for label definition */
    size_t first_len = strlen(token_strings[0]);
    if (token_strings[0][first_len - 1] == ':') {
        token_strings[0][first_len - 1] = '\0';
        add_label(token_strings[0], current_byte_address, line_num, raw_backup);
        current_idx++;
        
        if (current_idx >= t_count) {
            return;  /* Label only, no instruction */
        }
    }

    if (instruction_count >= MAX_INSTRUCTIONS) {
        print_diagnostic_error("Fatal", "Instruction count exceeded",
                             line_num, raw_backup, token_strings[current_idx]);
        exit(1);
    }

    ParsedInstruction *inst = &intermediate_rep[instruction_count];
    strncpy(inst->mnemonic, token_strings[current_idx++], 31);
    inst->mnemonic[31] = '\0';
    inst->line_num = line_num;
    inst->byte_address = current_byte_address;
    inst->operand_count = 0;
    strncpy(inst->original_line, raw_backup, MAX_LINE_LEN - 1);
    inst->original_line[MAX_LINE_LEN - 1] = '\0';

    /* Parse operands */
    while (current_idx < t_count && inst->operand_count < 3) {
        Token *tok = &inst->operands[inst->operand_count];
        strncpy(tok->text, token_strings[current_idx], MAX_TOKEN_LEN - 1);
        tok->text[MAX_TOKEN_LEN - 1] = '\0';

        if (isalpha((unsigned char)tok->text[0]) || tok->text[0] == '_') {
            if ((tok->text[0] == 'R' || tok->text[0] == 'r') &&
                isdigit((unsigned char)tok->text[1])) {
                /* Register operand */
                tok->type = TOKEN_REGISTER;
                tok->value = atoi(&tok->text[1]);
                
                if (tok->value < 0 || tok->value >= NUM_REGISTERS) {
                    char err_buf[MAX_LINE_LEN];
                    snprintf(err_buf, sizeof(err_buf),
                            "Invalid register R%lld (valid: R0-R15)",
                            tok->value);
                    print_diagnostic_error("Syntax", err_buf, line_num,
                                         raw_backup, tok->text);
                    exit(1);
                }
            } else {
                /* Label reference */
                tok->type = TOKEN_LABEL_REF;
                tok->value = 0;
            }
        } else {
            /* Immediate value */
            tok->type = TOKEN_IMMEDIATE;
            tok->value = parse_immediate(tok->text, line_num, raw_backup);
        }
        
        inst->operand_count++;
        current_idx++;
    }

    instruction_count++;
}

/* ============================================================================
 * CODE GENERATION
 * ============================================================================
 */

static uint32_t build_r(uint8_t op, int rd, int rs1, int rs2) {
    return ((op & 0x3F) << 26) |
           ((rd & 0x0F) << 22) |
           ((rs1 & 0x0F) << 18) |
           ((rs2 & 0x0F) << 14);
}

static uint32_t build_i(uint8_t op, int rd, int rs, int64_t imm,
                        int line, const char *raw, const char *tok) {
    if (imm < IMM18_MIN || imm > IMM18_MAX) {
        char warn_buf[MAX_LINE_LEN];
        snprintf(warn_buf, sizeof(warn_buf),
                "Immediate overflow: %lld (truncating to 18-bit)",
                (long long)imm);
        print_diagnostic_error("Assembler Warning", warn_buf, line, raw, tok);
    }

    return ((op & 0x3F) << 26) |
           ((rd & 0x0F) << 22) |
           ((rs & 0x0F) << 18) |
           (imm & 0x3FFFF);
}

static uint32_t build_j(uint8_t op, int target) {
    return ((op & 0x3F) << 26) | (target & IMM26_MASK);
}

/* ============================================================================
 * MAIN ASSEMBLY LOOP
 * ============================================================================
 */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Assembler - Convert assembly to binary\n");
        printf("Usage: %s <source.asm> <output.bin>\n", argv[0]);
        return 1;
    }

    current_filename = argv[1];
    
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        perror("Failed to open source file");
        return 1;
    }

    char raw_buf[MAX_LINE_LEN];
    int line_counter = 0;

    /* First pass: tokenize and collect labels */
    while (fgets(raw_buf, sizeof(raw_buf), file)) {
        line_counter++;
        tokenize_string(raw_buf, line_counter);
    }
    fclose(file);

    /* Second pass: generate binary */
    uint32_t *binary_image = malloc(sizeof(uint32_t) * instruction_count);
    if (!binary_image) {
        perror("Memory allocation failed");
        return 1;
    }

    for (int i = 0; i < instruction_count; i++) {
        ParsedInstruction *inst = &intermediate_rep[i];
        uint32_t encoded_inst = 0;

        const char *m = inst->mnemonic;
        int64_t v0 = inst->operands[0].value;
        int64_t v1 = inst->operands[1].value;
        int64_t v2 = inst->operands[2].value;

        /* Encode R-type instructions */
        if (strcmp(m, "NOP") == 0)          encoded_inst = build_r(OP_NOP, 0, 0, 0);
        else if (strcmp(m, "HLT") == 0)     encoded_inst = build_r(OP_HLT, 0, 0, 0);
        else if (strcmp(m, "MOV") == 0)     encoded_inst = build_r(OP_MOV, v0, v1, 0);
        else if (strcmp(m, "ADD") == 0)     encoded_inst = build_r(OP_ADD, v0, v1, v2);
        else if (strcmp(m, "SUB") == 0)     encoded_inst = build_r(OP_SUB, v0, v1, v2);
        else if (strcmp(m, "MUL") == 0)     encoded_inst = build_r(OP_MUL, v0, v1, v2);
        else if (strcmp(m, "DIV") == 0)     encoded_inst = build_r(OP_DIV, v0, v1, v2);
        else if (strcmp(m, "CMP") == 0)     encoded_inst = build_r(OP_CMP, 0, v0, v1);
        else if (strcmp(m, "AND") == 0)     encoded_inst = build_r(OP_AND, v0, v1, v2);
        else if (strcmp(m, "OR") == 0)      encoded_inst = build_r(OP_OR, v0, v1, v2);
        else if (strcmp(m, "XOR") == 0)     encoded_inst = build_r(OP_XOR, v0, v1, v2);
        else if (strcmp(m, "CPYT") == 0)    encoded_inst = build_r(OP_CPYT, v0, v1, 0);
        else if (strcmp(m, "CLRT") == 0)    encoded_inst = build_r(OP_CLRT, v0, 0, 0);
        else if (strcmp(m, "SRA") == 0)     encoded_inst = build_r(OP_SRA, v0, v1, v2);
        else if (strcmp(m, "ERET") == 0)    encoded_inst = build_r(OP_ERET, 0, 0, 0);

        /* Encode I-type instructions */
        else if (strcmp(m, "MOVI") == 0)    encoded_inst = build_i(OP_MOVI, v0, 0, v1, inst->line_num, inst->original_line, inst->operands[1].text);
        else if (strcmp(m, "MOVIH") == 0)   encoded_inst = build_i(OP_MOVIH, v0, 0, v1, inst->line_num, inst->original_line, inst->operands[1].text);
        else if (strcmp(m, "ADDI") == 0)    encoded_inst = build_i(OP_ADDI, v0, v1, v2, inst->line_num, inst->original_line, inst->operands[2].text);
        else if (strcmp(m, "SUBI") == 0)    encoded_inst = build_i(OP_SUBI, v0, v1, v2, inst->line_num, inst->original_line, inst->operands[2].text);
        else if (strcmp(m, "LDR") == 0)     encoded_inst = build_i(OP_LDR, v0, v1, v2, inst->line_num, inst->original_line, inst->operands[2].text);
        else if (strcmp(m, "STR") == 0)     encoded_inst = build_i(OP_STR, v0, v1, v2, inst->line_num, inst->original_line, inst->operands[2].text);
        else if (strcmp(m, "CMPI") == 0)    encoded_inst = build_i(OP_CMPI, 0, v0, v1, inst->line_num, inst->original_line, inst->operands[1].text);

        /* Encode J-type instructions */
        else if (strcmp(m, "SVC") == 0)     encoded_inst = build_j(OP_SVC, v0);
        else if (strcmp(m, "SYS") == 0)     encoded_inst = build_j(OP_SYS, 0);

        /* Branch instructions */
        else if (strcmp(m, "B") == 0 || strcmp(m, "BL") == 0) {
            int target = (inst->operands[0].type == TOKEN_LABEL_REF) ?
                        find_label(inst->operands[0].text) : (int)v0;
            
            if (target == -1) {
                char err_m[MAX_LINE_LEN];
                snprintf(err_m, sizeof(err_m),
                        "Unresolved label '%s'", inst->operands[0].text);
                print_diagnostic_error("Linker", err_m, inst->line_num,
                                     inst->original_line, inst->operands[0].text);
                free(binary_image);
                exit(1);
            }
            
            encoded_inst = build_j((strcmp(m, "B") == 0) ? OP_B : OP_BL, target);
        }
        else if (strcmp(m, "BEQ") == 0 || strcmp(m, "BNE") == 0 ||
                strcmp(m, "BGT") == 0 || strcmp(m, "BLT") == 0 ||
                strcmp(m, "BLE") == 0 || strcmp(m, "BGE") == 0) {
            int target = (inst->operands[0].type == TOKEN_LABEL_REF) ?
                        find_label(inst->operands[0].text) : (int)v0;
            
            if (target == -1) {
                char err_m[MAX_LINE_LEN];
                snprintf(err_m, sizeof(err_m),
                        "Unresolved label '%s'", inst->operands[0].text);
                print_diagnostic_error("Linker", err_m, inst->line_num,
                                     inst->original_line, inst->operands[0].text);
                free(binary_image);
                exit(1);
            }
            
            int offset_bytes = target - inst->byte_address;
            
            uint8_t op_select;
            if (strcmp(m, "BEQ") == 0)      op_select = OP_BEQ;
            else if (strcmp(m, "BNE") == 0) op_select = OP_BNE;
            else if (strcmp(m, "BGT") == 0) op_select = OP_BGT;
            else if (strcmp(m, "BLT") == 0) op_select = OP_BLT;
            else if (strcmp(m, "BLE") == 0) op_select = OP_BLE;
            else                            op_select = OP_BGE;
            
            encoded_inst = build_i(op_select, 0, 0, offset_bytes,
                                 inst->line_num, inst->original_line,
                                 inst->operands[0].text);
        }
        else {
            char err_m[MAX_LINE_LEN];
            snprintf(err_m, sizeof(err_m),
                    "Unknown instruction '%s'", m);
            print_diagnostic_error("Compilation", err_m, inst->line_num,
                                 inst->original_line, m);
            free(binary_image);
            return 1;
        }

        binary_image[i] = encoded_inst;
    }

    /* Write binary output */
    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        perror("Failed to open output file");
        free(binary_image);
        return 1;
    }

    if (fwrite(binary_image, sizeof(uint32_t), instruction_count, out) != (size_t)instruction_count) {
        perror("Failed to write output file");
        fclose(out);
        free(binary_image);
        return 1;
    }

    fclose(out);
    free(binary_image);

    printf("\033[1;32mSuccess!\033[0m Assembled %d instructions with %d labels.\n",
           instruction_count, label_count);
    return 0;
}