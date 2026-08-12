#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h> 
#include <errno.h>  
#include "common.h"
#include <unistd.h>
#include <stdint.h>
// V3 Pandy
// ============================================
// CFI (Control-Flow Integrity) Enforcement
// ============================================
#define CFI_LANDING_PADS_MAX 256
typedef struct {
    long long address;
    int valid;
} LandingPad;
LandingPad cfi_landing_pads[CFI_LANDING_PADS_MAX];
int cfi_landing_pad_count = 0;

// ============================================
// PAC (Pointer Authentication Code)
// ============================================
typedef struct {
    uint64_t key;
    int valid;
} PACKey;
PACKey pac_keys[4];
uint64_t pac_nonce = 0xDEADBEEFCAFEBABE;

// ============================================
// Side-Channel & Timing Instrumentation
// ============================================
typedef struct {
    unsigned long total_cycles;
    unsigned long cache_hits;
    unsigned long cache_misses;
    unsigned long btb_hits;
    unsigned long btb_misses;
    unsigned long speculative_exec;
    unsigned long mispredicted_branches;
} SideChannelMetrics;
SideChannelMetrics sc_metrics = {0};

// Explicit Exception Vector Table Offsets
#define EXC_MEM_FAULT   0   // CR1 + 0
#define EXC_ILLEGAL_OP  4   // CR1 + 4
#define EXC_PRIV_VIOL   8   // CR1 + 8
#define EXC_SYS_CALL    12  // CR1 + 12
#define EXC_TAINT_FAULT 16  // CR1 + 16 (Security Vector for Taint Policy Violations)
#define EXC_NX_FAULT    20  // CR1 + 20 (New Security Vector for W^X / NX Violations)
#define EXC_CFI_FAULT   24  // CR1 + 24 (New Security Vector for Forward-Edge CFI Violations)
#define EXC_MTE_FAULT   28  // CR1 + 28 (New Security Vector for Memory Tagging Extension Violations)

// Memory Permission Bitmasks
#define PERM_W (1 << 0)
#define PERM_X (1 << 1)

// --- Memory Tagging Extension (MTE) Configuration ---
#define MTE_GRANULE_SIZE    16      // 16-byte aligned granules (ARM MTE / SPARC ADI standard)
#define MTE_TAG_BITS        4       // 4-bit tags per granule (2^4 = 16 unique tags)
#define MTE_TAG_MASK        0x0F    // Mask to extract 4-bit tag value
#define MTE_POINTER_TAG_SHIFT 56    // Tag stored in upper 4 bits of 64-bit pointer (bits [59:56])
#define MTE_POINTER_TAG_MASK  0x0F00000000000000ULL  // Isolation mask for pointer tag bits
#define MTE_GRANULE_COUNT   (40960 / MTE_GRANULE_SIZE)  // 2560 granules in 40KB sandbox
#define MTE_TAG_TABLE_SIZE  (MTE_GRANULE_COUNT / 2)     // Pack 2 tags per byte = 1280 bytes

// ===================================================
// --- VIRTUAL MEMORY UNIT (MMU) CONFIGURATION ---
// ===================================================
#define PAGE_SIZE           4096        // 4KB pages
#define PAGE_OFFSET_BITS    12          // log2(4096)
#define PAGE_TABLE_SIZE     256         // 256 entries per page table
#define NUM_PAGE_TABLES     2           // 2-level hierarchy
#define MAX_PROCESSES       16          // Max concurrent processes
#define TLB_ENTRIES         32          // Translation Lookaside Buffer size
#define EXC_PAGE_FAULT      32          // CR1 + 32 (Virtual memory page fault)

#define PERM_READ_USER      (1 << 0)    // User can read
#define PERM_WRITE_USER     (1 << 1)    // User can write
#define PERM_EXEC_USER      (1 << 2)    // User can execute
#define PERM_READ_KERN      (1 << 3)    // Kernel can read
#define PERM_WRITE_KERN     (1 << 4)    // Kernel can write
#define PERM_EXEC_KERN      (1 << 5)    // Kernel can execute

// ===================================================
// --- L1 CACHE SUBSYSTEM CONFIGURATION ---
// ===================================================
#define L1I_SIZE            16384       // 16KB I-Cache
#define L1D_SIZE            16384       // 16KB D-Cache
#define CACHE_LINE_SIZE     64          // 64-byte cache lines
#define CACHE_WAYS          2           // 2-way associative
#define CACHE_SETS          (L1D_SIZE / (CACHE_LINE_SIZE * CACHE_WAYS))
#define CACHE_TAG_BITS      20          // Tag field width

// ===================================================
// --- GDB RSP STUB CONFIGURATION ---
// ===================================================
#define GDB_PORT            9001        // GDB remote protocol port
#define GDB_BUFFER_SIZE     4096        // Receive buffer size
#define GDB_MAX_BREAKPOINTS 32          // Max hardware breakpoints

// Global Metadata Storage Spaces
unsigned char memory_taint[40960] = {0};
unsigned char memory_perms[40960] = {0}; // Track W^X access rights byte-by-byte
unsigned char memory_tags[MTE_TAG_TABLE_SIZE] = {0};  // MTE: 4-bit tags per 16-byte granule (packed 2-per-byte)
unsigned char register_mte_tags[16] = {0};  // MTE pointer tags for each register (R0-R15)
unsigned char current_ptr_tag = 0;  // Temp storage for pointer tag in current MEM operation

// ===================================================
// --- MMU/TLB DATA STRUCTURES ---
// ===================================================
typedef struct {
    long long vaddr;                    // Virtual address tag
    long long paddr;                    // Physical address
    unsigned char perms;                // Permission bits (R/W/X for user/kernel)
    int pid;                            // Process ID
    int valid;                          // Entry validity flag
    int lru_age;                        // LRU counter for replacement
} TLBEntry;

typedef struct {
    TLBEntry entries[TLB_ENTRIES];
    int lru_counter;                    // Global LRU timestamp
} TLB;

typedef struct {
    long long page_frames[PAGE_TABLE_SIZE];  // Physical page frame numbers
    unsigned char perms[PAGE_TABLE_SIZE];    // Per-page permissions
    int valid[PAGE_TABLE_SIZE];              // Validity bits
} PageTable;

typedef struct {
    PageTable *page_tables[NUM_PAGE_TABLES]; // 2-level page table hierarchy
    int pid;                                 // Process ID
    int active;                              // Is this process active
} ProcessMMUContext;

// ===================================================
// --- L1 CACHE DATA STRUCTURES ---
// ===================================================
typedef struct {
    long long tag;                      // Tag field
    unsigned char data[CACHE_LINE_SIZE]; // Cache line data
    int valid;                          // Valid bit
    int dirty;                          // Dirty bit (write-back)
    int lru_age;                        // LRU counter
} CacheLine;

typedef struct {
    CacheLine lines[CACHE_WAYS];        // Ways in this set
} CacheSet;

typedef struct {
    CacheSet sets[CACHE_SETS];          // All cache sets
    unsigned long hits;                 // Hit counter
    unsigned long misses;               // Miss counter
    int lru_counter;                    // Global LRU timestamp
} L1Cache;

// ===================================================
// --- GDB RSP STUB DATA STRUCTURES ---
// ===================================================
typedef struct {
    long long address;                  // Breakpoint address
    int type;                           // 0=soft, 1=hard (instruction)
    int enabled;                        // Active flag
} Breakpoint;

typedef struct {
    int socket;                         // Client socket (-1 if not connected)
    char recv_buffer[GDB_BUFFER_SIZE];  // Receive buffer
    int recv_len;                       // Bytes in buffer
    int running;                        // Target execution state
    Breakpoint breakpoints[GDB_MAX_BREAKPOINTS]; // Hardware breakpoint table
    int paused_pc;                      // PC when execution paused
} GDBStub;

// Global subsystem instances
TLB global_tlb;
ProcessMMUContext mmu_contexts[MAX_PROCESSES];
int current_pid = 0;

L1Cache l1_icache;                      // Instruction cache
L1Cache l1_dcache;                      // Data cache

GDBStub gdb_stub;
int gdb_enabled = 0;                    // Enable GDB debugging

// Helper function to sign-extend an 18-bit signed integer to a 64-bit long long
long long sign_extend_18(int imm) {
    if (imm & 0x20000) { 
        return (long long)(imm | 0xFFFFFFFFFFFC0000ULL);
    }
    return (long long)(imm & 0x3FFFF);
}

// Helper to extract current ring privilege level
int get_privilege_level(CPUContext *cpu) {
    return (int)(cpu->cr[0] & 1);
}

// ========================================
// --- MMU/TLB SUBSYSTEM IMPLEMENTATION ---
// ========================================

// Initialize MMU structures
void mmu_init() {
    memset(&global_tlb, 0, sizeof(TLB));
    memset(mmu_contexts, 0, sizeof(mmu_contexts));
    
    // Create page tables for kernel space (process 0)
    for (int i = 0; i < NUM_PAGE_TABLES; i++) {
        mmu_contexts[0].page_tables[i] = (PageTable*)malloc(sizeof(PageTable));
        memset(mmu_contexts[0].page_tables[i], 0, sizeof(PageTable));
    }
    mmu_contexts[0].pid = 0;
    mmu_contexts[0].active = 1;
    current_pid = 0;
}

// Translate virtual address to physical address using 2-level page table
// Returns physical address, or -1 on page fault
long long mmu_translate(long long vaddr, unsigned char required_perm, int privilege_level) {
    // First, check TLB for hit
    for (int i = 0; i < TLB_ENTRIES; i++) {
        if (global_tlb.entries[i].valid && 
            global_tlb.entries[i].vaddr == (vaddr & ~(PAGE_SIZE - 1)) &&
            global_tlb.entries[i].pid == current_pid) {
            
            // Check permissions
            unsigned char perm_check = (privilege_level == PRIV_KERNEL) ? 
                (global_tlb.entries[i].perms >> 3) : 
                (global_tlb.entries[i].perms & 0x07);
            
            if ((perm_check & required_perm) != required_perm) {
                return -1;  // Permission fault
            }
            
            global_tlb.entries[i].lru_age = global_tlb.lru_counter++;
            return global_tlb.entries[i].paddr + (vaddr & (PAGE_SIZE - 1));
        }
    }
    
    // TLB miss: walk page tables
    if (current_pid >= MAX_PROCESSES || !mmu_contexts[current_pid].active) {
        return -1;  // Invalid process context
    }
    
    ProcessMMUContext *ctx = &mmu_contexts[current_pid];
    
    // Extract page table indices from virtual address
    int l1_index = (vaddr >> (PAGE_OFFSET_BITS + 8)) & 0xFF;
    int l2_index = (vaddr >> PAGE_OFFSET_BITS) & 0xFF;
    
    if (l1_index >= PAGE_TABLE_SIZE || l2_index >= PAGE_TABLE_SIZE) {
        return -1;  // Address out of range
    }
    
    // Check second level page table
    PageTable *l2_table = ctx->page_tables[1];
    if (!l2_table || !l2_table->valid[l2_index]) {
        return -1;  // Page not mapped
    }
    
    // Check permissions
    unsigned char page_perm = l2_table->perms[l2_index];
    unsigned char perm_check = (privilege_level == PRIV_KERNEL) ? 
        (page_perm >> 3) : (page_perm & 0x07);
    
    if ((perm_check & required_perm) != required_perm) {
        return -1;  // Permission fault
    }
    
    // Install entry in TLB (LRU replacement)
    int lru_victim = 0;
    int oldest_age = global_tlb.entries[0].lru_age;
    for (int i = 1; i < TLB_ENTRIES; i++) {
        if (!global_tlb.entries[i].valid) {
            lru_victim = i;
            break;
        }
        if (global_tlb.entries[i].lru_age < oldest_age) {
            oldest_age = global_tlb.entries[i].lru_age;
            lru_victim = i;
        }
    }
    
    long long paddr = (l2_table->page_frames[l2_index] << PAGE_OFFSET_BITS) + (vaddr & (PAGE_SIZE - 1));
    global_tlb.entries[lru_victim].vaddr = vaddr & ~(PAGE_SIZE - 1);
    global_tlb.entries[lru_victim].paddr = paddr & ~(PAGE_SIZE - 1);
    global_tlb.entries[lru_victim].perms = page_perm;
    global_tlb.entries[lru_victim].pid = current_pid;
    global_tlb.entries[lru_victim].valid = 1;
    global_tlb.entries[lru_victim].lru_age = global_tlb.lru_counter++;
    
    return paddr;
}

// Map virtual address to physical page frame
int mmu_map_page(int pid, long long vaddr, long long paddr, unsigned char perms) {
    if (pid >= MAX_PROCESSES) return -1;
    
    ProcessMMUContext *ctx = &mmu_contexts[pid];
    int l2_index = (vaddr >> PAGE_OFFSET_BITS) & 0xFF;
    
    if (l2_index >= PAGE_TABLE_SIZE) return -1;
    
    if (!ctx->page_tables[1]) {
        ctx->page_tables[1] = (PageTable*)malloc(sizeof(PageTable));
        memset(ctx->page_tables[1], 0, sizeof(PageTable));
    }
    
    ctx->page_tables[1]->page_frames[l2_index] = paddr >> PAGE_OFFSET_BITS;
    ctx->page_tables[1]->perms[l2_index] = perms;
    ctx->page_tables[1]->valid[l2_index] = 1;
    
    // Invalidate TLB entries for this virtual address
    for (int i = 0; i < TLB_ENTRIES; i++) {
        if (global_tlb.entries[i].vaddr == (vaddr & ~(PAGE_SIZE - 1)) &&
            global_tlb.entries[i].pid == pid) {
            global_tlb.entries[i].valid = 0;
        }
    }
    
    return 0;
}

// Invalidate TLB (used on context switch)
void mmu_invalidate_tlb(int pid) {
    for (int i = 0; i < TLB_ENTRIES; i++) {
        if (global_tlb.entries[i].pid == pid) {
            global_tlb.entries[i].valid = 0;
        }
    }
}

// ========================================
// --- L1 CACHE SUBSYSTEM IMPLEMENTATION ---
// ========================================

// Initialize L1 caches
void cache_init() {
    memset(&l1_icache, 0, sizeof(L1Cache));
    memset(&l1_dcache, 0, sizeof(L1Cache));
    l1_icache.lru_counter = 0;
    l1_dcache.lru_counter = 0;
}

// Extract cache index and tag from physical address
void cache_extract_index_tag(long long paddr, int *set_index, long long *tag) {
    *set_index = (paddr / CACHE_LINE_SIZE) % CACHE_SETS;
    *tag = (paddr >> (6 + (int)log2(CACHE_SETS))) & ((1LL << CACHE_TAG_BITS) - 1);
}

// Lookup data in L1 cache (instruction or data)
int cache_lookup(L1Cache *cache, long long paddr, unsigned char *data, int size) {
    int set_index;
    long long tag;
    
    cache_extract_index_tag(paddr, &set_index, &tag);
    
    CacheSet *set = &cache->sets[set_index];
    
    // Check for cache hit
    for (int way = 0; way < CACHE_WAYS; way++) {
        if (set->lines[way].valid && set->lines[way].tag == tag) {
            cache->hits++;
            set->lines[way].lru_age = cache->lru_counter++;
            
            // Extract requested bytes from cache line
            int offset = paddr & (CACHE_LINE_SIZE - 1);
            if (offset + size <= CACHE_LINE_SIZE) {
                memcpy(data, &set->lines[way].data[offset], size);
                return 0;  // Hit
            }
        }
    }
    
    cache->misses++;
    return 1;  // Miss
}

// Install cache line (on miss)
void cache_install(L1Cache *cache, long long paddr, unsigned char *data) {
    int set_index;
    long long tag;
    
    cache_extract_index_tag(paddr, &set_index, &tag);
    
    CacheSet *set = &cache->sets[set_index];
    
    // Find LRU victim
    int victim_way = 0;
    int oldest_age = set->lines[0].lru_age;
    
    for (int way = 1; way < CACHE_WAYS; way++) {
        if (!set->lines[way].valid) {
            victim_way = way;
            break;
        }
        if (set->lines[way].lru_age < oldest_age) {
            oldest_age = set->lines[way].lru_age;
            victim_way = way;
        }
    }
    
    // Install cache line
    set->lines[victim_way].tag = tag;
    set->lines[victim_way].valid = 1;
    set->lines[victim_way].dirty = 0;
    set->lines[victim_way].lru_age = cache->lru_counter++;
    
    memcpy(set->lines[victim_way].data, data, CACHE_LINE_SIZE);
}

// Write-back cache line (dirty eviction)
void cache_writeback(L1Cache *cache, int way_index, CacheLine *line) {
    if (line->valid && line->dirty) {
        // Simulate write-back to L2/memory
        // In real implementation, would write back to L2 cache or main memory
        line->dirty = 0;
    }
}

// Flush entire cache (invalidate all entries)
void cache_flush(L1Cache *cache) {
    for (int i = 0; i < CACHE_SETS; i++) {
        for (int j = 0; j < CACHE_WAYS; j++) {
            if (cache->sets[i].lines[j].dirty) {
                cache_writeback(cache, j, &cache->sets[i].lines[j]);
            }
            cache->sets[i].lines[j].valid = 0;
        }
    }
}

// ========================================
// --- GDB REMOTE SERIAL PROTOCOL STUB ---
// ========================================

// Initialize GDB stub (create listening socket)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

int gdb_server_socket = -1;
void gdb_init(int port) {
    // 1. Create socket using the global gdb_server_socket
    gdb_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (gdb_server_socket < 0) {
        perror("[GDB Stub] Socket creation failed");
        gdb_enabled = 0;
        return;
    }

    // 2. Set SO_REUSEADDR
    int opt = 1;
    if (setsockopt(gdb_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(gdb_server_socket);
        gdb_server_socket = -1;
        gdb_enabled = 0;
        return;
    }

    // 3. Bind address and port
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(gdb_server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("[GDB Stub] Bind failed");
        close(gdb_server_socket);
        gdb_server_socket = -1;
        gdb_enabled = 0;
        return;
    }

    // 4. Start listening
    if (listen(gdb_server_socket, 1) < 0) {
        perror("[GDB Stub] Listen failed");
        close(gdb_server_socket);
        gdb_server_socket = -1;
        gdb_enabled = 0;
        return;
    }

    // Use 'socket' instead of 'client_fd' to match your struct!
    gdb_stub.socket = -1;  
    gdb_stub.running = 0;

    // 5. If GDB debug mode is enabled, block execution and wait for connection
    if (gdb_enabled) {
        printf("[GDB Stub] Debug mode enabled. Blocking and waiting for GDB on port %d...\n", port);

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        // Synchronous accept: pauses simulator here until client connects
        gdb_stub.socket = accept(gdb_server_socket, (struct sockaddr *)&client_addr, &addr_len);

        if (gdb_stub.socket < 0) {
            perror("[GDB Stub] Accept failed");
            return;
        }

        // Set connected socket to non-blocking mode
        int flags = fcntl(gdb_stub.socket, F_GETFL, 0);
        fcntl(gdb_stub.socket, F_SETFL, flags | O_NONBLOCK);

        printf("[GDB Stub] Debugger attached! Starting pipeline execution...\n");
    } else {
        // Non-blocking socket listener mode when --debug option is omitted
        int flags = fcntl(gdb_server_socket, F_GETFL, 0);
        fcntl(gdb_server_socket, F_SETFL, flags | O_NONBLOCK);
    }
}

// Process incoming GDB commands (simplified)
void gdb_process_command(const char *cmd, CPUContext *cpu) {
    if (!cmd || !gdb_stub.socket) return;
    
    // Handle common GDB remote protocol commands
    switch (cmd[0]) {
        case 'c':  // Continue execution
            gdb_stub.running = 1;
            break;
            
        case 's':  // Single step
            gdb_stub.running = 0;  // Execute 1 instruction then pause
            break;
            
        case 'g':  // Read all registers
        {
            char response[256];
            snprintf(response, sizeof(response), 
                    "$%016llx%016llx%016llx%016llx$", 
                    cpu->regs[0], cpu->regs[1], cpu->regs[2], cpu->regs[3]);
            send(gdb_stub.socket, response, strlen(response), 0);
            break;
        }
            
        case 'p':  // Read single register
        {
            int reg_num = 0;
            if (sscanf(cmd, "p%x", &reg_num) == 1 && reg_num < 16) {
                char response[64];
                snprintf(response, sizeof(response), "$%016llx#", cpu->regs[reg_num]);
                send(gdb_stub.socket, response, strlen(response), 0);
            }
            break;
        }
            
        case 'Z':  // Insert breakpoint
        {
            long long addr;
            if (sscanf(cmd, "Z1,%llx", &addr) == 1) {
                for (int i = 0; i < GDB_MAX_BREAKPOINTS; i++) {
                    if (!gdb_stub.breakpoints[i].enabled) {
                        gdb_stub.breakpoints[i].address = addr;
                        gdb_stub.breakpoints[i].enabled = 1;
                        gdb_stub.breakpoints[i].type = 1;  // Hardware
                        send(gdb_stub.socket, "$OK#", 4, 0);
                        return;
                    }
                }
            }
            break;
        }
            
        case 'z':  // Remove breakpoint
        {
            long long addr;
            if (sscanf(cmd, "z1,%llx", &addr) == 1) {
                for (int i = 0; i < GDB_MAX_BREAKPOINTS; i++) {
                    if (gdb_stub.breakpoints[i].address == addr) {
                        gdb_stub.breakpoints[i].enabled = 0;
                        send(gdb_stub.socket, "$OK#", 4, 0);
                        return;
                    }
                }
            }
            break;
        }
            
        case '?':  // Query stop reason
        {
            char response[32];
            snprintf(response, sizeof(response), "$S05#");
            send(gdb_stub.socket, response, strlen(response), 0);
            break;
        }
            
        default:
            send(gdb_stub.socket, "$#", 2, 0);  // Unknown command
            break;
    }
}

// Poll GDB socket for incoming connections/commands
void gdb_poll(CPUContext *cpu) {
    if (!gdb_enabled || gdb_server_socket < 0) return;
    
    // Accept new connections
    if (gdb_stub.socket < 0) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(gdb_server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket >= 0) {
            gdb_stub.socket = client_socket;
            fcntl(client_socket, F_SETFL, O_NONBLOCK);
            printf("[GDB] Client connected\n");
            send(client_socket, "$OK#", 4, 0);
        }
    }
    
    // Receive data from connected client
    if (gdb_stub.socket >= 0) {
        int bytes = recv(gdb_stub.socket, gdb_stub.recv_buffer + gdb_stub.recv_len, 
                        GDB_BUFFER_SIZE - gdb_stub.recv_len - 1, 0);
        
        if (bytes > 0) {
            gdb_stub.recv_len += bytes;
            gdb_stub.recv_buffer[gdb_stub.recv_len] = '\0';
            
            // Process complete commands (end with '#')
            char *cmd_start = gdb_stub.recv_buffer;
            char *cmd_end = strchr(cmd_start, '#');
            
            if (cmd_end) {
                *cmd_end = '\0';
                if (cmd_start[0] == '$') {
                    gdb_process_command(cmd_start + 1, cpu);
                }
                
                // Shift buffer for next command
                int consumed = (cmd_end - cmd_start) + 2;
                memmove(gdb_stub.recv_buffer, cmd_end + 1, gdb_stub.recv_len - consumed);
                gdb_stub.recv_len -= consumed;
            }
        } else if (bytes < 0 && errno != EAGAIN) {
            close(gdb_stub.socket);
            gdb_stub.socket = -1;
            printf("[GDB] Client disconnected\n");
        }
    }
}

// Check if execution should pause (breakpoint hit)
int gdb_check_breakpoint(long long pc) {
    if (!gdb_enabled) return 0;
    
    for (int i = 0; i < GDB_MAX_BREAKPOINTS; i++) {
        if (gdb_stub.breakpoints[i].enabled && gdb_stub.breakpoints[i].address == pc) {
            gdb_stub.paused_pc = pc;
            return 1;  // Breakpoint hit
        }
    }
    return 0;
}

// ========================================
// --- Memory Tagging Extension (MTE) Subsystem ---
// ========================================

// Extract the 4-bit MTE tag from the upper bits of a 64-bit pointer
unsigned char extract_pointer_tag(long long ptr) {
    return (unsigned char)((ptr >> MTE_POINTER_TAG_SHIFT) & MTE_TAG_MASK);
}

// Get the memory tag for a 16-byte aligned granule at address `addr`
unsigned char get_memory_tag(long long addr) {
    if (addr < 0 || addr >= 40960) return 0;
    
    int granule_index = addr / MTE_GRANULE_SIZE;
    int byte_index = granule_index / 2;
    int nibble_index = granule_index % 2;
    
    if (byte_index >= MTE_TAG_TABLE_SIZE) return 0;
    
    unsigned char byte_val = memory_tags[byte_index];
    if (nibble_index == 0) {
        return (byte_val & 0x0F);  // Lower nibble
    } else {
        return ((byte_val >> 4) & 0x0F);  // Upper nibble
    }
}

// Set the MTE tag for a 16-byte aligned granule
void set_memory_tag(long long addr, unsigned char tag) {
    if (addr < 0 || addr >= 40960) return;
    
    tag &= MTE_TAG_MASK;  // Enforce 4-bit constraint
    int granule_index = addr / MTE_GRANULE_SIZE;
    int byte_index = granule_index / 2;
    int nibble_index = granule_index % 2;
    
    if (byte_index >= MTE_TAG_TABLE_SIZE) return;
    
    if (nibble_index == 0) {
        memory_tags[byte_index] = (memory_tags[byte_index] & 0xF0) | (tag & 0x0F);
    } else {
        memory_tags[byte_index] = (memory_tags[byte_index] & 0x0F) | ((tag & 0x0F) << 4);
    }
}

// Perform MTE tag verification on memory access
// Returns 0 if tags match (access allowed), non-zero if mismatch (violation)
int check_mte_tag(long long ptr, long long addr) {
    // Extract pointer tag and memory tag
    unsigned char ptr_tag = extract_pointer_tag(ptr);
    unsigned char mem_tag = get_memory_tag(addr);
    
    // Tags must match for access to be allowed
    if (ptr_tag != mem_tag) {
        return 1;  // MTE violation detected
    }
    return 0;  // Access allowed
}

// Initialize MTE tags for a memory region (used during allocation)
void mte_tag_region(long long start_addr, long long size, unsigned char tag) {
    tag &= MTE_TAG_MASK;
    
    // Align to granule boundaries
    long long aligned_start = (start_addr / MTE_GRANULE_SIZE) * MTE_GRANULE_SIZE;
    long long aligned_end = ((start_addr + size + MTE_GRANULE_SIZE - 1) / MTE_GRANULE_SIZE) * MTE_GRANULE_SIZE;
    
    for (long long addr = aligned_start; addr < aligned_end; addr += MTE_GRANULE_SIZE) {
        if (addr >= 0 && addr < 40960) {
            set_memory_tag(addr, tag);
        }
    }
}

// --- Hardened MPU Violation & Permission Gate ---
int check_mpu_violation(CPUContext *cpu, long long addr, size_t size, unsigned char required_perm) {
    // 1. Physical Bounds Guard
    if (addr < 0 || (addr + (long long)size) > 40960) {
        return 1; 
    }
    // 2. Privilege Ring Domain Separation
    if (get_privilege_level(cpu) == PRIV_USER) {
        if (addr < KERNEL_BOUNDARY) {
            return 1; // User space thread blocked from Kernel space
        }
    }
    // 3. W^X / NX Permission Bit Check
    for (size_t i = 0; i < size; i++) {
        if ((memory_perms[addr + i] & required_perm) != required_perm) {
            return 2; // Flag a strict security permission access mismatch
        }
    }
    return 0; // Access Authorized
}

// --- Comprehensive Memory Access Verification with MTE ---
// Returns: 0 = Access OK | 1 = Bounds fault | 2 = Permission fault | 3 = MTE tag mismatch
int check_memory_access(CPUContext *cpu, long long ptr, long long addr, size_t size, unsigned char required_perm) {
    // First check traditional MPU violations
    int mpu_result = check_mpu_violation(cpu, addr, size, required_perm);
    if (mpu_result != 0) {
        return mpu_result;
    }
    
    // Check MTE tag match if enabled in CR0 bit 1 (MTE enable flag)
    // Assume CR0 bit 1 is reserved for MTE enable
    if (cpu->cr[0] & (1 << 1)) {
        // Verify MTE tag on the target address
        if (check_mte_tag(ptr, addr) != 0) {
            return 3;  // MTE tag mismatch
        }
    }
    
    return 0;  // All checks passed
}

// --- Automated Exception Router and Vector Dispatcher ---
void trigger_exception(CPUContext *cpu, int exception_offset, long long faulting_pc) {
    printf("[Hardware Exception] Routing event to Vector Table Base CR1 [0x%llX] + Offset %d\n", cpu->cr[1], exception_offset);
    
    cpu->cr[2] = cpu->regs[13]; // Preserve User Stack Pointer
    cpu->cr[3] = faulting_pc;   // Save the address of the faulting instruction
    cpu->cr[0] &= ~1ULL;        // Escalate CPU privilege to Kernel Mode (PRIV_KERNEL)
    cpu->regs[13] = 2048;       // Safely switch to separated Kernel Stack Memory environment
    cpu->regs[15] = cpu->cr[1] + exception_offset; // Transfer Control to Handler Address
    
    // Flush the pipeline when an exception hits to prevent downstream dirty execution state leaks
    cpu->control_flush = 1;
}

// Trace logger to format and print instructions as they execute
void log_instruction(long long pc, unsigned char op, unsigned char rd, unsigned char rs1, unsigned char rs2, long long imm, int target) {
    printf("[PC: 0x%04llX] ", pc);
    switch (op) {
        case OP_NOP:   printf("NOP\n"); break;
        case OP_HLT:   printf("HLT\n"); break;
        case OP_MOV:   printf("MOV R%d, R%d\n", rd, rs1); break;
        case OP_MOVI:  printf("MOVI R%d, %lld\n", rd, imm); break;
        case OP_MOVIH: printf("MOVIH R%d, %lld\n", rd, imm); break;
        case OP_MCR:   printf("MCR CR%d, R%d\n", rd, rs1); break;
        case OP_MRC:   printf("MRC R%d, CR%d\n", rd, rs1); break;
        case OP_CPYT:  printf("CPYT R%d, R%d\n", rd, rs1); break;
        case OP_CLRT:  printf("CLRT R%d\n", rd); break;
        case OP_ADD:   printf("ADD R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_ADDI:  printf("ADDI R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_SUB:   printf("SUB R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_SUBI:  printf("SUBI R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_MUL:   printf("MUL R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_MULI:  printf("MULI R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_DIV:   printf("DIV R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_DIVI:  printf("DIVI R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_MOD:   printf("MOD R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_MODI:  printf("MODI R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_AND:   printf("AND R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_ANDI:  printf("ANDI R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_OR:    printf("OR R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_ORI:   printf("ORI R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_XOR:   printf("XOR R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_XORI:  printf("XORI R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_NOT:   printf("NOT R%d, R%d\n", rd, rs1); break;
        case OP_SHL:   printf("SHL R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_SRL:   printf("SRL R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_SAR:   printf("SAR R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_LDR:   printf("LDR R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_STR:   printf("STR R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_LDB:   printf("LDB R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_STB:   printf("STB R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_PUSH:  printf("PUSH R%d\n", rs1); break;
        case OP_POP:   printf("POP R%d\n", rd); break;
        case OP_LEA:   printf("LEA R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_CMP:   printf("CMP R%d, R%d\n", rs1, rs2); break;
        case OP_CMPI:  printf("CMPI R%d, %lld\n", rs1, imm); break;
        case OP_B:     printf("B 0x%X\n", target); break;
        case OP_BEQ:   printf("BEQ (offset: %lld)\n", imm); break;
        case OP_BNE:   printf("BNE (offset: %lld)\n", imm); break;
        case OP_BGT:   printf("BGT (offset: %lld)\n", imm); break;
        case OP_BLT:   printf("BLT (offset: %lld)\n", imm); break;
        case OP_BL:    printf("BL 0x%X\n", target); break;
        case OP_BX:    printf("BX R%d\n", rs1); break;
        case OP_BLX:   printf("BLX R%d\n", rs1); break;
        case OP_LDH:   printf("LDH R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_STH:   printf("STH R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_LDRS:  printf("LDRS R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_LDBS:  printf("LDBS R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_LDHS:  printf("LDHS R%d, [R%d + %lld]\n", rd, rs1, imm); break;
        case OP_CLZ:   printf("CLZ R%d, R%d\n", rd, rs1); break;
        case OP_JALR:  printf("JALR R%d, R%d, %lld\n", rd, rs1, imm); break;
        case OP_SRA:   printf("SRA R%d, R%d, R%d\n", rd, rs1, rs2); break;
        case OP_SVC:   printf("SVC\n"); break;
        case OP_SYS:   printf("SYS\n"); break;
        case OP_RFE:   printf("RFE\n"); break;
        case OP_CLI:   printf("CLI\n"); break;
        case OP_STI:   printf("STI\n"); break;
        case OP_IEV:   printf("IEV\n"); break;
        case OP_ERET:  printf("ERET\n"); break;
        case OP_TLBIV: printf("TLBIV\n"); break;
        case OP_BLE:   printf("BLE (offset: %lld)\n", imm); break;
        case OP_BGE:   printf("BGE (offset: %lld)\n", imm); break;
        default:       printf("UNKNOWN (Opcode: 0x%02X)\n", op); break;
    }
}

void print_cpu_state(CPUContext *cpu) {
    printf("\n=== CPU Register State ===\n");
    for (int i = 0; i < 13; i++) {
        printf("R%02d: %016llx [%s] ", i, cpu->regs[i], cpu->taint_regs[i] ? "TAINTED" : "CLEAN");
        if ((i + 1) % 2 == 0) printf("\n");
    }
    printf("\nSP (R13): %016llx | LR (R14): %016llx | PC (R15): %016llx\n", 
           cpu->regs[13], cpu->regs[14], cpu->regs[15]);
    printf("CR0 (Status): %016llx [Mode: %s] | CR1 (IVT Base): %016llx\n", 
           cpu->cr[0], (cpu->cr[0] & 1) ? "USER" : "KERNEL", cpu->cr[1]);
    printf("==========================\n");
}

// Check if an opcode updates a target destination register
int op_writes_rd(unsigned char op) {
    if (op == OP_NOP || op == OP_HLT || op == OP_STR || op == OP_STB || op == OP_STH ||
        op == OP_PUSH || op == OP_CMP || op == OP_CMPI || op == OP_B || op == OP_BEQ ||
        op == OP_BNE || op == OP_BGT || op == OP_BLT || op == OP_BLE || op == OP_BGE ||
        op == OP_BX || op == OP_SVC || op == OP_SYS || op == OP_RFE || op == OP_ERET ||
        op == OP_CLI || op == OP_STI || op == OP_IEV || op == OP_TLBIV || op == OP_MCR) {
        return 0;
    }
    return 1;
}

// Check if an opcode reads from a memory location (Load type)
int op_is_load(unsigned char op) {
    return (op == OP_LDR || op == OP_LDB || op == OP_LDH || op == OP_LDRS || op == OP_LDBS || op == OP_LDHS || op == OP_POP);
}

// ========================================
// --- MTE SECURITY DOCUMENTATION ---
// ========================================
//
// Memory Tagging Extension (MTE) Overview:
//   - Adds a 4-bit tag to every 16-byte aligned memory granule
//   - Each pointer stores a matching 4-bit tag in bits [59:56]
//   - Hardware verifies pointer tag == memory tag before any access
//   - Instantly detects: Use-After-Free (UAF), Heap Buffer Overflows
//
// How It Works:
//   1. Allocate memory: Set MTE tag on 16-byte granules
//   2. Create pointer: Embed same 4-bit tag in upper bits of address
//   3. Dereference: Verify tag match at hardware level during load/store
//   4. Free memory: Change granule tag to "free" value (e.g., 0)
//   5. UAF detected: Next dereference with old pointer tag mismatches new free tag
//
// Enable/Disable:
//   - CR0 bit 1 controls MTE enable/disable in this simulator
//   - Set CR0 = 0x02 to enable MTE security checks
//
// Example Attack Detection:
//   ```
//   void* ptr = malloc(16);  // Allocate with tag=5
//   store with tag=5         // Access succeeds (tags match)
//   free(ptr);               // Change granule tag to 0
//   store with tag=5         // CAUGHT! Tag 5 != 0 -> EXC_MTE_FAULT
//   ```

// ============================================
// CFI Forward-Edge: Landing Pad Validation
// ============================================
void cfi_register_landing_pad(long long addr) {
    if (cfi_landing_pad_count < CFI_LANDING_PADS_MAX) {
        cfi_landing_pads[cfi_landing_pad_count].address = addr;
        cfi_landing_pads[cfi_landing_pad_count].valid = 1;
        cfi_landing_pad_count++;
    }
}

int cfi_validate_indirect_target(long long target_addr) {
    for (int i = 0; i < cfi_landing_pad_count; i++) {
        if (cfi_landing_pads[i].valid && cfi_landing_pads[i].address == target_addr) {
            return 0;  // Valid landing pad
        }
    }
    return -1;  // CFI violation
}

// ============================================
// CFI Backward-Edge: Shadow Stack Validation
// ============================================
int cfi_shadow_stack_verify(CPUContext *cpu, long long expected_pc) {
    if (cpu->ssp <= 0) return -1;
    
    long long shadow_return = cpu->shadow_stack[cpu->ssp - 1];
    if (shadow_return == expected_pc) {
        return 0;  // Match
    }
    return -1;  // Mismatch - corruption detected
}

void cfi_shadow_stack_push(CPUContext *cpu, long long return_addr) {
    if (cpu->ssp < 1024) {
        cpu->shadow_stack[cpu->ssp++] = return_addr;
    }
}

void cfi_shadow_stack_pop(CPUContext *cpu) {
    if (cpu->ssp > 0) {
        cpu->ssp--;
    }
}

// ============================================
// PAC: Pointer Authentication Signing
// ============================================
void pac_init_keys() {
    pac_keys[0].key = 0x0F0F0F0F0F0F0F0FULL;
    pac_keys[0].valid = 1;
    pac_keys[1].key = 0xF0F0F0F0F0F0F0F0ULL;
    pac_keys[1].valid = 1;
}

// Simple PAC signing: XOR pointer with key and nonce
uint64_t pac_sign_pointer(uint64_t ptr, int key_idx) {
    if (key_idx >= 4 || !pac_keys[key_idx].valid) return ptr;
    
    uint64_t signature = ptr ^ pac_keys[key_idx].key ^ pac_nonce;
    return (ptr & 0x00FFFFFFFFFFFFFFULL) | ((signature & 0x00FF) << 56);
}

// PAC authentication: verify signature
int pac_authenticate_pointer(uint64_t signed_ptr, int key_idx) {
    if (key_idx >= 4 || !pac_keys[key_idx].valid) return -1;
    
    uint64_t stored_sig = (signed_ptr >> 56) & 0x00FF;
    uint64_t ptr = signed_ptr & 0x00FFFFFFFFFFFFFFULL;
    uint64_t computed_sig = (ptr ^ pac_keys[key_idx].key ^ pac_nonce) & 0x00FF;
    
    if (stored_sig == computed_sig) {
        return 0;  // Valid
    }
    return -1;  // Tampered
}

// Sign return address on stack (when pushing)
void pac_sign_return_address(CPUContext *cpu, long long return_addr) {
    uint64_t signed_addr = pac_sign_pointer((uint64_t)return_addr, 0);
    cfi_shadow_stack_push(cpu, (long long)signed_addr);
}

// Authenticate return address (when popping)
int pac_verify_return_address(CPUContext *cpu, long long *return_addr) {
    if (cpu->ssp <= 0) return -1;
    
    long long signed_addr = cpu->shadow_stack[cpu->ssp - 1];
    if (pac_authenticate_pointer((uint64_t)signed_addr, 0) != 0) {
        return -1;  // Tampering detected
    }
    
    *return_addr = signed_addr & 0x00FFFFFFFFFFFFFFULL;
    cfi_shadow_stack_pop(cpu);
    return 0;
}

// ============================================
// Side-Channel: Timing & Behavior Tracking
// ============================================
void sc_track_cycle() {
    sc_metrics.total_cycles++;
}

void sc_track_btb_hit() {
    sc_metrics.btb_hits++;
}

void sc_track_btb_miss() {
    sc_metrics.btb_misses++;
}

void sc_track_cache_hit() {
    sc_metrics.cache_hits++;
}

void sc_track_cache_miss() {
    sc_metrics.cache_misses++;
}

void sc_track_speculative_execution() {
    sc_metrics.speculative_exec++;
}

void sc_track_misprediction() {
    sc_metrics.mispredicted_branches++;
}

void sc_report_metrics() {
    printf("\n=== Side-Channel Metrics ===\n");
    printf("Total Cycles: %lu\n", sc_metrics.total_cycles);
    printf("BTB Hits: %lu / Misses: %lu (Ratio: %.2f%%)\n", 
           sc_metrics.btb_hits, sc_metrics.btb_misses,
           100.0 * sc_metrics.btb_hits / (sc_metrics.btb_hits + sc_metrics.btb_misses + 1));
    printf("Cache Hits: %lu / Misses: %lu (Ratio: %.2f%%)\n",
           sc_metrics.cache_hits, sc_metrics.cache_misses,
           100.0 * sc_metrics.cache_hits / (sc_metrics.cache_hits + sc_metrics.cache_misses + 1));
    printf("Speculative Executions: %lu\n", sc_metrics.speculative_exec);
    printf("Mispredicted Branches: %lu\n", sc_metrics.mispredicted_branches);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <binary.bin>\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-g") == 0) {
            gdb_enabled = 1;
        }
    }

    // Initialize GDB Server on port 9001
    gdb_init(GDB_PORT);

    CPUContext cpu;
    memset(&cpu, 0, sizeof(CPUContext));
    
    srand((unsigned int)time(NULL));
    int aslr_offset = (rand() % 256) * 4;
    long long user_load_address = KERNEL_BOUNDARY + aslr_offset;

    cpu.cr[1] = 0x1000;             
    cpu.cr[0] |= PRIV_USER;          
    cpu.regs[13] = 40960;           
    cpu.regs[15] = user_load_address;
    cpu.ssp = 0;

    memset(&memory_perms[0], PERM_W, KERNEL_BOUNDARY);
    memset(&memory_perms[KERNEL_BOUNDARY], PERM_X, 16384);
    memset(&memory_perms[24576], PERM_W, 40960 - 24576);

    FILE *bin = fopen(argv[1], "rb");
    if (!bin) {
        perror("Failed to open binary payload file");
        return 1;
    }
    
    memset(&memory_perms[user_load_address], PERM_W | PERM_X, 4096);
    size_t bytes_read = fread(&cpu.memory[user_load_address], 1, 4096, bin);
    fclose(bin);
    
    memset(&memory_perms[user_load_address], PERM_X, 4096);

    printf("--- Hardened Pipelined Security Kernel Online ---\n");
    printf("[W^X Active] Page Permissions Configured: Code Area=NX_DISABLED, Stack Area=NX_ENABLED\n");
    printf("[ASLR Base] Loading program entry location safely at PC: 0x%llX\n\n", user_load_address);

    // Initialize security subsystems
    pac_init_keys();
    printf("[PAC] Pointer Authentication Code keys initialized\n");
    printf("[CFI] Control-Flow Integrity enforcement enabled\n");
    printf("[SC]  Side-Channel metrics tracking enabled\n\n");

    int running = 1;
    unsigned long long instructions_executed = 0;
    unsigned long long clock_cycles = 0;

    // Temporary storage structures to buffer intermediate pipeline updates safely per cycle tick
    IF_ID_Reg  next_if_id  = {0};
    ID_EX_Reg  next_id_ex  = {0};
    EX_MEM_Reg next_ex_mem = {0};
    MEM_WB_Reg next_mem_wb = {0};

    while (running || cpu.if_id.active || cpu.id_ex.active || cpu.ex_mem.active || cpu.mem_wb.active) {
        clock_cycles++;
        sc_track_cycle();  // Track side-channel metrics
        cpu.hazard_stall = 0;

        // ==========================================
        // 5. WRITEBACK (WB) STAGE
        // ==========================================
        if (cpu.mem_wb.active) {
            if (op_writes_rd(cpu.mem_wb.op)) {
                cpu.regs[cpu.mem_wb.rd] = cpu.mem_wb.val_wb;
            }
            if (cpu.mem_wb.op == OP_HLT) {
                printf("HLT committed at WB stage. Halting execution pipeline cleanly.\n");
                running = 0;
            }
            instructions_executed++;
        }

        // ==========================================
        // 4. MEMORY ACCESS (MEM) STAGE
        // ==========================================
        memset(&next_mem_wb, 0, sizeof(MEM_WB_Reg));
        if (cpu.ex_mem.active) {
            next_mem_wb.pc = cpu.ex_mem.pc;
            next_mem_wb.op = cpu.ex_mem.op;
            next_mem_wb.rd = cpu.ex_mem.rd;
            next_mem_wb.active = 1;
            next_mem_wb.val_wb = cpu.ex_mem.alu_result; // default path

            long long addr = cpu.ex_mem.alu_result;

            switch (cpu.ex_mem.op) {
                case OP_LDR:
                    if (check_mpu_violation(&cpu, addr, 8, 0)) trigger_exception(&cpu, EXC_MEM_FAULT, cpu.ex_mem.pc);
                    else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        // Check MTE tag match for pointer
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] LDR: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX (Use-After-Free or Buffer Overflow detected)\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            memcpy(&next_mem_wb.val_wb, &cpu.memory[addr], 8);
                            cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr]; 
                        }
                    } else {
                        memcpy(&next_mem_wb.val_wb, &cpu.memory[addr], 8);
                        cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr]; 
                    }
                    break;
                case OP_STR:
                    if (check_mpu_violation(&cpu, addr, 8, PERM_W) != 0) {
                        trigger_exception(&cpu, (check_mpu_violation(&cpu, addr, 8, PERM_W) == 2) ? EXC_NX_FAULT : EXC_MEM_FAULT, cpu.ex_mem.pc);
                    } else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        // Check MTE tag match for pointer
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] STR: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX (Use-After-Free or Buffer Overflow detected)\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            memcpy(&cpu.memory[addr], &cpu.ex_mem.store_data, 8);
                            memory_taint[addr] = (unsigned char)cpu.taint_regs[cpu.ex_mem.rd];
                        }
                    } else {
                        memcpy(&cpu.memory[addr], &cpu.ex_mem.store_data, 8);
                        memory_taint[addr] = (unsigned char)cpu.taint_regs[cpu.ex_mem.rd];
                    }
                    break;
                case OP_LDB:
                    if (check_mpu_violation(&cpu, addr, 1, 0)) trigger_exception(&cpu, EXC_MEM_FAULT, cpu.ex_mem.pc);
                    else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] LDB: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            next_mem_wb.val_wb = cpu.memory[addr];
                            cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                        }
                    } else {
                        next_mem_wb.val_wb = cpu.memory[addr];
                        cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                    }
                    break;
                case OP_STB:
                    if (check_mpu_violation(&cpu, addr, 1, PERM_W) != 0) {
                        trigger_exception(&cpu, (check_mpu_violation(&cpu, addr, 1, PERM_W) == 2) ? EXC_NX_FAULT : EXC_MEM_FAULT, cpu.ex_mem.pc);
                    } else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] STB: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            cpu.memory[addr] = (unsigned char)(cpu.ex_mem.store_data & 0xFF);
                            memory_taint[addr] = (unsigned char)cpu.taint_regs[cpu.ex_mem.rd];
                        }
                    } else {
                        cpu.memory[addr] = (unsigned char)(cpu.ex_mem.store_data & 0xFF);
                        memory_taint[addr] = (unsigned char)cpu.taint_regs[cpu.ex_mem.rd];
                    }
                    break;
                case OP_PUSH:
                    if (check_mpu_violation(&cpu, addr, 8, PERM_W) != 0) {
                        trigger_exception(&cpu, (check_mpu_violation(&cpu, addr, 8, PERM_W) == 2) ? EXC_NX_FAULT : EXC_MEM_FAULT, cpu.ex_mem.pc);
                    } else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] PUSH: Stack pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            memcpy(&cpu.memory[addr], &cpu.ex_mem.store_data, 8);
                            memory_taint[addr] = (unsigned char)cpu.taint_regs[cpu.ex_mem.rd];
                            cpu.regs[13] = addr; // Commit stack pointer allocation directly
                        }
                    } else {
                        memcpy(&cpu.memory[addr], &cpu.ex_mem.store_data, 8);
                        memory_taint[addr] = (unsigned char)cpu.taint_regs[cpu.ex_mem.rd];
                        cpu.regs[13] = addr; // Commit stack pointer allocation directly
                    }
                    break;
                case OP_POP:
                    if (check_mpu_violation(&cpu, addr, 8, 0)) trigger_exception(&cpu, EXC_MEM_FAULT, cpu.ex_mem.pc);
                    else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] POP: Stack pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            memcpy(&next_mem_wb.val_wb, &cpu.memory[addr], 8);
                            cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                            cpu.regs[13] = addr + 8;
                        }
                    } else {
                        memcpy(&next_mem_wb.val_wb, &cpu.memory[addr], 8);
                        cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                        cpu.regs[13] = addr + 8;
                    }
                    break;
                case OP_LDH:
                    if (check_mpu_violation(&cpu, addr, 2, 0)) trigger_exception(&cpu, EXC_MEM_FAULT, cpu.ex_mem.pc);
                    else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] LDH: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            unsigned short val;
                            memcpy(&val, &cpu.memory[addr], 2);
                            next_mem_wb.val_wb = val;
                            cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                        }
                    } else {
                        unsigned short val;
                        memcpy(&val, &cpu.memory[addr], 2);
                        next_mem_wb.val_wb = val;
                        cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                    }
                    break;
                case OP_STH:
                    if (check_mpu_violation(&cpu, addr, 2, PERM_W) != 0) {
                        trigger_exception(&cpu, (check_mpu_violation(&cpu, addr, 2, PERM_W) == 2) ? EXC_NX_FAULT : EXC_MEM_FAULT, cpu.ex_mem.pc);
                    } else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] STH: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            unsigned short val = (unsigned short)(cpu.ex_mem.store_data & 0xFFFF);
                            memcpy(&cpu.memory[addr], &val, 2);
                            memory_taint[addr] = (unsigned char)cpu.taint_regs[cpu.ex_mem.rd];
                        }
                    } else {
                        unsigned short val = (unsigned short)(cpu.ex_mem.store_data & 0xFFFF);
                        memcpy(&cpu.memory[addr], &val, 2);
                        memory_taint[addr] = (unsigned char)cpu.taint_regs[cpu.ex_mem.rd];
                    }
                    break;
                case OP_LDRS:
                    if (check_mpu_violation(&cpu, addr, 4, 0)) trigger_exception(&cpu, EXC_MEM_FAULT, cpu.ex_mem.pc);
                    else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] LDRS: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            int val;
                            memcpy(&val, &cpu.memory[addr], 4);
                            next_mem_wb.val_wb = (long long)val;
                            cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                        }
                    } else {
                        int val;
                        memcpy(&val, &cpu.memory[addr], 4);
                        next_mem_wb.val_wb = (long long)val;
                        cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                    }
                    break;
                case OP_LDBS:
                    if (check_mpu_violation(&cpu, addr, 1, 0)) trigger_exception(&cpu, EXC_MEM_FAULT, cpu.ex_mem.pc);
                    else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] LDBS: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            next_mem_wb.val_wb = (char)cpu.memory[addr];
                            cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                        }
                    } else {
                        next_mem_wb.val_wb = (char)cpu.memory[addr];
                        cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                    }
                    break;
                case OP_LDHS:
                    if (check_mpu_violation(&cpu, addr, 2, 0)) trigger_exception(&cpu, EXC_MEM_FAULT, cpu.ex_mem.pc);
                    else if (cpu.cr[0] & (1 << 1)) {  // MTE enabled in CR0 bit 1
                        unsigned char mem_tag = get_memory_tag(addr);
                        if (current_ptr_tag != mem_tag) {
                            printf("[MTE Violation] LDHS: Pointer tag 0x%X does not match memory tag 0x%X at 0x%llX\n", 
                                   current_ptr_tag, mem_tag, addr);
                            trigger_exception(&cpu, EXC_MTE_FAULT, cpu.ex_mem.pc);
                        } else {
                            short val;
                            memcpy(&val, &cpu.memory[addr], 2);
                            next_mem_wb.val_wb = (long long)val;
                            cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                        }
                    } else {
                        short val;
                        memcpy(&val, &cpu.memory[addr], 2);
                        next_mem_wb.val_wb = (long long)val;
                        cpu.taint_regs[cpu.ex_mem.rd] = memory_taint[addr];
                    }
                    break;
            }
        }

        // ==========================================
        // 3. EXECUTE (EX) STAGE
        // ==========================================
        memset(&next_ex_mem, 0, sizeof(EX_MEM_Reg));
        if (cpu.id_ex.active) {
            next_ex_mem.pc = cpu.id_ex.pc;
            next_ex_mem.op = cpu.id_ex.op;
            next_ex_mem.rd = cpu.id_ex.rd;
            next_ex_mem.active = 1;

            long long src1 = cpu.id_ex.val_rs1;
            long long src2 = cpu.id_ex.val_rs2;

            // --- DATA FORWARDING UNIT ---
            // Forward from EX/MEM stage
            if (cpu.ex_mem.active && op_writes_rd(cpu.ex_mem.op)) {
                if (cpu.ex_mem.rd == cpu.id_ex.rs1) src1 = cpu.ex_mem.alu_result;
                if (cpu.ex_mem.rd == cpu.id_ex.rs2) src2 = cpu.ex_mem.alu_result;
            }
            // Forward from MEM/WB stage
            if (cpu.mem_wb.active && op_writes_rd(cpu.mem_wb.op)) {
                if (cpu.mem_wb.rd == cpu.id_ex.rs1) src1 = cpu.mem_wb.val_wb;
                if (cpu.mem_wb.rd == cpu.id_ex.rs2) src2 = cpu.mem_wb.val_wb;
            }

            next_ex_mem.store_data = src2; // Default payload mapping for store operations

            switch (cpu.id_ex.op) {
                case OP_MOV:
                    next_ex_mem.alu_result = src1;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_MOVI:
                    next_ex_mem.alu_result = cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = 0;
                    break;
                case OP_MOVIH:
                    next_ex_mem.alu_result = (cpu.regs[cpu.id_ex.rd] & 0x00000000FFFFFFFFULL) | ((cpu.id_ex.imm & 0x3FFFF) << 32);
                    break;
                case OP_ADD:
                    next_ex_mem.alu_result = src1 + src2;
                    // Propagate taint: if either source register is untrusted, the result is untrusted
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1] | cpu.taint_regs[cpu.id_ex.rs2];
                    break;
                case OP_ADDI:
                    next_ex_mem.alu_result = src1 + cpu.id_ex.imm;
                    // Propagate taint from the source register
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_SUB:
                    next_ex_mem.alu_result = src1 - src2;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1] | cpu.taint_regs[cpu.id_ex.rs2];
                    break;
                case OP_SUBI:
                    next_ex_mem.alu_result = src1 - cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_MUL:
                    next_ex_mem.alu_result = src1 * src2;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1] | cpu.taint_regs[cpu.id_ex.rs2];
                    break;
                case OP_MULI:
                    next_ex_mem.alu_result = src1 * cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_DIV:
                    if (src2 == 0) trigger_exception(&cpu, EXC_ILLEGAL_OP, cpu.id_ex.pc);
                    else {
                        next_ex_mem.alu_result = src1 / src2;
                        cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1] | cpu.taint_regs[cpu.id_ex.rs2];
                    }
                    break;
                case OP_DIVI:
                    if (cpu.id_ex.imm == 0) trigger_exception(&cpu, EXC_ILLEGAL_OP, cpu.id_ex.pc);
                    else {
                        next_ex_mem.alu_result = src1 / cpu.id_ex.imm;
                        cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    }
                    break;
                case OP_AND:
                    next_ex_mem.alu_result = src1 & src2;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1] | cpu.taint_regs[cpu.id_ex.rs2];
                    break;
                case OP_ANDI:
                    next_ex_mem.alu_result = src1 & cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_OR:
                    next_ex_mem.alu_result = src1 | src2;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1] | cpu.taint_regs[cpu.id_ex.rs2];
                    break;
                case OP_ORI:
                    next_ex_mem.alu_result = src1 | cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_XOR:
                    next_ex_mem.alu_result = src1 ^ src2;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1] | cpu.taint_regs[cpu.id_ex.rs2];
                    break;
                case OP_XORI:
                    next_ex_mem.alu_result = src1 ^ cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_SHL:
                    next_ex_mem.alu_result = src1 << cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_SRL:
                    next_ex_mem.alu_result = (unsigned long long)src1 >> cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_SAR:
                case OP_SRA:
                    next_ex_mem.alu_result = src1 >> cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_LEA:
                    next_ex_mem.alu_result = src1 + cpu.id_ex.imm;
                    cpu.taint_regs[cpu.id_ex.rd] = cpu.taint_regs[cpu.id_ex.rs1];
                    break;
                case OP_LDR: case OP_LDB: case OP_LDH: case OP_LDRS: case OP_LDBS: case OP_LDHS:
                case OP_STR: case OP_STB: case OP_STH:
                    next_ex_mem.alu_result = src1 + cpu.id_ex.imm;
                    // --- MTE Pointer Tag Propagation ---
                    // Extract and propagate the MTE tag from the base pointer register
                    current_ptr_tag = register_mte_tags[cpu.id_ex.rs1];
                    break;
                case OP_PUSH:
                    next_ex_mem.alu_result = cpu.regs[13] - 8;
                    next_ex_mem.store_data = src1; // Data to be stored is pushed from rs1
                    break;
                case OP_POP:
                    next_ex_mem.alu_result = cpu.regs[13];
                    break;
                case OP_CMP:
                    if (src1 == src2) cpu.cr[0] = (cpu.cr[0] & 1); 
                    else if (src1 > src2) cpu.cr[0] = (cpu.cr[0] & 1) | (1LL << 2);
                    else cpu.cr[0] = (cpu.cr[0] & 1) | (1LL << 3);
                    break;
                case OP_CMPI:
                    if (src1 == cpu.id_ex.imm) cpu.cr[0] = (cpu.cr[0] & 1);
                    else if (src1 > cpu.id_ex.imm) cpu.cr[0] = (cpu.cr[0] & 1) | (1LL << 2);
                    else cpu.cr[0] = (cpu.cr[0] & 1) | (1LL << 3);
                    break;
                case OP_B:
                    cpu.regs[15] = cpu.id_ex.target;
                    cpu.control_flush = 1;
                    break;
                case OP_BEQ: {
                    int actual_taken = ((cpu.cr[0] >> 2) == 0);
                    long long true_target = actual_taken ? (cpu.id_ex.pc + cpu.id_ex.imm - 4) : (cpu.id_ex.pc + 4);
                    
                    // Find or allocate a slot in the BTB
                    int btb_index = -1;
                    for (int i = 0; i < BTB_SIZE; i++) {
                        if (cpu.btb[i].valid && cpu.btb[i].src_pc == cpu.id_ex.pc) {
                            btb_index = i;
                            break;
                        }
                    }
                    if (btb_index == -1) { // If missing, find an invalid space to provision
                        for (int i = 0; i < BTB_SIZE; i++) {
                            if (!cpu.btb[i].valid) {
                                btb_index = i;
                                cpu.btb[btb_index].valid = 1;
                                cpu.btb[btb_index].src_pc = cpu.id_ex.pc;
                                cpu.btb[btb_index].history = 0; 
                                break;
                            }
                        }
                    }

                    // Update the predictor's directional history bit saturation values
                    if (btb_index != -1) {
                        cpu.btb[btb_index].target_pc = cpu.id_ex.pc + cpu.id_ex.imm - 4;
                        if (actual_taken) {
                            if (cpu.btb[btb_index].history < 1) cpu.btb[btb_index].history++;
                        } else {
                            if (cpu.btb[btb_index].history > 0) cpu.btb[btb_index].history--;
                        }
                    }

                    // Misprediction Validation Check: Did the speculative PC sequence miss the mark?
                    // If the next pipeline stage PC does not equal our real target, flush immediately.
                    if (cpu.regs[15] != true_target) {
                        sc_track_misprediction();  // Track branch misprediction
                        cpu.regs[15] = true_target;
                        cpu.control_flush = 1; // Flush downstream bad-path latches
                    }
                    break;
                }
                case OP_BNE:
                    if ((cpu.cr[0] >> 2) != 0) { cpu.regs[15] = cpu.id_ex.pc + cpu.id_ex.imm - 4; cpu.control_flush = 1; }
                    break;
                case OP_BGT:
                    if ((cpu.cr[0] >> 2) & 1) { cpu.regs[15] = cpu.id_ex.pc + cpu.id_ex.imm - 4; cpu.control_flush = 1; }
                    break;
                case OP_BLT:
                    if ((cpu.cr[0] >> 3) & 1) { cpu.regs[15] = cpu.id_ex.pc + cpu.id_ex.imm - 4; cpu.control_flush = 1; }
                    break;
                case OP_BLE:
                    if (((cpu.cr[0] >> 3) & 1) || ((cpu.cr[0] >> 2) == 0)) { cpu.regs[15] = cpu.id_ex.pc + cpu.id_ex.imm - 4; cpu.control_flush = 1; }
                    break;
                case OP_BGE:
                    if (((cpu.cr[0] >> 2) & 1) || ((cpu.cr[0] >> 2) == 0)) { cpu.regs[15] = cpu.id_ex.pc + cpu.id_ex.imm - 4; cpu.control_flush = 1; }
                    break;
                case OP_BL:
                    cpu.regs[14] = cpu.id_ex.pc + 4;
                    // Sign return address with PAC before storing on shadow stack
                    if (cpu.ssp < 1024) {
                        uint64_t signed_ret = pac_sign_pointer((uint64_t)cpu.regs[14], 0);
                        cpu.shadow_stack[cpu.ssp++] = (long long)signed_ret;
                    }
                    cpu.regs[15] = cpu.id_ex.pc + cpu.id_ex.imm - 4;
                    cpu.control_flush = 1;
                    break;
                case OP_BX:
                    if (cpu.id_ex.rs1 == 14) {
                        // Backward-edge: PAC + shadow stack protection
                        if (cpu.ssp > 0) {
                            long long signed_return = cpu.shadow_stack[--cpu.ssp];
                            // Verify PAC signature
                            if (pac_authenticate_pointer((uint64_t)signed_return, 0) != 0) {
                                trigger_exception(&cpu, EXC_CFI_FAULT, cpu.id_ex.pc);
                                break;
                            }
                            long long actual_return = signed_return & 0x00FFFFFFFFFFFFFFULL;
                            if (cpu.regs[14] != actual_return) {
                                trigger_exception(&cpu, EXC_ROP_FAULT, cpu.id_ex.pc);
                                break;
                            }
                        } else {
                            trigger_exception(&cpu, EXC_ROP_FAULT, cpu.id_ex.pc);
                            break;
                        }
                        cpu.regs[15] = src1;
                        cpu.control_flush = 1;
                    } else {
                        // Forward-edge: CFI landing pad validation
                        if (cfi_validate_indirect_target(src1) != 0) {
                            trigger_exception(&cpu, EXC_CFI_FAULT, cpu.id_ex.pc);
                            break;
                        }
                        cpu.regs[15] = src1;
                        cpu.control_flush = 1;
                    }
                    sc_track_cycle();
                    break;
                case OP_JALR:
                    if (cpu.id_ex.rs1 == 14) {
                        if (cpu.ssp > 0) {
                            long long expected_return = cpu.shadow_stack[--cpu.ssp];
                            if (cpu.regs[14] != expected_return) { trigger_exception(&cpu, EXC_ROP_FAULT, cpu.id_ex.pc); break; }
                        } else { trigger_exception(&cpu, EXC_ROP_FAULT, cpu.id_ex.pc); break; }
                    }
                    if (cpu.id_ex.rd == 14) {
                        if (cpu.ssp < 1024) { cpu.shadow_stack[cpu.ssp++] = cpu.id_ex.pc + 4; }
                    }
                    
                    // Forward-edge check for indirect call targets (when not returning via R14)
                    if (cpu.id_ex.rs1 != 14) {
                        long long target_addr = src1 + cpu.id_ex.imm;
                        if (target_addr >= 0 && (target_addr + 4) <= 40960) {
                            unsigned int target_instr;
                            memcpy(&target_instr, &cpu.memory[target_addr], sizeof(unsigned int));
                            unsigned char target_op = (target_instr >> 26) & 0x3F;
                            
                            if (target_op != OP_NOP) {
                                trigger_exception(&cpu, EXC_CFI_FAULT, cpu.id_ex.pc);
                                break;
                            }
                        }
                    }
                    
                    next_ex_mem.alu_result = cpu.id_ex.pc + 4;
                    cpu.regs[15] = src1 + cpu.id_ex.imm;
                    cpu.control_flush = 1;
                    break;
                case OP_RFE:
                case OP_ERET:
                    if (get_privilege_level(&cpu) == PRIV_KERNEL) {
                        cpu.regs[15] = cpu.cr[3]; 
                        cpu.regs[13] = cpu.cr[2]; 
                        cpu.cr[0] |= PRIV_USER;   
                        cpu.control_flush = 1;
                    }
                    break;
                default:
                    break;
            }
        }

        // ==========================================
        // 2. INSTRUCTION DECODE (ID) STAGE
        // ==========================================
        memset(&next_id_ex, 0, sizeof(ID_EX_Reg));
        if (cpu.if_id.active) {
            unsigned int instr = cpu.if_id.instr;
            unsigned char op   = (instr >> 26) & 0x3F;
            unsigned char rd   = (instr >> 22) & 0x0F;
            unsigned char rs1  = (instr >> 18) & 0x0F;
            unsigned char rs2  = (instr >> 14) & 0x0F;
            long long imm      = sign_extend_18(instr & 0x3FFFF);
            int target         = instr & 0x3FFFFFF;

            // --- HAZARD DETECTION UNIT (Load-to-Use) ---
            if (cpu.id_ex.active && op_is_load(cpu.id_ex.op)) {
                if (cpu.id_ex.rd == rs1 || cpu.id_ex.rd == rs2) {
                    cpu.hazard_stall = 1; // Bubble the pipeline
                }
            }

            if (!cpu.hazard_stall) {
                log_instruction(cpu.if_id.pc, op, rd, rs1, rs2, imm, target);

                // Privilege Ring Exception Enforcement
                if (get_privilege_level(&cpu) == PRIV_USER) {
                    if (op == OP_MCR || op == OP_RFE || op == OP_CLI || op == OP_STI || 
                        op == OP_IEV || op == OP_TLBIV || op == OP_ERET || op == OP_SYS) {
                        trigger_exception(&cpu, EXC_PRIV_VIOL, cpu.if_id.pc);
                    }
                }

                // DTT Security Intercept Policy Check
                if (((op == OP_BX || op == OP_BLX || op == OP_JALR) && cpu.taint_regs[rs1]) ||
                    ((op == OP_LDR || op == OP_STR || op == OP_LDB || op == OP_STB) && cpu.taint_regs[rs1])) {
                    trigger_exception(&cpu, EXC_TAINT_FAULT, cpu.if_id.pc);
                }

                next_id_ex.pc = cpu.if_id.pc;
                next_id_ex.op = op;
                next_id_ex.rd = rd;
                next_id_ex.rs1 = rs1;
                next_id_ex.rs2 = rs2;
                next_id_ex.imm = imm;
                next_id_ex.target = target;
                next_id_ex.val_rs1 = cpu.regs[rs1];
                next_id_ex.val_rs2 = cpu.regs[rs2];
                next_id_ex.active = 1;
            }
        }

        // ==========================================
        // 1. INSTRUCTION FETCH (IF) STAGE
        // ==========================================
        memset(&next_if_id, 0, sizeof(IF_ID_Reg));
        if (running && !cpu.hazard_stall) {
            long long current_pc = cpu.regs[15];
            
            int fetch_fault = check_mpu_violation(&cpu, current_pc, 4, PERM_X);
            if (fetch_fault == 1) {
                trigger_exception(&cpu, EXC_MEM_FAULT, current_pc);
            } else if (fetch_fault == 2) {
                trigger_exception(&cpu, EXC_NX_FAULT, current_pc);
            } else {
                next_if_id.pc = current_pc;
                memcpy(&next_if_id.instr, &cpu.memory[current_pc], sizeof(unsigned int));
                next_if_id.active = 1;

                // Check Branch Target Buffer for a predictive hit
                int predicted_taken = 0;
                long long predicted_target = current_pc + 4;
                int btb_hit = 0;

                for (int i = 0; i < BTB_SIZE; i++) {
                    if (cpu.btb[i].valid && cpu.btb[i].src_pc == current_pc) {
                        btb_hit = 1;
                        sc_track_btb_hit();  // Track BTB hit
                        if (cpu.btb[i].history >= 1) {
                            predicted_taken = 1;
                            predicted_target = cpu.btb[i].target_pc;
                            sc_track_speculative_execution();  // Speculative branch
                        }
                        break;
                    }
                }
                if (!btb_hit) {
                    sc_track_btb_miss();  // Track BTB miss
                }

                cpu.regs[15] = predicted_target; // Divert PC speculatively if predictor says so
            }
        }

        // ==========================================
        // PIPELINE LATCH LATENCY COMMITMENT
        // ==========================================
        if (cpu.control_flush) {
            // Correctly flush speculative stages (IF/ID and ID/EX) up to the faulting branch.
            // Do NOT wipe out ex_mem or mem_wb, allowing the branch instruction itself 
            // to progress to Writeback and commit cleanly!
            memset(&cpu.if_id, 0, sizeof(IF_ID_Reg));
            memset(&cpu.id_ex, 0, sizeof(ID_EX_Reg));
            
            cpu.ex_mem = next_ex_mem;
            cpu.mem_wb = next_mem_wb;
            cpu.control_flush = 0;
        } else {
            if (!cpu.hazard_stall) {
                cpu.if_id = next_if_id;
            } else {
                // If we are stalling, ensure we don't accidentally pass a duplicate 
                // instruction context down into the execution units
                memset(&next_id_ex, 0, sizeof(ID_EX_Reg));
            }
            cpu.id_ex  = next_id_ex;
            cpu.ex_mem = next_ex_mem;
            cpu.mem_wb = next_mem_wb;
        }

        // Fast-path hardware termination: Stop immediately when HLT commits at WB
        if (!running) {
            break;
        }
        // sleep(1); // Makes it so it is 2s delay per instruction executed.
    }

    print_cpu_state(&cpu);
    printf("Total Clock Cycles Simulated: %llu\n", clock_cycles);
    printf("Total Instructions Committed: %llu\n", instructions_executed);
    printf("\n");
    sc_report_metrics();
    return 0;
}