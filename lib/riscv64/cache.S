#include "edk2asm.h"

       .file   "cache.S"
       .text

GCC_ASM_EXPORT(__riscv_flush_icache)

ASM_PFX(__riscv_flush_icache):
       .word 0x0100000f
       ret
