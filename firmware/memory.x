/*
 * Linker script for the nanobyte mote — rv32imc, 32 KB NOR flash, 8 KB SRAM.
 * Block 0.0 placeholder: pinned sizes only, no real boot sequence yet.
 * Real bootloader (triple-redundant A/B/C decode) lands in Block 0.1.
 */

MEMORY
{
    FLASH : ORIGIN = 0x20000000, LENGTH = 32K
    RAM   : ORIGIN = 0x80000000, LENGTH = 8K
}

/* Symbol aliases used by the runtime crate once we pick one (riscv-rt or
 * a hand-rolled reset vector + vector table). Defined as zero placeholders
 * so this file parses cleanly without a runtime dependency. */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);
_heap_size = 0;  /* no heap — panic=abort + no_std + no allocator */

/* Triple-redundant flash image slots. Bootloader picks the highest-versioned
 * slot whose CRC passes. Three slots × 10 KB leaves 2 KB for the bootloader.
 * Block 0.1 wires these up. */
_flash_boot  = ORIGIN(FLASH);
_flash_slot_a = ORIGIN(FLASH) + 2K;
_flash_slot_b = ORIGIN(FLASH) + 12K;
_flash_slot_c = ORIGIN(FLASH) + 22K;
