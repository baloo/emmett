SECTIONS
{
 vvar_start = . - 4 * (1 << 12);
 vvar_page = vvar_start;


vvar__vdso_data = vvar_page + 128;

 pvclock_page = vvar_start + (1 << 12);
 hvclock_page = vvar_start + 2 * (1 << 12);
 timens_page = vvar_start + 3 * (1 << 12);

timens__vdso_data = timens_page + 128;


 . = SIZEOF_HEADERS;

 .hash : { *(.hash) } :text
 .gnu.hash : { *(.gnu.hash) }
 .dynsym : { *(.dynsym) }
 .dynstr : { *(.dynstr) }
 .gnu.version : { *(.gnu.version) }
 .gnu.version_d : { *(.gnu.version_d) }
 .gnu.version_r : { *(.gnu.version_r) }

 .dynamic : { *(.dynamic) } :text :dynamic

 .rodata : {
  *(.rodata*)
  *(.data*)
  *(.sdata*)
  *(.got.plt) *(.got)
  *(.gnu.linkonce.d.*)
  *(.bss*)
  *(.dynbss*)
  *(.gnu.linkonce.b.*)
 } :text

 /DISCARD/ : {
  *(.note.gnu.property)
 }
 .note : { *(.note.*) } :text :note

 .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
 .eh_frame : { KEEP (*(.eh_frame)) } :text

 .text : {
  *(.text*)
  *(.fixup)
 } :text =0x90909090,



 .altinstructions : { *(.altinstructions) } :text
 .altinstr_replacement : { *(.altinstr_replacement) } :text

 __ex_table : { *(__ex_table) } :text

 /DISCARD/ : {
  *(.discard)
  *(.discard.*)
  *(__bug_table)
 }
}

PHDRS
{
 text PT_LOAD FLAGS(5) FILEHDR PHDRS; /* PF_R|PF_X */
 dynamic PT_DYNAMIC FLAGS(4); /* PF_R */
 note PT_NOTE FLAGS(4); /* PF_R */
 eh_frame_hdr 0x6474e550;
}

/*
 * This controls what userland symbols we export from the vDSO.
 */
VERSION {
 LINUX_2.6 {
 global:
  clock_gettime;
  __vdso_clock_gettime;
  gettimeofday;
  __vdso_gettimeofday;
  /*getcpu;
  __vdso_getcpu;
  time;
  __vdso_time;
  /*clock_getres;
  __vdso_clock_getres;
  /* __vdso_sgx_enter_enclave; */
 local: *;
 };
}
