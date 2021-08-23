# Emmett

Just run your program, jump in your DMC-12 and pretend it's 1955 all over again.

## How does that work?

This works by relying on seccomp-ebpf, which ensures all the children will be handled. Two things are hooked:
 - linux-vdso.so
   For dynamicaly-linked ELF, glibc's gettimeofday is actually completely userland. This works by having the kernel share a DLSO providing a shared mapping with the current time of the day.
   This vdso address is injected with the auxiliary vector.

   What we'll do here, is to hook onto the execve return, before the elf interp or the static binary has any chance to run or lookup anything, and we'll rewrite the vdso pointer right from underneath.

 - syscalls `clock_gettime`, `gettimeofday`, just the regular way.
