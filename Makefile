#!/usr/bin/env nix-shell
#!nix-shell -i "make -f" -p gnumake clang-tools pkg-config glib llvmPackages.bintools

CFLAGS+=$(shell pkg-config --cflags glib-2.0)
LDFLAGS+=$(shell pkg-config --libs glib-2.0)

emmett: emmett.o

debug: debug.o

.PHONY: test
test: emmett debug
	./$< ./debug 2>&1
	./$< bash -xc "date; sleep 2; date" 2>&1

.PHONY: format
format:
	clang-format -i vdso.c emmett.c debug.c

CFLAGS += -m64 -mcmodel=small -fPIC
VDSO_LDFLAGS = -nostdlib -shared -Bsymbolic
VDSO_LDFLAGS.lds = -m elf_x86_64 -soname linux-vdso.so.1 \
			-z max-page-size=4096


vdso.so: vdso.o vdso.lds Makefile
	$(LD) $(VDSO_LDFLAGS) -o $@ \
		$(VDSO_LDFLAGS.lds) \
		-T vdso.lds $<
	#ldd $@
	objdump -x $@

emmett.o: emmett.c vdso.so
