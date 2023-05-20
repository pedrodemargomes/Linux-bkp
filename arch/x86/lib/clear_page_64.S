#include <linux/linkage.h>
#include <asm/export.h>

/*
 * Most CPUs support enhanced REP MOVSB/STOSB instructions. It is
 * recommended to use this when possible and we do use them by default.
 * If enhanced REP MOVSB/STOSB is not available, try to use fast string.
 * Otherwise, use original.
 */

/*
 * Zero a page.
 * %rdi	- page
 */
ENTRY(clear_page_rep)
	movl $4096/8,%ecx
	xorl %eax,%eax
	rep stosq
	ret
ENDPROC(clear_page_rep)
EXPORT_SYMBOL_GPL(clear_page_rep)

ENTRY(clear_page_orig)
	xorl   %eax,%eax
	movl   $4096/64,%ecx
	.p2align 4
.Lloop:
	decl	%ecx
#define PUT(x) movq %rax,x*8(%rdi)
	movq %rax,(%rdi)
	PUT(1)
	PUT(2)
	PUT(3)
	PUT(4)
	PUT(5)
	PUT(6)
	PUT(7)
	leaq	64(%rdi),%rdi
	jnz	.Lloop
	nop
	ret
ENDPROC(clear_page_orig)
EXPORT_SYMBOL_GPL(clear_page_orig)

ENTRY(clear_page_erms)
	movl $4096,%ecx
	xorl %eax,%eax
	rep stosb
	ret
ENDPROC(clear_page_erms)
EXPORT_SYMBOL_GPL(clear_page_erms)

ENTRY(sse2_pagezero_chunk)
	addq    %rsi,%rdi
	neg		%rsi
	xorl    %eax,%eax
	jmp     1f
	/*
		* The loop takes 29 bytes.  Ensure that it doesn`t cross a 32-byte
		* cache line.
		*/
	.p2align 5,0x90
1:
	movnti  %rax,(%rdi,%rsi)
	movnti  %rax,8(%rdi,%rsi)
	movnti  %rax,16(%rdi,%rsi)
	movnti  %rax,24(%rdi,%rsi)
	addq    $32,%rsi
	jne     1b
	sfence
	ret
ENDPROC(sse2_pagezero_chunk)
EXPORT_SYMBOL_GPL(sse2_pagezero_chunk)
