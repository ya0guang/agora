
test.o:	file format ELF64-x86-64

Disassembly of section .text:
__sgx_function_magic_0:
       0:	9a  <unknown>
       1:	9a  <unknown>
       2:	9a  <unknown>
       3:	9a  <unknown>
       4:	9a  <unknown>
       5:	9a  <unknown>
       6:	9a  <unknown>
       7:	9a  <unknown>
       8:	4f 00 00 	addb	%r8b, (%r8)
       b:	00 00 	addb	%al, (%rax)
       d:	00 00 	addb	%al, (%rax)
       f:	00 55 48 	addb	%dl, 72(%rbp)

test_struct_1:
      10:	55 	pushq	%rbp
      11:	48 89 e5 	movq	%rsp, %rbp
      14:	48 83 ec 00 	subq	$0, %rsp
      18:	64 67 48 89 7d f0 	movq	%rdi, %fs:-16(%ebp)
      1e:	64 67 89 75 fc 	movl	%esi, %fs:-4(%ebp)
      23:	64 67 48 63 45 fc 	movslq	%fs:-4(%ebp), %rax
      29:	64 67 48 8b 4d f0 	movq	%fs:-16(%ebp), %rcx
      2f:	64 67 48 8b 09 	movq	%fs:(%ecx), %rcx
      34:	65 67 8b 04 81 	movl	%gs:(%ecx,%eax,4), %eax
      39:	65 67 89 45 ec 	movl	%eax, %gs:-20(%ebp)
      3e:	48 83 ec 00 	subq	$0, %rsp
      42:	5d 	popq	%rbp
      43:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_private_0:
      47:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
      51:	49 f7 d3 	notq	%r11
      54:	4d 39 1a 	cmpq	%r11, (%r10)
      57:	75 09 	jne	9 <__test_struct_1__int3>
      59:	41 5b 	popq	%r11
      5b:	49 83 c2 08 	addq	$8, %r10
      5f:	41 ff e2 	jmpq	*%r10

__test_struct_1__int3:
      62:	cc 	int3
      63:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)

__sgx_function_magic_1:
      70:	9a  <unknown>
      71:	9a  <unknown>
      72:	9a  <unknown>
      73:	9a  <unknown>
      74:	9a  <unknown>
      75:	9a  <unknown>
      76:	9a  <unknown>
      77:	9a  <unknown>
      78:	1f  <unknown>
      79:	00 00 	addb	%al, (%rax)
      7b:	00 00 	addb	%al, (%rax)
      7d:	00 00 	addb	%al, (%rax)
      7f:	00 55 48 	addb	%dl, 72(%rbp)

test_struct_2:
      80:	55 	pushq	%rbp
      81:	48 89 e5 	movq	%rsp, %rbp
      84:	48 83 ec 00 	subq	$0, %rsp
      88:	64 67 48 89 7d f8 	movq	%rdi, %fs:-8(%ebp)
      8e:	64 67 8b 47 08 	movl	%fs:8(%edi), %eax
      93:	48 83 ec 00 	subq	$0, %rsp
      97:	5d 	popq	%rbp
      98:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_public_0:
      9c:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
      a6:	49 f7 d3 	notq	%r11
      a9:	4d 39 1a 	cmpq	%r11, (%r10)
      ac:	75 09 	jne	9 <__test_struct_2__int3>
      ae:	41 5b 	popq	%r11
      b0:	49 83 c2 08 	addq	$8, %r10
      b4:	41 ff e2 	jmpq	*%r10

__test_struct_2__int3:
      b7:	cc 	int3
      b8:	0f 1f 84 00 00 00 00 00 	nopl	(%rax,%rax)

__sgx_function_magic_2:
      c0:	9a  <unknown>
      c1:	9a  <unknown>
      c2:	9a  <unknown>
      c3:	9a  <unknown>
      c4:	9a  <unknown>
      c5:	9a  <unknown>
      c6:	9a  <unknown>
      c7:	9a  <unknown>
      c8:	1f  <unknown>
      c9:	00 00 	addb	%al, (%rax)
      cb:	00 00 	addb	%al, (%rax)
      cd:	00 00 	addb	%al, (%rax)
      cf:	00 55 48 	addb	%dl, 72(%rbp)

copy_key:
      d0:	55 	pushq	%rbp
      d1:	48 89 e5 	movq	%rsp, %rbp
      d4:	48 83 ec 20 	subq	$32, %rsp
      d8:	64 67 48 89 7d f0 	movq	%rdi, %fs:-16(%ebp)
      de:	bf 10 00 00 00 	movl	$16, %edi
      e3:	4d 31 c9 	xorq	%r9, %r9
      e6:	4d 31 c0 	xorq	%r8, %r8
      e9:	48 31 c9 	xorq	%rcx, %rcx
      ec:	48 31 d2 	xorq	%rdx, %rdx
      ef:	48 31 f6 	xorq	%rsi, %rsi
      f2:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_0>

__sgx_callsite_magic_public_0:
      f7:	9a  <unknown>
      f8:	9a  <unknown>
      f9:	9a  <unknown>
      fa:	9a  <unknown>
      fb:	9a  <unknown>
      fc:	9a  <unknown>
      fd:	9a  <unknown>
      fe:	9a  <unknown>
      ff:	64 67 48 89 45 f8 	movq	%rax, %fs:-8(%ebp)
     105:	48 85 c0 	testq	%rax, %rax
     108:	0f 84 ab 00 00 00 	je	171 <__sgx_callsite_magic_public_3+0x8>
     10e:	bf 00 01 00 00 	movl	$256, %edi
     113:	4d 31 c9 	xorq	%r9, %r9
     116:	4d 31 c0 	xorq	%r8, %r8
     119:	48 31 c9 	xorq	%rcx, %rcx
     11c:	48 31 d2 	xorq	%rdx, %rdx
     11f:	48 31 f6 	xorq	%rsi, %rsi
     122:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_1>

__sgx_callsite_magic_public_1:
     127:	9a  <unknown>
     128:	9a  <unknown>
     129:	9a  <unknown>
     12a:	9a  <unknown>
     12b:	9a  <unknown>
     12c:	9a  <unknown>
     12d:	9a  <unknown>
     12e:	9a  <unknown>
     12f:	64 67 48 8b 4d f8 	movq	%fs:-8(%ebp), %rcx
     135:	64 67 48 89 01 	movq	%rax, %fs:(%ecx)
     13a:	64 67 48 8b 45 f8 	movq	%fs:-8(%ebp), %rax
     140:	64 67 48 83 38 00 	cmpq	$0, %fs:(%eax)
     146:	74 52 	je	82 <__sgx_callsite_magic_public_2+0x2C>
     148:	64 67 48 8b 45 f8 	movq	%fs:-8(%ebp), %rax
     14e:	64 67 48 8b 38 	movq	%fs:(%eax), %rdi
     153:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     159:	64 67 48 8b 30 	movq	%fs:(%eax), %rsi
     15e:	ba 00 01 00 00 	movl	$256, %edx
     163:	4d 31 c9 	xorq	%r9, %r9
     166:	4d 31 c0 	xorq	%r8, %r8
     169:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_2>

__sgx_callsite_magic_public_2:
     16e:	9a  <unknown>
     16f:	9a  <unknown>
     170:	9a  <unknown>
     171:	9a  <unknown>
     172:	9a  <unknown>
     173:	9a  <unknown>
     174:	9a  <unknown>
     175:	9a  <unknown>
     176:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     17c:	64 67 8b 40 08 	movl	%fs:8(%eax), %eax
     181:	64 67 48 8b 4d f8 	movq	%fs:-8(%ebp), %rcx
     187:	64 67 89 41 08 	movl	%eax, %fs:8(%ecx)
     18c:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     192:	64 67 48 89 45 e8 	movq	%rax, %fs:-24(%ebp)
     198:	eb 29 	jmp	41 <__sgx_callsite_magic_public_3+0x12>
     19a:	64 67 48 8b 7d f8 	movq	%fs:-8(%ebp), %rdi
     1a0:	4d 31 c9 	xorq	%r9, %r9
     1a3:	4d 31 c0 	xorq	%r8, %r8
     1a6:	48 31 d2 	xorq	%rdx, %rdx
     1a9:	48 31 f6 	xorq	%rsi, %rsi
     1ac:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_3>

__sgx_callsite_magic_public_3:
     1b1:	9a  <unknown>
     1b2:	9a  <unknown>
     1b3:	9a  <unknown>
     1b4:	9a  <unknown>
     1b5:	9a  <unknown>
     1b6:	9a  <unknown>
     1b7:	9a  <unknown>
     1b8:	9a  <unknown>
     1b9:	64 67 48 c7 45 e8 00 00 00 00 	movq	$0, %fs:-24(%ebp)
     1c3:	64 67 48 8b 45 e8 	movq	%fs:-24(%ebp), %rax
     1c9:	48 83 c4 20 	addq	$32, %rsp
     1cd:	5d 	popq	%rbp
     1ce:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_public_1:
     1d2:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
     1dc:	49 f7 d3 	notq	%r11
     1df:	4d 39 1a 	cmpq	%r11, (%r10)
     1e2:	75 09 	jne	9 <__int3_label_2>
     1e4:	41 5b 	popq	%r11
     1e6:	49 83 c2 08 	addq	$8, %r10
     1ea:	41 ff e2 	jmpq	*%r10

__int3_label_2:
     1ed:	cc 	int3
     1ee:	66 90 	nop

__sgx_function_magic_3:
     1f0:	9a  <unknown>
     1f1:	9a  <unknown>
     1f2:	9a  <unknown>
     1f3:	9a  <unknown>
     1f4:	9a  <unknown>
     1f5:	9a  <unknown>
     1f6:	9a  <unknown>
     1f7:	9a  <unknown>
     1f8:	1f  <unknown>
     1f9:	00 00 	addb	%al, (%rax)
     1fb:	00 00 	addb	%al, (%rax)
     1fd:	00 00 	addb	%al, (%rax)
     1ff:	00 55 48 	addb	%dl, 72(%rbp)

is_valid_key:
     200:	55 	pushq	%rbp
     201:	48 89 e5 	movq	%rsp, %rbp
     204:	48 83 ec 00 	subq	$0, %rsp
     208:	64 67 48 89 7d f0 	movq	%rdi, %fs:-16(%ebp)
     20e:	48 85 ff 	testq	%rdi, %rdi
     211:	74 5c 	je	92 <is_valid_key+0x6F>
     213:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     219:	64 67 48 83 38 00 	cmpq	$0, %fs:(%eax)
     21f:	74 4e 	je	78 <is_valid_key+0x6F>
     221:	64 67 c7 45 fc 00 00 00 00 	movl	$0, %fs:-4(%ebp)
     22a:	eb 09 	jmp	9 <is_valid_key+0x35>
     22c:	0f 1f 40 00 	nopl	(%rax)
     230:	64 67 ff 45 fc 	incl	%fs:-4(%ebp)
     235:	64 67 83 7d fc 3f 	cmpl	$63, %fs:-4(%ebp)
     23b:	7f 65 	jg	101 <__is_valid_key__int3+0x1>
     23d:	64 67 48 63 45 fc 	movslq	%fs:-4(%ebp), %rax
     243:	64 67 48 8b 4d f0 	movq	%fs:-16(%ebp), %rcx
     249:	64 67 48 8b 09 	movq	%fs:(%ecx), %rcx
     24e:	65 67 83 3c 81 00 	cmpl	$0, %gs:(%ecx,%eax,4)
     254:	78 19 	js	25 <is_valid_key+0x6F>
     256:	64 67 48 63 45 fc 	movslq	%fs:-4(%ebp), %rax
     25c:	64 67 48 8b 4d f0 	movq	%fs:-16(%ebp), %rcx
     262:	64 67 48 8b 09 	movq	%fs:(%ecx), %rcx
     267:	65 67 83 3c 81 65 	cmpl	$101, %gs:(%ecx,%eax,4)
     26d:	7c c1 	jl	-63 <is_valid_key+0x30>
     26f:	64 67 c7 45 f8 ff ff ff ff 	movl	$4294967295, %fs:-8(%ebp)
     278:	64 67 8b 45 f8 	movl	%fs:-8(%ebp), %eax
     27d:	48 83 ec 00 	subq	$0, %rsp
     281:	5d 	popq	%rbp
     282:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_public_2:
     286:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
     290:	49 f7 d3 	notq	%r11
     293:	4d 39 1a 	cmpq	%r11, (%r10)
     296:	75 09 	jne	9 <__is_valid_key__int3>
     298:	41 5b 	popq	%r11
     29a:	49 83 c2 08 	addq	$8, %r10
     29e:	41 ff e2 	jmpq	*%r10

__is_valid_key__int3:
     2a1:	cc 	int3
     2a2:	64 67 c7 45 f8 00 00 00 00 	movl	$0, %fs:-8(%ebp)
     2ab:	eb cb 	jmp	-53 <is_valid_key+0x78>
     2ad:	0f 1f 00 	nopl	(%rax)

__sgx_function_magic_4:
     2b0:	9a  <unknown>
     2b1:	9a  <unknown>
     2b2:	9a  <unknown>
     2b3:	9a  <unknown>
     2b4:	9a  <unknown>
     2b5:	9a  <unknown>
     2b6:	9a  <unknown>
     2b7:	9a  <unknown>
     2b8:	0f 00 00 	sldtw	(%rax)
     2bb:	00 00 	addb	%al, (%rax)
     2bd:	00 00 	addb	%al, (%rax)
     2bf:	00 55 48 	addb	%dl, 72(%rbp)

enc_dec:
     2c0:	55 	pushq	%rbp
     2c1:	48 89 e5 	movq	%rsp, %rbp
     2c4:	48 83 ec 20 	subq	$32, %rsp
     2c8:	64 67 48 89 7d e8 	movq	%rdi, %fs:-24(%ebp)
     2ce:	64 67 48 89 75 e0 	movq	%rsi, %fs:-32(%ebp)
     2d4:	65 67 89 55 f4 	movl	%edx, %gs:-12(%ebp)
     2d9:	64 67 48 8b 7d e8 	movq	%fs:-24(%ebp), %rdi
     2df:	4d 31 c9 	xorq	%r9, %r9
     2e2:	4d 31 c0 	xorq	%r8, %r8
     2e5:	48 31 c9 	xorq	%rcx, %rcx
     2e8:	48 31 d2 	xorq	%rdx, %rdx
     2eb:	e8 10 ff ff ff 	callq	-240 <is_valid_key>

__sgx_callsite_magic_public_4:
     2f0:	9a  <unknown>
     2f1:	9a  <unknown>
     2f2:	9a  <unknown>
     2f3:	9a  <unknown>
     2f4:	9a  <unknown>
     2f5:	9a  <unknown>
     2f6:	9a  <unknown>
     2f7:	9a  <unknown>
     2f8:	85 c0 	testl	%eax, %eax
     2fa:	74 0b 	je	11 <__sgx_callsite_magic_public_4+0x17>
     2fc:	64 67 c7 45 f8 ff ff ff ff 	movl	$4294967295, %fs:-8(%ebp)
     305:	eb 68 	jmp	104 <__sgx_callsite_magic_public_4+0x7F>
     307:	64 67 c7 45 fc 00 00 00 00 	movl	$0, %fs:-4(%ebp)
     310:	eb 48 	jmp	72 <__sgx_callsite_magic_public_4+0x6A>
     312:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)
     320:	64 67 48 63 45 fc 	movslq	%fs:-4(%ebp), %rax
     326:	89 c1 	movl	%eax, %ecx
     328:	c1 f9 1f 	sarl	$31, %ecx
     32b:	c1 e9 1a 	shrl	$26, %ecx
     32e:	01 c1 	addl	%eax, %ecx
     330:	83 e1 c0 	andl	$-64, %ecx
     333:	89 c2 	movl	%eax, %edx
     335:	29 ca 	subl	%ecx, %edx
     337:	48 63 ca 	movslq	%edx, %rcx
     33a:	64 67 48 8b 55 e8 	movq	%fs:-24(%ebp), %rdx
     340:	64 67 48 8b 12 	movq	%fs:(%edx), %rdx
     345:	65 67 8b 0c 8a 	movl	%gs:(%edx,%ecx,4), %ecx
     34a:	64 67 48 8b 55 e0 	movq	%fs:-32(%ebp), %rdx
     350:	65 67 31 0c 82 	xorl	%ecx, %gs:(%edx,%eax,4)
     355:	64 67 ff 45 fc 	incl	%fs:-4(%ebp)
     35a:	64 67 8b 45 fc 	movl	%fs:-4(%ebp), %eax
     35f:	65 67 3b 45 f4 	cmpl	%gs:-12(%ebp), %eax
     364:	7c ba 	jl	-70 <__sgx_callsite_magic_public_4+0x30>
     366:	64 67 c7 45 f8 00 00 00 00 	movl	$0, %fs:-8(%ebp)
     36f:	64 67 8b 45 f8 	movl	%fs:-8(%ebp), %eax
     374:	48 83 c4 20 	addq	$32, %rsp
     378:	5d 	popq	%rbp
     379:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_public_3:
     37d:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
     387:	49 f7 d3 	notq	%r11
     38a:	4d 39 1a 	cmpq	%r11, (%r10)
     38d:	75 09 	jne	9 <__int3_label_4>
     38f:	41 5b 	popq	%r11
     391:	49 83 c2 08 	addq	$8, %r10
     395:	41 ff e2 	jmpq	*%r10

__int3_label_4:
     398:	cc 	int3
     399:	0f 1f 80 00 00 00 00 	nopl	(%rax)

__sgx_function_magic_5:
     3a0:	9a  <unknown>
     3a1:	9a  <unknown>
     3a2:	9a  <unknown>
     3a3:	9a  <unknown>
     3a4:	9a  <unknown>
     3a5:	9a  <unknown>
     3a6:	9a  <unknown>
     3a7:	9a  <unknown>
     3a8:	1f  <unknown>
     3a9:	00 00 	addb	%al, (%rax)
     3ab:	00 00 	addb	%al, (%rax)
     3ad:	00 00 	addb	%al, (%rax)
     3af:	00 55 48 	addb	%dl, 72(%rbp)

generate_data:
     3b0:	55 	pushq	%rbp
     3b1:	48 89 e5 	movq	%rsp, %rbp
     3b4:	48 83 ec 20 	subq	$32, %rsp
     3b8:	64 67 89 7d f8 	movl	%edi, %fs:-8(%ebp)
     3bd:	64 67 48 63 7d f8 	movslq	%fs:-8(%ebp), %rdi
     3c3:	48 c1 e7 02 	shlq	$2, %rdi
     3c7:	4d 31 c9 	xorq	%r9, %r9
     3ca:	4d 31 c0 	xorq	%r8, %r8
     3cd:	48 31 c9 	xorq	%rcx, %rcx
     3d0:	48 31 d2 	xorq	%rdx, %rdx
     3d3:	48 31 f6 	xorq	%rsi, %rsi
     3d6:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_5>

__sgx_callsite_magic_public_5:
     3db:	9a  <unknown>
     3dc:	9a  <unknown>
     3dd:	9a  <unknown>
     3de:	9a  <unknown>
     3df:	9a  <unknown>
     3e0:	9a  <unknown>
     3e1:	9a  <unknown>
     3e2:	9a  <unknown>
     3e3:	64 67 48 89 45 f0 	movq	%rax, %fs:-16(%ebp)
     3e9:	48 85 c0 	testq	%rax, %rax
     3ec:	74 73 	je	115 <__sgx_callsite_magic_public_6+0x4A>
     3ee:	64 67 c7 45 fc 00 00 00 00 	movl	$0, %fs:-4(%ebp)
     3f7:	eb 4e 	jmp	78 <__sgx_callsite_magic_public_6+0x30>
     3f9:	0f 1f 80 00 00 00 00 	nopl	(%rax)
     400:	4d 31 c9 	xorq	%r9, %r9
     403:	4d 31 c0 	xorq	%r8, %r8
     406:	48 31 c9 	xorq	%rcx, %rcx
     409:	48 31 d2 	xorq	%rdx, %rdx
     40c:	48 31 f6 	xorq	%rsi, %rsi
     40f:	48 31 ff 	xorq	%rdi, %rdi
     412:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_6>

__sgx_callsite_magic_public_6:
     417:	9a  <unknown>
     418:	9a  <unknown>
     419:	9a  <unknown>
     41a:	9a  <unknown>
     41b:	9a  <unknown>
     41c:	9a  <unknown>
     41d:	9a  <unknown>
     41e:	9a  <unknown>
     41f:	89 c1 	movl	%eax, %ecx
     421:	c1 f9 1f 	sarl	$31, %ecx
     424:	c1 e9 18 	shrl	$24, %ecx
     427:	01 c1 	addl	%eax, %ecx
     429:	81 e1 00 ff ff ff 	andl	$4294967040, %ecx
     42f:	29 c8 	subl	%ecx, %eax
     431:	64 67 48 63 4d fc 	movslq	%fs:-4(%ebp), %rcx
     437:	64 67 48 8b 55 f0 	movq	%fs:-16(%ebp), %rdx
     43d:	65 67 89 04 8a 	movl	%eax, %gs:(%edx,%ecx,4)
     442:	64 67 ff 45 fc 	incl	%fs:-4(%ebp)
     447:	64 67 8b 45 fc 	movl	%fs:-4(%ebp), %eax
     44c:	64 67 3b 45 f8 	cmpl	%fs:-8(%ebp), %eax
     451:	7c ad 	jl	-83 <__sgx_callsite_magic_public_5+0x25>
     453:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     459:	64 67 48 89 45 e8 	movq	%rax, %fs:-24(%ebp)
     45f:	eb 0a 	jmp	10 <__sgx_callsite_magic_public_6+0x54>
     461:	64 67 48 c7 45 e8 00 00 00 00 	movq	$0, %fs:-24(%ebp)
     46b:	64 67 48 8b 45 e8 	movq	%fs:-24(%ebp), %rax
     471:	48 83 c4 20 	addq	$32, %rsp
     475:	5d 	popq	%rbp
     476:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_public_4:
     47a:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
     484:	49 f7 d3 	notq	%r11
     487:	4d 39 1a 	cmpq	%r11, (%r10)
     48a:	75 09 	jne	9 <__int3_label_5>
     48c:	41 5b 	popq	%r11
     48e:	49 83 c2 08 	addq	$8, %r10
     492:	41 ff e2 	jmpq	*%r10

__int3_label_5:
     495:	cc 	int3
     496:	66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)

__sgx_function_magic_6:
     4a0:	9a  <unknown>
     4a1:	9a  <unknown>
     4a2:	9a  <unknown>
     4a3:	9a  <unknown>
     4a4:	9a  <unknown>
     4a5:	9a  <unknown>
     4a6:	9a  <unknown>
     4a7:	9a  <unknown>
     4a8:	4f 00 00 	addb	%r8b, (%r8)
     4ab:	00 00 	addb	%al, (%rax)
     4ad:	00 00 	addb	%al, (%rax)
     4af:	00 55 48 	addb	%dl, 72(%rbp)

process_data:
     4b0:	55 	pushq	%rbp
     4b1:	48 89 e5 	movq	%rsp, %rbp
     4b4:	48 83 ec 00 	subq	$0, %rsp
     4b8:	64 67 48 89 7d e8 	movq	%rdi, %fs:-24(%ebp)
     4be:	64 67 89 75 f4 	movl	%esi, %fs:-12(%ebp)
     4c3:	64 67 48 83 7d e8 00 	cmpq	$0, %fs:-24(%ebp)
     4ca:	74 08 	je	8 <process_data+0x24>
     4cc:	64 67 83 7d f4 00 	cmpl	$0, %fs:-12(%ebp)
     4d2:	7f 0b 	jg	11 <process_data+0x2F>
     4d4:	65 67 c7 45 f0 ff ff ff ff 	movl	$4294967295, %gs:-16(%ebp)
     4dd:	eb 52 	jmp	82 <process_data+0x81>
     4df:	65 67 c7 45 f8 00 00 00 00 	movl	$0, %gs:-8(%ebp)
     4e8:	64 67 c7 45 fc 00 00 00 00 	movl	$0, %fs:-4(%ebp)
     4f1:	eb 28 	jmp	40 <process_data+0x6B>
     4f3:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)
     500:	64 67 48 63 45 fc 	movslq	%fs:-4(%ebp), %rax
     506:	64 67 48 8b 4d e8 	movq	%fs:-24(%ebp), %rcx
     50c:	65 67 8b 04 81 	movl	%gs:(%ecx,%eax,4), %eax
     511:	65 67 01 45 f8 	addl	%eax, %gs:-8(%ebp)
     516:	64 67 ff 45 fc 	incl	%fs:-4(%ebp)
     51b:	64 67 8b 45 fc 	movl	%fs:-4(%ebp), %eax
     520:	64 67 3b 45 f4 	cmpl	%fs:-12(%ebp), %eax
     525:	7c d9 	jl	-39 <process_data+0x50>
     527:	65 67 8b 45 f8 	movl	%gs:-8(%ebp), %eax
     52c:	65 67 89 45 f0 	movl	%eax, %gs:-16(%ebp)
     531:	65 67 8b 45 f0 	movl	%gs:-16(%ebp), %eax
     536:	48 83 ec 00 	subq	$0, %rsp
     53a:	5d 	popq	%rbp
     53b:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_private_1:
     53f:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
     549:	49 f7 d3 	notq	%r11
     54c:	4d 39 1a 	cmpq	%r11, (%r10)
     54f:	75 09 	jne	9 <__process_data__int3>
     551:	41 5b 	popq	%r11
     553:	49 83 c2 08 	addq	$8, %r10
     557:	41 ff e2 	jmpq	*%r10

__process_data__int3:
     55a:	cc 	int3
     55b:	0f 1f 44 00 00 	nopl	(%rax,%rax)

__sgx_function_magic_7:
     560:	9a  <unknown>
     561:	9a  <unknown>
     562:	9a  <unknown>
     563:	9a  <unknown>
     564:	9a  <unknown>
     565:	9a  <unknown>
     566:	9a  <unknown>
     567:	9a  <unknown>
     568:	03 00 	addl	(%rax), %eax
     56a:	00 00 	addb	%al, (%rax)
     56c:	00 00 	addb	%al, (%rax)
     56e:	00 00 	addb	%al, (%rax)

matrix_multiply:
     570:	55 	pushq	%rbp
     571:	48 89 e5 	movq	%rsp, %rbp
     574:	48 83 ec 00 	subq	$0, %rsp
     578:	64 67 48 89 7d d8 	movq	%rdi, %fs:-40(%ebp)
     57e:	64 67 48 89 75 e0 	movq	%rsi, %fs:-32(%ebp)
     584:	64 67 48 89 55 e8 	movq	%rdx, %fs:-24(%ebp)
     58a:	64 67 89 4d fc 	movl	%ecx, %fs:-4(%ebp)
     58f:	64 67 c7 45 f4 00 00 00 00 	movl	$0, %fs:-12(%ebp)
     598:	eb 0b 	jmp	11 <matrix_multiply+0x35>
     59a:	66 0f 1f 44 00 00 	nopw	(%rax,%rax)
     5a0:	64 67 ff 45 f4 	incl	%fs:-12(%ebp)
     5a5:	64 67 8b 45 f4 	movl	%fs:-12(%ebp), %eax
     5aa:	64 67 3b 45 fc 	cmpl	%fs:-4(%ebp), %eax
     5af:	0f 8d bd 00 00 00 	jge	189 <matrix_multiply+0x102>
     5b5:	64 67 c7 45 f8 00 00 00 00 	movl	$0, %fs:-8(%ebp)
     5be:	eb 05 	jmp	5 <matrix_multiply+0x55>
     5c0:	64 67 ff 45 f8 	incl	%fs:-8(%ebp)
     5c5:	64 67 8b 45 f8 	movl	%fs:-8(%ebp), %eax
     5ca:	64 67 3b 45 fc 	cmpl	%fs:-4(%ebp), %eax
     5cf:	7d cf 	jge	-49 <matrix_multiply+0x30>
     5d1:	64 67 48 63 45 f4 	movslq	%fs:-12(%ebp), %rax
     5d7:	64 67 48 63 4d fc 	movslq	%fs:-4(%ebp), %rcx
     5dd:	48 0f af c8 	imulq	%rax, %rcx
     5e1:	64 67 48 63 45 f8 	movslq	%fs:-8(%ebp), %rax
     5e7:	48 01 c8 	addq	%rcx, %rax
     5ea:	64 67 48 8b 4d e8 	movq	%fs:-24(%ebp), %rcx
     5f0:	65 67 c7 04 81 00 00 00 00 	movl	$0, %gs:(%ecx,%eax,4)
     5f9:	64 67 c7 45 f0 00 00 00 00 	movl	$0, %fs:-16(%ebp)
     602:	eb 5d 	jmp	93 <matrix_multiply+0xF1>
     604:	66 66 66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)
     610:	64 67 48 63 45 f4 	movslq	%fs:-12(%ebp), %rax
     616:	64 67 48 63 4d fc 	movslq	%fs:-4(%ebp), %rcx
     61c:	48 0f af c1 	imulq	%rcx, %rax
     620:	64 67 48 63 55 f0 	movslq	%fs:-16(%ebp), %rdx
     626:	48 8d 34 10 	leaq	(%rax,%rdx), %rsi
     62a:	64 67 48 8b 7d d8 	movq	%fs:-40(%ebp), %rdi
     630:	65 67 8b 34 b7 	movl	%gs:(%edi,%esi,4), %esi
     635:	48 0f af d1 	imulq	%rcx, %rdx
     639:	64 67 48 63 4d f8 	movslq	%fs:-8(%ebp), %rcx
     63f:	48 01 ca 	addq	%rcx, %rdx
     642:	64 67 48 8b 7d e0 	movq	%fs:-32(%ebp), %rdi
     648:	65 67 0f af 34 97 	imull	%gs:(%edi,%edx,4), %esi
     64e:	48 01 c8 	addq	%rcx, %rax
     651:	64 67 48 8b 4d e8 	movq	%fs:-24(%ebp), %rcx
     657:	65 67 01 34 81 	addl	%esi, %gs:(%ecx,%eax,4)
     65c:	64 67 ff 45 f0 	incl	%fs:-16(%ebp)
     661:	64 67 8b 45 f0 	movl	%fs:-16(%ebp), %eax
     666:	64 67 3b 45 fc 	cmpl	%fs:-4(%ebp), %eax
     66b:	7c a3 	jl	-93 <matrix_multiply+0xA0>
     66d:	e9 4e ff ff ff 	jmp	-178 <matrix_multiply+0x50>
     672:	48 83 ec 00 	subq	$0, %rsp
     676:	5d 	popq	%rbp
     677:	48 31 c0 	xorq	%rax, %rax
     67a:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_public_5:
     67e:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
     688:	49 f7 d3 	notq	%r11
     68b:	4d 39 1a 	cmpq	%r11, (%r10)
     68e:	75 09 	jne	9 <__matrix_multiply__int3>
     690:	41 5b 	popq	%r11
     692:	49 83 c2 08 	addq	$8, %r10
     696:	41 ff e2 	jmpq	*%r10

__matrix_multiply__int3:
     699:	cc 	int3
     69a:	66 0f 1f 44 00 00 	nopw	(%rax,%rax)

__sgx_function_magic_8:
     6a0:	9a  <unknown>
     6a1:	9a  <unknown>
     6a2:	9a  <unknown>
     6a3:	9a  <unknown>
     6a4:	9a  <unknown>
     6a5:	9a  <unknown>
     6a6:	9a  <unknown>
     6a7:	9a  <unknown>
     6a8:	0f 00 00 	sldtw	(%rax)
     6ab:	00 00 	addb	%al, (%rax)
     6ad:	00 00 	addb	%al, (%rax)
     6af:	00 55 48 	addb	%dl, 72(%rbp)

main:
     6b0:	55 	pushq	%rbp
     6b1:	48 89 e5 	movq	%rsp, %rbp
     6b4:	48 83 ec 30 	subq	$48, %rsp
     6b8:	64 67 c7 45 fc 00 00 00 00 	movl	$0, %fs:-4(%ebp)
     6c1:	64 67 89 7d d8 	movl	%edi, %fs:-40(%ebp)
     6c6:	64 67 48 89 75 d0 	movq	%rsi, %fs:-48(%ebp)
     6cc:	bf 10 00 00 00 	movl	$16, %edi
     6d1:	4d 31 c9 	xorq	%r9, %r9
     6d4:	4d 31 c0 	xorq	%r8, %r8
     6d7:	48 31 c9 	xorq	%rcx, %rcx
     6da:	48 31 d2 	xorq	%rdx, %rdx
     6dd:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_7>

__sgx_callsite_magic_public_7:
     6e2:	9a  <unknown>
     6e3:	9a  <unknown>
     6e4:	9a  <unknown>
     6e5:	9a  <unknown>
     6e6:	9a  <unknown>
     6e7:	9a  <unknown>
     6e8:	9a  <unknown>
     6e9:	9a  <unknown>
     6ea:	64 67 48 89 45 f0 	movq	%rax, %fs:-16(%ebp)
     6f0:	48 85 c0 	testq	%rax, %rax
     6f3:	0f 84 83 01 00 00 	je	387 <__sgx_callsite_magic_public_14+0x8>
     6f9:	bf 00 01 00 00 	movl	$256, %edi
     6fe:	4d 31 c9 	xorq	%r9, %r9
     701:	4d 31 c0 	xorq	%r8, %r8
     704:	48 31 c9 	xorq	%rcx, %rcx
     707:	48 31 d2 	xorq	%rdx, %rdx
     70a:	48 31 f6 	xorq	%rsi, %rsi
     70d:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_8>

__sgx_callsite_magic_public_8:
     712:	9a  <unknown>
     713:	9a  <unknown>
     714:	9a  <unknown>
     715:	9a  <unknown>
     716:	9a  <unknown>
     717:	9a  <unknown>
     718:	9a  <unknown>
     719:	9a  <unknown>
     71a:	64 67 48 8b 4d f0 	movq	%fs:-16(%ebp), %rcx
     720:	64 67 48 89 01 	movq	%rax, %fs:(%ecx)
     725:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     72b:	64 67 48 83 38 00 	cmpq	$0, %fs:(%eax)
     731:	0f 84 23 01 00 00 	je	291 <__sgx_callsite_magic_public_13+0x8>
     737:	64 67 c7 45 ec 00 00 00 00 	movl	$0, %fs:-20(%ebp)
     740:	eb 60 	jmp	96 <__sgx_callsite_magic_public_9+0x3E>
     742:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	nopw	%cs:(%rax,%rax)
     750:	4d 31 c9 	xorq	%r9, %r9
     753:	4d 31 c0 	xorq	%r8, %r8
     756:	48 31 d2 	xorq	%rdx, %rdx
     759:	48 31 f6 	xorq	%rsi, %rsi
     75c:	48 31 ff 	xorq	%rdi, %rdi
     75f:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_9>

__sgx_callsite_magic_public_9:
     764:	9a  <unknown>
     765:	9a  <unknown>
     766:	9a  <unknown>
     767:	9a  <unknown>
     768:	9a  <unknown>
     769:	9a  <unknown>
     76a:	9a  <unknown>
     76b:	9a  <unknown>
     76c:	48 98 	cltq
     76e:	48 69 c8 1f 85 eb 51 	imulq	$1374389535, %rax, %rcx
     775:	48 89 ca 	movq	%rcx, %rdx
     778:	48 c1 ea 3f 	shrq	$63, %rdx
     77c:	48 c1 f9 25 	sarq	$37, %rcx
     780:	01 d1 	addl	%edx, %ecx
     782:	6b c9 64 	imull	$100, %ecx, %ecx
     785:	29 c8 	subl	%ecx, %eax
     787:	64 67 48 63 4d ec 	movslq	%fs:-20(%ebp), %rcx
     78d:	64 67 48 8b 55 f0 	movq	%fs:-16(%ebp), %rdx
     793:	64 67 48 8b 12 	movq	%fs:(%edx), %rdx
     798:	65 67 89 04 8a 	movl	%eax, %gs:(%edx,%ecx,4)
     79d:	64 67 ff 45 ec 	incl	%fs:-20(%ebp)
     7a2:	64 67 83 7d ec 3f 	cmpl	$63, %fs:-20(%ebp)
     7a8:	7e a6 	jle	-90 <__sgx_callsite_magic_public_8+0x3E>
     7aa:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     7b0:	64 67 c7 40 08 01 00 00 00 	movl	$1, %fs:8(%eax)
     7b9:	bf 64 00 00 00 	movl	$100, %edi
     7be:	4d 31 c9 	xorq	%r9, %r9
     7c1:	4d 31 c0 	xorq	%r8, %r8
     7c4:	48 31 d2 	xorq	%rdx, %rdx
     7c7:	48 31 f6 	xorq	%rsi, %rsi
     7ca:	e8 e1 fb ff ff 	callq	-1055 <generate_data>

__sgx_callsite_magic_public_10:
     7cf:	9a  <unknown>
     7d0:	9a  <unknown>
     7d1:	9a  <unknown>
     7d2:	9a  <unknown>
     7d3:	9a  <unknown>
     7d4:	9a  <unknown>
     7d5:	9a  <unknown>
     7d6:	9a  <unknown>
     7d7:	64 67 48 89 45 e0 	movq	%rax, %fs:-32(%ebp)
     7dd:	48 85 c0 	testq	%rax, %rax
     7e0:	74 51 	je	81 <__sgx_callsite_magic_public_12+0x8>
     7e2:	64 67 48 8b 7d f0 	movq	%fs:-16(%ebp), %rdi
     7e8:	64 67 48 8b 75 e0 	movq	%fs:-32(%ebp), %rsi
     7ee:	ba 64 00 00 00 	movl	$100, %edx
     7f3:	4d 31 c9 	xorq	%r9, %r9
     7f6:	4d 31 c0 	xorq	%r8, %r8
     7f9:	48 31 c9 	xorq	%rcx, %rcx
     7fc:	e8 bf fa ff ff 	callq	-1345 <enc_dec>

__sgx_callsite_magic_public_11:
     801:	9a  <unknown>
     802:	9a  <unknown>
     803:	9a  <unknown>
     804:	9a  <unknown>
     805:	9a  <unknown>
     806:	9a  <unknown>
     807:	9a  <unknown>
     808:	9a  <unknown>
     809:	85 c0 	testl	%eax, %eax
     80b:	0f 84 9e 00 00 00 	je	158 <__main__int3+0x1>
     811:	64 67 48 8b 7d e0 	movq	%fs:-32(%ebp), %rdi
     817:	4d 31 c9 	xorq	%r9, %r9
     81a:	4d 31 c0 	xorq	%r8, %r8
     81d:	48 31 c9 	xorq	%rcx, %rcx
     820:	48 31 d2 	xorq	%rdx, %rdx
     823:	48 31 f6 	xorq	%rsi, %rsi
     826:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_12>

__sgx_callsite_magic_public_12:
     82b:	9a  <unknown>
     82c:	9a  <unknown>
     82d:	9a  <unknown>
     82e:	9a  <unknown>
     82f:	9a  <unknown>
     830:	9a  <unknown>
     831:	9a  <unknown>
     832:	9a  <unknown>
     833:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     839:	64 67 48 8b 38 	movq	%fs:(%eax), %rdi
     83e:	4d 31 c9 	xorq	%r9, %r9
     841:	4d 31 c0 	xorq	%r8, %r8
     844:	48 31 c9 	xorq	%rcx, %rcx
     847:	48 31 d2 	xorq	%rdx, %rdx
     84a:	48 31 f6 	xorq	%rsi, %rsi
     84d:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_13>

__sgx_callsite_magic_public_13:
     852:	9a  <unknown>
     853:	9a  <unknown>
     854:	9a  <unknown>
     855:	9a  <unknown>
     856:	9a  <unknown>
     857:	9a  <unknown>
     858:	9a  <unknown>
     859:	9a  <unknown>
     85a:	64 67 48 8b 7d f0 	movq	%fs:-16(%ebp), %rdi
     860:	4d 31 c9 	xorq	%r9, %r9
     863:	4d 31 c0 	xorq	%r8, %r8
     866:	48 31 c9 	xorq	%rcx, %rcx
     869:	48 31 d2 	xorq	%rdx, %rdx
     86c:	48 31 f6 	xorq	%rsi, %rsi
     86f:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_14>

__sgx_callsite_magic_public_14:
     874:	9a  <unknown>
     875:	9a  <unknown>
     876:	9a  <unknown>
     877:	9a  <unknown>
     878:	9a  <unknown>
     879:	9a  <unknown>
     87a:	9a  <unknown>
     87b:	9a  <unknown>
     87c:	64 67 c7 45 fc ff ff ff ff 	movl	$4294967295, %fs:-4(%ebp)
     885:	64 67 8b 45 fc 	movl	%fs:-4(%ebp), %eax
     88a:	48 83 c4 30 	addq	$48, %rsp
     88e:	5d 	popq	%rbp
     88f:	4c 8b 14 24 	movq	(%rsp), %r10

__sgx_returnsite_magic_public_6:
     893:	49 bb 65 65 65 65 65 65 65 65 	movabsq	$7306357456645743973, %r11
     89d:	49 f7 d3 	notq	%r11
     8a0:	4d 39 1a 	cmpq	%r11, (%r10)
     8a3:	75 09 	jne	9 <__main__int3>
     8a5:	41 5b 	popq	%r11
     8a7:	49 83 c2 08 	addq	$8, %r10
     8ab:	41 ff e2 	jmpq	*%r10

__main__int3:
     8ae:	cc 	int3
     8af:	64 67 48 8b 7d e0 	movq	%fs:-32(%ebp), %rdi
     8b5:	be 64 00 00 00 	movl	$100, %esi
     8ba:	4d 31 c9 	xorq	%r9, %r9
     8bd:	4d 31 c0 	xorq	%r8, %r8
     8c0:	48 31 c9 	xorq	%rcx, %rcx
     8c3:	48 31 d2 	xorq	%rdx, %rdx
     8c6:	e8 e5 fb ff ff 	callq	-1051 <process_data>

__sgx_callsite_magic_private_0:
     8cb:	9a  <unknown>
     8cc:	9a  <unknown>
     8cd:	9a  <unknown>
     8ce:	9a  <unknown>
     8cf:	9a  <unknown>
     8d0:	9a  <unknown>
     8d1:	9a  <unknown>
     8d2:	9a  <unknown>
     8d3:	65 67 89 45 dc 	movl	%eax, %gs:-36(%ebp)
     8d8:	bf 00 00 00 00 	movl	$0, %edi
     8dd:	89 c6 	movl	%eax, %esi
     8df:	4d 31 c9 	xorq	%r9, %r9
     8e2:	4d 31 c0 	xorq	%r8, %r8
     8e5:	48 31 c9 	xorq	%rcx, %rcx
     8e8:	48 31 d2 	xorq	%rdx, %rdx
     8eb:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_15>

__sgx_callsite_magic_public_15:
     8f0:	9a  <unknown>
     8f1:	9a  <unknown>
     8f2:	9a  <unknown>
     8f3:	9a  <unknown>
     8f4:	9a  <unknown>
     8f5:	9a  <unknown>
     8f6:	9a  <unknown>
     8f7:	9a  <unknown>
     8f8:	64 67 48 8b 7d e0 	movq	%fs:-32(%ebp), %rdi
     8fe:	4d 31 c9 	xorq	%r9, %r9
     901:	4d 31 c0 	xorq	%r8, %r8
     904:	48 31 c9 	xorq	%rcx, %rcx
     907:	48 31 d2 	xorq	%rdx, %rdx
     90a:	48 31 f6 	xorq	%rsi, %rsi
     90d:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_16>

__sgx_callsite_magic_public_16:
     912:	9a  <unknown>
     913:	9a  <unknown>
     914:	9a  <unknown>
     915:	9a  <unknown>
     916:	9a  <unknown>
     917:	9a  <unknown>
     918:	9a  <unknown>
     919:	9a  <unknown>
     91a:	64 67 48 8b 45 f0 	movq	%fs:-16(%ebp), %rax
     920:	64 67 48 8b 38 	movq	%fs:(%eax), %rdi
     925:	4d 31 c9 	xorq	%r9, %r9
     928:	4d 31 c0 	xorq	%r8, %r8
     92b:	48 31 c9 	xorq	%rcx, %rcx
     92e:	48 31 d2 	xorq	%rdx, %rdx
     931:	48 31 f6 	xorq	%rsi, %rsi
     934:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_17>

__sgx_callsite_magic_public_17:
     939:	9a  <unknown>
     93a:	9a  <unknown>
     93b:	9a  <unknown>
     93c:	9a  <unknown>
     93d:	9a  <unknown>
     93e:	9a  <unknown>
     93f:	9a  <unknown>
     940:	9a  <unknown>
     941:	64 67 48 8b 7d f0 	movq	%fs:-16(%ebp), %rdi
     947:	4d 31 c9 	xorq	%r9, %r9
     94a:	4d 31 c0 	xorq	%r8, %r8
     94d:	48 31 c9 	xorq	%rcx, %rcx
     950:	48 31 d2 	xorq	%rdx, %rdx
     953:	48 31 f6 	xorq	%rsi, %rsi
     956:	e8 00 00 00 00 	callq	0 <__sgx_callsite_magic_public_18>

__sgx_callsite_magic_public_18:
     95b:	9a  <unknown>
     95c:	9a  <unknown>
     95d:	9a  <unknown>
     95e:	9a  <unknown>
     95f:	9a  <unknown>
     960:	9a  <unknown>
     961:	9a  <unknown>
     962:	9a  <unknown>
     963:	64 67 c7 45 fc 00 00 00 00 	movl	$0, %fs:-4(%ebp)
     96c:	e9 14 ff ff ff 	jmp	-236 <__sgx_callsite_magic_public_14+0x11>
