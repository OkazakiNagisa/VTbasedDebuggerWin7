EXTERN	HvmSubvertCpu:PROC

.CODE
; CmInvept (PVOID Ep4ta(rcx), ULONG inval (rdx) );
CmInvept proc
     push	 rbp
	 mov	 rbp, rsp
	 push    rsi
	 mov     rsi, rcx
	 mov     rax, rdx
	 invept  rax, xmmword ptr [rsi]
	 pop     rsi
	 mov	 rsp, rbp
	 pop	 rbp
	 ret
CmInvept endp
_ReadVMCS PROC
    vmread rdx, rcx
    mov rax, rdx
    ret
_ReadVMCS ENDP

_WriteVMCS PROC
    vmwrite rcx, rdx
    ret
_WriteVMCS ENDP
_Cr0 PROC
	mov		rax, cr0
	ret
_Cr0 ENDP

_Cr2 PROC
	mov		rax, cr2
	ret
_Cr2 ENDP

_SetCr2 PROC
    mov cr2, rcx
    ret
_SetCr2 ENDP    

_Cr3 PROC
	mov		rax, cr3
	ret
_Cr3 ENDP

_SetCr3 PROC
	mov		cr3, rcx
	ret
_SetCr3 ENDP

_Cr4 PROC
	mov		rax, cr4
	ret
_Cr4 ENDP

_SetCr4 PROC 
	mov rax,cr4
	or  rcx,rax
	mov cr4,rcx	
	ret
_SetCr4 ENDP

_Cr8 PROC
	mov		rax, cr8
	ret
_Cr8 ENDP

_SetCr8 PROC
	mov		cr8, rcx
	ret
_SetCr8 ENDP

_Dr6 PROC
	mov		rax, dr6
	ret
_Dr6 ENDP

_Dr0 PROC
	mov		rax, dr0
	ret
_Dr0 ENDP

_Dr1 PROC
	mov		rax, dr1
	ret
_Dr1 ENDP

_Dr2 PROC
	mov		rax, dr2
	ret
_Dr2 ENDP

_Dr3 PROC
	mov		rax, dr3
	ret
_Dr3 ENDP

_SetDr0 PROC
	mov		dr0, rcx
	ret
_SetDr0 ENDP

_SetDr1 PROC
	mov		dr1, rcx
	ret
_SetDr1 ENDP

_SetDr2 PROC
	mov		dr2, rcx
	ret
_SetDr2 ENDP

_SetDr3 PROC
	mov		dr3, rcx
	ret
_SetDr3 ENDP

_Rflags PROC
	pushfq
	pop		rax
	ret
_Rflags ENDP

_Rsp PROC
	mov		rax, rsp
	add		rax, 8
	ret
_Rsp ENDP
_Int3 PROC
    int 3
    ret
_Int3 ENDP    

_Invd PROC
    invd
    ret
_Invd ENDP    

_InvalidatePage PROC
    invlpg [rcx]
    ret
_InvalidatePage ENDP
;CmInvvpid (PVOID table (rcx), ULONG inval (rdx) );
CmInvvpid proc
     push	  rbp
 	 mov	  rbp, rsp
	 push     rsi
	 mov      rsi, rcx
	 mov      rax, rdx
	 invvpid  rax, xmmword ptr [rsi]
	 pop      rsi
	 mov	  rsp, rbp
	 pop	  rbp
	 ret
CmInvvpid endp

;CmInvpcid (PVOID table (rcx), ULONG inval (rdx) );
CmInvpcid proc
     push	  rbp
 	 mov	  rbp, rsp
	 push     rsi
	 mov      rsi, rcx
	 mov      rax, rdx
	 invpcid  rax, xmmword ptr [rsi]
	 pop      rsi
	 mov	  rsp, rbp
	 pop	  rbp
	 ret
CmInvpcid endp
GetCpuIdInfo PROC
   push   rbp
   mov      rbp, rsp
   push   rbx
   push   rsi

   mov      [rbp+18h], rdx
   mov      eax, ecx
   cpuid
   mov      rsi, [rbp+18h]
   mov      [rsi], eax
   mov      [r8], ebx
   mov      [r9], ecx
   mov      rsi, [rbp+30h]
   mov      [rsi], edx

   pop      rsi
   pop      rbx
   mov      rsp, rbp
   pop      rbp
   ret
GetCpuIdInfo ENDP

CmSubvert PROC

	push	rax
	push	rcx
	push	rdx
	push	rbx
	push	rbp
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15

	sub	rsp, 28h

	mov	rcx, rsp           ; __fastcall用rcx传递第一个参数GuestRsp
	                       ; x64统一为__fastcall: 前四个参数由RCX,RDX,R8,R9依次传递
	call	HvmSubvertCpu  ; VmxSubvertCpu要求一个参数GuestRsp

CmSubvert ENDP

CmGuestEip PROC

	add	rsp, 28h

	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rbp
	pop	rbx
	pop	rdx
	pop	rcx
	pop	rax

	ret

CmGuestEip ENDP

END
