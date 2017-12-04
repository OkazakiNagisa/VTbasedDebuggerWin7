.CODE
HVM_SAVE_ALL_NOSEGREGS MACRO
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8        
        push rdi
        push rsi
        push rbp
        push rbp	; rsp
        push rbx
        push rdx
        push rcx
        push rax
ENDM

HVM_RESTORE_ALL_NOSEGREGS MACRO
        pop rax
        pop rcx
        pop rdx
        pop rbx
        pop rbp		; rsp
        pop rbp
        pop rsi
        pop rdi 
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
ENDM

extern jmp_SwapContext_PatchXRstor:QWORD
extern jmp_SwapContext:QWORD
extern jmp_SwapContextTp:QWORD
extern IstThreadStub:PROC
MySwapContext PROC



       sub     rsp,38h
     mov     qword ptr [rsp+30h],rbp
       prefetchw [rsi+49h]
       mov     byte ptr [rsp+28h],cl
	 
    cmp     byte ptr [rsi+49h],0
  
   je jmp_patch
  jmp    qword ptr [jmp_SwapContext_PatchXRstor]

  jmp_patch:


   ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	  HVM_SAVE_ALL_NOSEGREGS
	  mov rcx,rdi
	  mov rdx,rsi
	  call IstThreadStub
	  cmp rax,1
	  je jmptp
	  HVM_RESTORE_ALL_NOSEGREGS
	  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

      mov     byte ptr [rsi+49h],1
        cli
       rdtsc
     shl     rdx,20h
       or      rax,rdx

	   push qword ptr [jmp_SwapContext]
	   ret

	   jmptp:
	   HVM_RESTORE_ALL_NOSEGREGS
	   push qword ptr [jmp_SwapContextTp]
	   ret
MySwapContext ENDP
END