
.CODE
 myKiSaveDebugRegisterState PROC

 mov   r9,qword ptr gs:[18h]
       mov     rax,dr0
        mov     rdx,dr1
     mov     qword ptr [rbp+58h],rax
    mov     qword ptr [rbp+60h],rdx
      mov     rax,dr2
      mov     rdx,dr3
   mov     qword ptr [rbp+68h],rax
     mov     qword ptr [rbp+70h],rdx
       mov     rax,dr6
     mov     rdx,dr7
      mov     qword ptr [rbp+78h],rax
 mov     qword ptr [rbp+80h],rdx
        xor     eax,eax
       mov     dr7,rax
       ret     0
	    myKiSaveDebugRegisterState ENDP




myKiRestoreDebugRegisterState PROC
       xor     edx,edx
       mov     dr7,rdx
      mov     rax,qword ptr [rbp+58h]
      mov     rdx,qword ptr [rbp+60h]
        mov     dr0,rax
       mov     dr1,rdx
    mov     rax,qword ptr [rbp+68h]
   mov     rdx,qword ptr [rbp+70h]
 mov     dr2,rax
 mov     dr3,rdx
 mov     rdx,qword ptr [rbp+80h]
    xor     eax,eax
       mov     dr6,rax
        mov     dr7,rdx
        ret     0
		myKiRestoreDebugRegisterState ENDP

END