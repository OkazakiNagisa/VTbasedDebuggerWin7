EXTERN ObfDereferenceObject:PROC
EXTERN ObfReferenceObjectWithTag:PROC
EXTERN MmUserProbeAddress:QWORD
.CODE

ObFastDereferenceObject PROC
prefetchw byte ptr [rcx]
mov     rax, [rcx]
mov     r8, rax
xor     r8, rdx
cmp     r8, 0Fh
jnb a
mov     r9, rcx
loc_1400921A5:
lea     r8, [rax+1]
lock cmpxchg [r9], r8
jnz     short loc_1400921B9
ret
loc_1400921B9:
mov     rcx, rax
xor     rcx, rdx
cmp     rcx, 0Fh
jb      short loc_1400921A5
mov     rcx, rdx        ; Object
jmp     ObfDereferenceObject





a:         ; Object
mov     rcx, rdx
jmp     ObfDereferenceObject

ObFastDereferenceObject ENDP

ObFastReferenceObjectLocked PROC

push    rbx
sub     rsp, 20h
mov     rbx, [rcx]
and     rbx, 0FFFFFFFFFFFFFFF0h
jz      short loc_1400B6B7C
mov     edx, 746C6644h
mov     rcx, rbx
call    ObfReferenceObjectWithTag

loc_1400B6B7C:
mov     rax, rbx
add     rsp, 20h
pop     rbx
ret
ObFastReferenceObjectLocked ENDP

ProbeWrite PROC

mov     rax, qword ptr [MmUserProbeAddress]
cmp     rcx, rax
cmovnb  rcx, rax
mov     rax, [rcx]
mov     [rcx], rax

ProbeWrite ENDP
END