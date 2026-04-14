
PUBLIC NtQueryInformationProcessDebugHook_begin 
PUBLIC NtQueryInformationProcessDebugHook_end 
PUBLIC GetProcAddressHook_begin
PUBLIC GetProcAddressHook_end
.code

;rcx =ProcessHandle
;rdx =ProcessInformationClass
;r8 =ProcessInformation
;r9 =ProcessInformationLen
;cur rsp+28h =Preturn Len
NtQueryInformationProcessDebugHook_begin PROC
    cmp rdx,7h
    jz hookskipA
    mov r10,rcx
    mov eax,19h
    test byte ptr [7FFE0308h],1
    jnz interruptA
    syscall
    ret
interruptA:
    int 2Eh
    ret
hookskipA:
    cmp r9,8
    jnz hookskipA1
    mov qword ptr [r8],0
    mov eax,0
    cmp qword ptr [rsp+28h],0
    jz hookskipA11
    push rsi
    mov rsi,[rsp+30h]
    mov dword ptr [rsi],8h
    pop rsi
    ret 
hookskipA11:
    ret
hookskipA1:
    mov eax,0C0000004h
    ret
NtQueryInformationProcessDebugHook_begin ENDP
NtQueryInformationProcessDebugHook_end Label BYTE

GetProcAddressHook_begin Label BYTE
GetProcAddressHook_NtQueryInformationProcess_ReturnValue dq 0
GetProcAddress_original dq 0

GetProcAddressHook PROC
    cmp dword ptr [rdx],    'uQtN'  ; N t Q u
    jne not_equal
    cmp dword ptr [rdx+4],  'Iyre'  ; e r y I
    jne not_equal
    cmp dword ptr [rdx+8],  'rofn'  ; n f o r
    jne not_equal
    cmp dword ptr [rdx+12], 'itam'  ; m a t i 
    jne not_equal
    cmp dword ptr [rdx+16], 'rPno'  ; o n P r 
    jne not_equal
    cmp dword ptr [rdx+20], 'seco'  ; o c e s  
    jne not_equal
    cmp byte ptr [rdx+24], 's'      ; s       
    jne not_equal
    cmp byte ptr [rdx+25], 0h
    jne not_equal
    mov rax, [GetProcAddressHook_NtQueryInformationProcess_ReturnValue]
    ret

not_equal:
    jmp [GetProcAddress_original]

GetProcAddressHook ENDP
GetProcAddressHook_end Label BYTE
END