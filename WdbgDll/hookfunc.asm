
PUBLIC NtQueryInformationProcessDebugHook_begin 
PUBLIC NtQueryInformationProcessDebugHook_end 
PUBLIC GetProcAddressHook_begin
PUBLIC GetProcAddressHook_end
PUBLIC OutputDebugStringHook_begin
PUBLIC OutputDebugStringhook_end
PUBLIC NtSetInformationThreadHook_begin
PUBLIC NtSetInformationThreadHook_end

.code

OutputDebugStringHook_begin PROC
    ret
OutputDebugStringHook_begin ENDP
OutputDebugStringHook_end Label BYTE


NtSetInformationThreadHook_begin Label BYTE
NtSetInformationThread_original dq 0
NtSetInformationThreadHook PROC
    cmp rdx,011h
    jne NtSetInformationThreadHook_skip
    xor eax,eax
    ret

NtSetInformationThreadHook_skip:
    jmp [NtSetInformationThread_original]
    

NtSetInformationThreadHook ENDP
NtSetInformationThreadHook_end Label BYTE


;rcx =ProcessHandle
;rdx =ProcessInformationClass
;r8 =ProcessInformation
;r9 =ProcessInformationLen
;cur rsp+28h =Preturn Len
NtQueryInformationProcessDebugHook_begin PROC
    cmp rdx,7h
    jz hookskipA
    cmp rdx,01Eh
    jz hookskipB
    cmp rdx,01Fh
    jz hookskipC

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
    jnz hookskiperror
    mov qword ptr [r8],0
    mov eax,0
retlen:
    cmp qword ptr [rsp+28h],0
    jz hookskipretlen
    push rsi
    mov rsi,[rsp+30h]
    mov dword ptr [rsi],8h
    pop rsi
    ret 
hookskipretlen:
    ret
hookskiperror:
    mov eax,0C0000004h
    ret

hookskipB:
    cmp r9,8
    jnz hookskiperror
    mov rax,0C0000353h
    jmp retlen

hookskipC:
    cmp r9,4
    jnz hookskiperror
    mov dword ptr [r8],1
    mov eax,0
    cmp qword ptr [rsp+28h],0
    jz hookskipretlen
    push rsi
    mov rsi,[rsp+30h]
    mov dword ptr [rsi],4h
    pop rsi
    ret

NtQueryInformationProcessDebugHook_begin ENDP
NtQueryInformationProcessDebugHook_end Label BYTE



GetProcAddressHook_begin Label BYTE
GetProcAddressHook_NtQueryInformationProcess_ReturnValue dq 0
GetProcAddressHook_NtSetInformationThread_ReturnValue    dq 0
GetProcAddressHook_OutputDebugString_ReturnValue         dq 0
GetProcAddress_original                                  dq 0

GetProcAddressHook PROC
    ; ── NtQueryInformationProcess ──
    ; N t Q u
    cmp dword ptr [rdx], 'uQtN'
    jne not_equal1
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
    cmp byte  ptr [rdx+24], 's'
    jne not_equal
    cmp byte  ptr [rdx+25], 0h
    jne not_equal
    mov rax, [GetProcAddressHook_NtQueryInformationProcess_ReturnValue]
    ret

not_equal1:
    ; ── OutputDebugStringA / OutputDebugStringW ──
    ; O u t p
    cmp dword ptr [rdx], 'ptuO'
    jne not_equal2
    ; u t D e
    cmp dword ptr [rdx+4], 'eDtu'
    jne not_equal
    ; b u g S
    cmp dword ptr [rdx+8], 'Sgub'
    jne not_equal
    ; t r i n
    cmp dword ptr [rdx+12], 'nirt'
    jne not_equal
    ; g A  or  g W
    cmp byte ptr [rdx+16], 'g'
    jne not_equal
    cmp byte ptr [rdx+17], 'A'
    je  is_output_debug
    cmp byte ptr [rdx+17], 'W'
    jne not_equal
is_output_debug:
    cmp byte ptr [rdx+18], 0h
    jne not_equal
    mov rax, [GetProcAddressHook_OutputDebugString_ReturnValue]
    ret

not_equal2:
    ; ── NtSetInformationThread ──
    ; N t S e
    cmp dword ptr [rdx], 'eStN'
    jne not_equal
    ; t I n f
    cmp dword ptr [rdx+4], 'fnIt'
    jne not_equal
    ; o r m a
    cmp dword ptr [rdx+8], 'amro'
    jne not_equal
    ; t i o n
    cmp dword ptr [rdx+12], 'noit'
    jne not_equal
    ; T h r e
    cmp dword ptr [rdx+16], 'erhT'
    jne not_equal
    ; a d
    cmp byte ptr [rdx+20], 'a'
    jne not_equal
    cmp byte ptr [rdx+21], 'd'
    jne not_equal
    cmp byte ptr [rdx+22], 0h
    jne not_equal
    mov rax, [GetProcAddressHook_NtSetInformationThread_ReturnValue]
    ret

not_equal:
    jmp [GetProcAddress_original]

GetProcAddressHook ENDP
GetProcAddressHook_end Label BYTE
END
END