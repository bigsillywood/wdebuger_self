
OPTION PROLOGUE:none
OPTION EPILOGUE:none
OPTION CASEMAP:NONE     ; 保持大小写

PUBLIC NtDebugContinue
PUBLIC ZwRemoveProcessDebug

.code

NtDebugContinue PROC
    mov     r10, rcx
    mov     eax, 0D7h
    syscall
    ret
NtDebugContinue ENDP

ZwRemoveProcessDebug PROC
    mov     r10, rcx
    mov     eax, 180h
    syscall
    ret
ZwRemoveProcessDebug ENDP

END
