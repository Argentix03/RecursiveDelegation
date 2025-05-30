.CODE

EXTERN ProcessResultAndExit : PROC  ; Declare external C++ function

CaptureRAX_And_CallHelper PROC

    ; tl;dr 
    ; mov rcx, rax 
    ; sub rsp, 28h
    ; call ProcessResultAndExit

    ; At this point, when this stub is entered via 'ret' from the target API:
    ; - RAX contains the return value of the target API.
    ; - RSP points to the "return address" that was pushed by the target API's caller
    ;   (which is actually not relevant here as we are the effective return).
    ;   More accurately, RSP points to what was *after* our own address on the stack
    ;   if NtContinue set up a stack frame for the target API that included our stub's address.
    ;   In our PrepareStackForApiCall, RSP (finalRspVal) points to *our* stub address.
    ;   So when the target API 'ret's, it pops our stub's address into RIP,
    ;   and RSP is incremented by 8.
    ;   The value at [RSP] now would be the StubWorkerContext* we plan to add later.

    ; For now, the stub only needs to capture RAX and call the C++ helper.
    ; The C++ helper will take RAX as its first argument (in RCX).

    mov rcx, rax          ; Move target API's return value (RAX) into RCX for ProcessResultAndExit

    ; Before calling another function (ProcessResultAndExit),
    ; we need to allocate shadow space (home space) on the stack for the callee.
    ; The stack must also be 16-byte aligned *before* the CALL instruction.
    ; RSP is currently (16*N)+8 because the target API's `ret` just popped 8 bytes.
    ; To make it 16-byte aligned before our CALL:
    ;   push some_register  (RSP is now 16*N) ; or sub rsp, 8
    ;   call CppHelper
    ;   pop some_register   (RSP is now 16*N+8)
    ; More robustly:
    sub rsp, 28h          ; Allocate 32 bytes for shadow space (for CppHelper)
                          ; plus 8 bytes to maintain 16-byte alignment for the call
                          ; (RSP was (16N)+8, sub 8 -> 16N, sub 20h -> 16M for call)
                          ; (RSP (16N)+8 -> after sub 28h (40 bytes) -> (16N)+8 - (16*2+8) = 16(N-2) -> 16-byte aligned RSP.
                          ; This makes RSP 16-byte aligned. The call will push RIP, making new RSP (16M)+8 for CppHelper.

    call ProcessResultAndExit

CaptureRAX_And_CallHelper ENDP

END