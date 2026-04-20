.CODE

LongMode_On equ 1

; PushfqHandler(_Inout_ uint64_t Rsp, _In_ bool CSLongMode, _In_ uint64_t RflagsValue, _In_ uint32_t VmFlag, _In_ uint32_t RFlag, _In_ uint32_t TFlag):
PushfqHandler PROC PUBLIC
	; RCX - Rsp from guest
	; RDX - CSLongMode from guest
	; R8 - RFlags from guest
	; R9 - Vm Flag(8086 mode)(should be off)
	; [rsp + 028h] - Resume flag(should be off)
	xor r10, r10
	mov r10d, dword ptr [rsp + 028h]

	;Check Vm flag of 8086 Mode. This flag should be off
	cmp r9, 020000h

	jne @VmOff
	not r8w
	or r8w, 020000h
	; VM - 020000h
	not r8w
	; R8W - WITHOUT VM
@VmOff:
	;Check Resume flag. This flag should be off
	cmp r10, 010000h

	jne @RfOff
	not r8w
	or r8w, 010000h
	; RF - 010000h
	not r8w
	; R8W - WITHOUT RF
@RfOff:
	cmp rdx, LongMode_On
	je @LongMode_On
@LongMode_Disable:
	sub rcx, 4
	;cmp r11d, 0100h
	;jne @WITHOUTLOF_TF

	not r8d
	or r8d, 0100h
	; TF - 0100h
	not r8d
	; R8D - WITHOUT TF
;@WITHOUTLOF_TF:
	mov dword ptr [rcx], r8d
    jmp @Fin
@LongMode_On:
	sub rcx, 8
	;cmp r11d, 0100h
	;jne @WITHOUTLON_TF

	not r8
	or r8, 0100h
	; TF - 0100h
	not r8
;@WITHOUTLON_TF:
	; R8 - WITHOUT TF
	mov qword ptr [rcx], r8

@Fin:
	mov rax, rcx
	ret
PushfqHandler ENDP

; PushfHandler(_In_ uint64_t Rsp, _In_ bool CSLongMode, _In_ uint64_t RflagsValue, _In_ uint32_t VmFlag, _In_ uint32_t RFlag):
PushfHandler PROC PUBLIC
	; RCX - Rsp from guest
	; RDX - CSLongMode from guest
	; R8 - RFlags from guest
	; R9 - Vm Flag(8086 mode)(must be off)
	; [rsp + 028h] - Resume flag(must be off)
	xor r10,r10
	mov r10d, dword ptr [rsp + 028h]

	;Check Vm flag of 8086 Mode. This flag should be off
	cmp r9, 020000h

	jne @VmOff
	not r8w
	or r8w, 020000h
	; VM - 020000h
	not r8w
	; R8W - WITHOUT VM
@VmOff:
	;Check Resume flag. This flag should be off
	cmp r10, 010000h

	jne @RfOff
	not r8w
	or r8w, 010000h
	; RF - 010000h
	not r8w
	; R8W - WITHOUT RF
@RfOff:
	cmp rdx, LongMode_On
	je @LongMode_On
@LongMode_Disable:
	sub rcx, 4
	not r8w
	or r8w, 0100h
	; TF - 0100h
	not r8w
	; R8W - WITHOUT TF
	mov word ptr [rcx], r8w
    jmp @Fin
@LongMode_On:
	sub rcx, 8
	not r8w
	or r8w, 0100h
	; TF - 0100h
	not r8w
	; R8W - WITHOUT TF
	mov word ptr [rcx], r8w

@Fin:
	mov rax, rcx
	ret
PushfHandler ENDP
END