#pragma once
//
// Shared kernel-stack capture for event senders.
//
// Include AFTER common.h (needs fltKernel decls such as KeGetCurrentIrql and
// RtlWalkFrameChain, edrdrv::EventField, and the lbvsext write() helpers).
//
// Captures the current kernel return addresses (RtlWalkFrameChain) and writes
// them as EvFld::KernelStack: a comma-separated hex string. String transport
// keeps the field first-class on every layer (LBVS str, Variant string, JSON
// logs, GUI display, ptm.local.src imatch patterns, offline symbolization).
// Strictly best-effort everywhere: any failure silently omits the field,
// never the event itself (a fault here would bugcheck the machine).
//
namespace cmd {
namespace kstack {

/// Max kernel frames captured per event. Small by design: enough to name the
/// blocking filter/driver, cheap enough for the hot path (10 x 17 chars).
constexpr ULONG c_nKernelStackMaxFrames = 10;

/// Hex digits for address formatting (no CRT dependency in the walk path).
constexpr wchar_t c_wszHexDigits[] = L"0123456789abcdef";

/// Capture + hex-format the current kernel stack.
/// @param wsBuffer Output buffer (wide chars, including room for terminator).
/// @param nBufferChars Buffer capacity in wide chars.
/// @return Chars written excluding terminator, 0 when skipped.
/// @note Callers guarantee IRQL <= APC_LEVEL; re-checked defensively.
_IRQL_requires_max_(APC_LEVEL)
inline ULONG captureKernelStackHex(_Out_writes_(nBufferChars) wchar_t* wsBuffer, _In_ ULONG nBufferChars)
{
	if (wsBuffer == nullptr || nBufferChars < 2)
		return 0;
	if (KeGetCurrentIrql() > APC_LEVEL)
		return 0;
	__try
	{
		PVOID pFrames[c_nKernelStackMaxFrames] = {};
		// Skip 1 frame: this helper itself.
		const ULONG nFlags = (1 << RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT);
		ULONG nCount = RtlWalkFrameChain(pFrames, c_nKernelStackMaxFrames, nFlags);
		if (nCount > c_nKernelStackMaxFrames)
			nCount = c_nKernelStackMaxFrames;

		// Format: 16 hex digits per address, comma-separated, no 0x prefix.
		ULONG nPos = 0;
		for (ULONG i = 0; i < nCount; ++i)
		{
			if (i != 0)
			{
				if (nPos + 1 >= nBufferChars)
					break;
				wsBuffer[nPos++] = L',';
			}
			if (nPos + 16 >= nBufferChars)
				break;
			const ULONG_PTR nAddr = (ULONG_PTR)pFrames[i];
			for (int nShift = 60; nShift >= 0; nShift -= 4)
				wsBuffer[nPos++] = c_wszHexDigits[(nAddr >> nShift) & 0xF];
		}
		wsBuffer[nPos] = L'\0';
		return nPos;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}
}

/// Format + write EvFld::KernelStack into any LBVS serializer.
/// @return false only when the serializer itself is out of memory (caller
///         should propagate STATUS_NO_MEMORY); skipping is success (true).
template<typename Serializer>
inline bool writeKernelStack(Serializer& serializer)
{
	// 10 frames x (16 hex + 1 comma) + terminator.
	wchar_t wsStack[c_nKernelStackMaxFrames * 17 + 1] = {};
	if (captureKernelStackHex(wsStack, ARRAYSIZE(wsStack)) == 0)
		return true;
	UNICODE_STRING usStack;
	RtlInitUnicodeString(&usStack, wsStack);
	return write(serializer, edrdrv::EventField::KernelStack, &usStack);
}

} // namespace kstack
} // namespace cmd
