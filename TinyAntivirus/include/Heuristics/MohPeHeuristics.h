#pragma once
#include "../TinyAvBase.h"
#include "../FileType/PEFile.h"

enum MosPeSignatureFlags
{
	MosPeSignatureNone = 0,
	MosPeSignatureSuspiciousImportMix = 1 << 0,
	MosPeSignatureLoaderImports = 1 << 1,
	MosPeSignatureNetworkExecutionImports = 1 << 2,
	MosPeSignatureEntrypointToLastSection = 1 << 3,
	MosPeSignatureWritableExecutableLastSection = 1 << 4,
	MosPeSignatureEntrypointLoaderStub = 1 << 5,
};

typedef struct MOS_PE_SIGNATURE_RESULT
{
	ULONG flags;
	ULONG score;
	ULONG importDllCount;
	ULONG importFunctionCount;
	UINT entrySectionIndex;
	UINT lastSectionIndex;
	BOOL detected;
} MOS_PE_SIGNATURE_RESULT, *LPMOS_PE_SIGNATURE_RESULT;

HRESULT WINAPI AnalyzeMosPeSignatures(__in IPeFile *peFile, __out MOS_PE_SIGNATURE_RESULT *result);
