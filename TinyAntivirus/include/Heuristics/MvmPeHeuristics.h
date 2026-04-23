#pragma once
#include "../TinyAvBase.h"
#include "../FileType/PEFile.h"

enum MvmPeHeuristicFlags
{
	MvmPeHeuristicNone = 0,
	MvmPeHeuristicSuspiciousImportMix = 1 << 0,
	MvmPeHeuristicLoaderImports = 1 << 1,
	MvmPeHeuristicNetworkExecutionImports = 1 << 2,
	MvmPeHeuristicEntrypointToLastSection = 1 << 3,
	MvmPeHeuristicWritableExecutableLastSection = 1 << 4,
	MvmPeHeuristicEntrypointLoaderStub = 1 << 5,
};

typedef struct MVM_PE_HEURISTIC_RESULT
{
	ULONG flags;
	ULONG score;
	ULONG importDllCount;
	ULONG importFunctionCount;
	UINT entrySectionIndex;
	UINT lastSectionIndex;
	BOOL detected;
} MVM_PE_HEURISTIC_RESULT, *LPMVM_PE_HEURISTIC_RESULT;

HRESULT WINAPI AnalyzeMvmPeHeuristics(__in IPeFile *peFile, __out MVM_PE_HEURISTIC_RESULT *result);
