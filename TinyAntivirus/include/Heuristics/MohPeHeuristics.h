#pragma once
#include "../TinyAvBase.h"
#include "../FileType/PEFile.h"

enum MohPeHeuristicFlags
{
	MohPeHeuristicNone = 0,
	MohPeHeuristicSuspiciousImportMix = 1 << 0,
	MohPeHeuristicLoaderImports = 1 << 1,
	MohPeHeuristicNetworkExecutionImports = 1 << 2,
	MohPeHeuristicEntrypointToLastSection = 1 << 3,
	MohPeHeuristicWritableExecutableLastSection = 1 << 4,
	MohPeHeuristicEntrypointLoaderStub = 1 << 5,
};

typedef struct Moh_PE_HEURISTIC_RESULT
{
	ULONG flags;
	ULONG score;
	ULONG importDllCount;
	ULONG importFunctionCount;
	UINT entrySectionIndex;
	UINT lastSectionIndex;
	BOOL detected;
} Moh_PE_HEURISTIC_RESULT, *LPMoh_PE_HEURISTIC_RESULT;

HRESULT WINAPI AnalyzeMohPeHeuristics(__in IPeFile *peFile, __out Moh_PE_HEURISTIC_RESULT *result);
