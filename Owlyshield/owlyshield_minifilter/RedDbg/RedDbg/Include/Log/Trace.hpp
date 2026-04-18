#pragma once

#include "Zydis/Zydis.h"
#include "HyperVisor/CommonTypes/SVM.hpp"
#include "Log/GraphViz/GraphVizLanguage.hpp"
#include "Log/File.hpp"

#include <ntddk.h>
#include <vector>
#include <unordered_map>
#include <unordered_set>

const UINT64 ASLRSystemAddr = 0x00007FF000000000;
#define SpaceBar 2
const int Arcs = 52;

typedef struct {
	uint64_t first;
	uint64_t second;
} GraphNode;


typedef struct _AddressTranslateMap {
	uint64_t key = 0;    // Original number
	uint64_t value = 0;  // Translated number
} AddressTranslateMap;

enum SizeRestrictions : const size_t {
	BufferSize = 100 * 1024 * 1024,//2621440 * sizeof(Mnemonic),//100 * 1024 * 1024,
	ReserveBufferSize = BufferSize,
	MAX_NODES = 51,
	MainNodesBytes = 1024,
};

template<typename Type>
class TraceMessage {
public:
	Type* Start = nullptr;
	Type* CurrentWriteIndex = nullptr;
	Type* End = nullptr;

	size_t AllSize = 0;
	size_t Size = 0;
	size_t DataWritten = 0;

	bool Reading = false;
	
	void write_front(const void* Data, const size_t SizeOfData);
	void clear();
	int find(const uint64_t Val, const size_t SizeOfData);
	size_t size(const size_t SizeOfData);
};

struct Mnemonic {
	uint8_t Opcodes[ZYDIS_MAX_INSTRUCTION_LENGTH + 1]{};
	uint64_t Address = 0;

	size_t Length = 0;

	bool Graph = false;
	bool operator==(const Mnemonic& t) const
	{
		return (this->Address == t.Address);
	}
};

class MyHashFunction {
public:
	// id is returned as hash function
	size_t operator()(const Mnemonic& t) const
	{
		return t.Address;
	}
};

class Trace {
private:
	uint64_t TranslationNumberCounter = 0;

	uint64_t* MainGraphs = nullptr;

	GraphNode* edges = nullptr;
	uint64_t** adjList = nullptr;
	uint64_t** adjListT = nullptr;

	uint64_t* adjListSize = nullptr;
	uint64_t* adjListTSize = nullptr;

	int64_t* visited = nullptr;

	uint64_t* postOrder = nullptr;
	uint64_t* component = nullptr;

	ZydisDecodedInstruction* Instruction = nullptr;
	ZydisDecoder* DecoderMinimal = nullptr;
	ZydisDecoder* DecoderFull = nullptr;
	ZydisDecodedOperand* Operands = nullptr;

	std::vector<TraceMessage<uint64_t>> CircleOfRips;
	std::vector<TraceMessage<Mnemonic>> CircleOfMnemonics;

	Mnemonic MnemonicCreator(_In_ uint64_t Rip, _In_ SVM::PRIVATE_VM_DATA* Private);

	void CircleOfMnemonicsFiller(_In_ uint64_t Rip, _In_ SVM::PRIVATE_VM_DATA* Private);
	
	uint64_t TranslateNumber(uint64_t number);

	uint64_t GetOriginalTransVal(uint64_t Val);

	void InitCycle();
	void KosarajuAlgorithm(uint64_t numNodes, uint64_t numEdges);
	void dfs2(uint64_t** _adjListT, uint64_t numNodes, uint64_t node, int64_t* _visited, uint64_t* _component, uint64_t* componentIndex);
	void dfs1(uint64_t** _adjList, uint64_t numNodes, uint64_t node, int64_t* _visited, uint64_t* _postOrder, uint64_t* index);
	void addEdge(uint64_t** _adjList, uint64_t from, uint64_t to, uint64_t* size);
public:
	bool Exit = false;
	bool EoF = false;

	bool TraceInitializeRip();
	bool TraceInitializeMnemonic();

	void AcceptRipMessage(File& objFile);
	void AcceptMnemonicMessage(File& objFile);
	void AcceptGraphMessage(File& objFile);
	void AcceptGraphCycleFoldingMessage(File& objFile);

	void TraceRip(_In_ SVM::PRIVATE_VM_DATA* Private);
	void TraceMnemonic(_In_ SVM::PRIVATE_VM_DATA* Private);

	void TraceRipFinalization();
	void TraceMnemonicFinalization();
};