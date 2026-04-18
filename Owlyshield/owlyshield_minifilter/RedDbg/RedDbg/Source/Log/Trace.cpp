#include "Log/Trace.hpp"

#include <ntstrsafe.h>
#include <intrin.h>
GraphVizLanguage objGraphVizLanguage;

void RtlInt64ToCharArray(_In_ uint64_t number, IN ULONG Base, _Out_ CHAR* hexString, _In_ size_t hexStringSize)
{
	CHAR Buffer[65];

	PCHAR Pos = &Buffer[64];
	*Pos = '\0';

	do
	{
		Pos--;
		CHAR Digit = (CHAR)(number % Base);
		number = number / Base;

		if (Digit < 10)
			*Pos = '0' + Digit;
		else
			*Pos = 'A' + Digit - 10;
	} while (number != 0L);

	size_t Len = &Buffer[64] - Pos;

	if (Len < hexStringSize)
		Len += 1;

	RtlCopyMemory(hexString, Pos, Len);
}

void RtlInt64ToCharExsitingArray(_In_ uint64_t number, IN ULONG Base, _Out_ CHAR* hexString, _Inout_ size_t Length)
{
	CHAR Buffer[65];

	PCHAR Pos = &Buffer[64];
	*Pos = '\0';

	do
	{
		Pos--;
		CHAR Digit = (CHAR)(number % Base);
		number = number / Base;

		if (Digit < 10)
			*Pos = '0' + Digit;
		else
			*Pos = 'A' + Digit - 10;
	} while (number != 0L);

	size_t Len = &Buffer[64] - Pos;

	Length = Len;
	RtlCopyMemory(hexString, Pos, Len);
}

#define STRCATADDR(Dest, Addr, Base, LenOut, ValLen) \
	RtlInt64ToCharExsitingArray(Addr, Base, (PCH)Dest, LenOut); \
	ValLen += strlen(Dest); \
	Dest = (PCH)(UINT64(Dest) + strlen(Dest));

#define EntryPointOfGraphVizLanguage(WriteTo, Name, Len) \
	STRCAT(WriteTo, objGraphVizLanguage.DigraphQuote, Len); \
	STRCAT(WriteTo, Name, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.StartOfdigraph, Len)

#define NodeAttributesOfDigraph(WriteTo, Len) \
    STRCAT(WriteTo, objGraphVizLanguage.Node, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.StartOfLabel, Len);\
	STRCAT(WriteTo, objGraphVizLanguage.Shape, Len);\
	STRCAT(WriteTo, objGraphVizLanguage.RecordShape, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.FontCourierName, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.FillBlackColor, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.FontColor, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.StyleTrue, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.EndOfLabel, Len);

#define AddGraph(WriteTo, UINT64FromAddr, UINT64ToAddr, Base, Len, LenOut) \
	STRCAT(WriteTo, objGraphVizLanguage.Address, Len); \
	STRCATADDR(WriteTo, UINT64FromAddr, Base, LenOut, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.Line, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.Address, Len); \
	STRCATADDR(WriteTo, UINT64ToAddr, Base, LenOut, Len);

#define SpecificNodeAdd(WriteTo, UINT64A, Base, Len, LenOut) \
	STRCAT(WriteTo, objGraphVizLanguage.Address, Len); \
	STRCATADDR(WriteTo, UINT64A, Base, LenOut, Len);

#define SpecificNodeLabel(WriteTo, _LabelText, Len) \
    STRCAT(WriteTo, objGraphVizLanguage.StartOfLabel, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.Label, Len); \
	STRCAT(WriteTo, _LabelText, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.EndOfLabel, Len); \
	STRCAT(WriteTo, "\n", Len);

#define SpecificNodeEntryLabel(WriteTo, Len) \
    STRCAT(WriteTo, objGraphVizLanguage.StartOfLabel, Len); \
	STRCAT(WriteTo, objGraphVizLanguage.Label, Len);

#define SpecificNodeFinLabel(WriteTo, Len) \
	STRCAT(WriteTo, "\"", Len); \
	STRCAT(WriteTo, objGraphVizLanguage.EndOfLabel, Len); \
	STRCAT(WriteTo, "\n", Len);

template<typename Type>
void TraceMessage<Type>::write_front(const void* Data, const size_t SizeOfData)
{
	//memcpy((void*)(CurrentWriteIndex), (const void*)Data, (size_t)SizeOfData); CurrentWriteIndex += SizeOfData; DataWritten += SizeOfData;
	if (CurrentWriteIndex < End && CurrentWriteIndex + SizeOfData < End && SizeOfData > 0)
	{
		memcpy((void*)(CurrentWriteIndex), (const void*)Data, (size_t)SizeOfData); CurrentWriteIndex += SizeOfData; DataWritten += SizeOfData;
	}
}

template<typename Type>
void TraceMessage<Type>::clear()
{
	memset(Start, 0, AllSize);  DataWritten = 0; Size = 0; CurrentWriteIndex = Start;
}

template<typename Type>
size_t TraceMessage<Type>::size(const size_t SizeOfData)
{
	Size = DataWritten / SizeOfData;
	return Size;
}

template<typename Type>
int TraceMessage<Type>::find(const uint64_t Val, const size_t SizeOfData)
{
	for (Type* LocalCWI = Start; LocalCWI < CurrentWriteIndex; LocalCWI += SizeOfData)
	{
		if (*LocalCWI == Val)
		{
			return *LocalCWI;
		}
	}
	return -1;
}

char* AttachString(char* buffer, char* string_to_attach)
{
	size_t buffer_size = strlen(buffer);
	size_t string_size = strlen(string_to_attach);
	PCH new_buffer =
		(PCH)ExAllocatePool(NonPagedPoolNx, buffer_size + string_size + 1); // allocate memory for combined string
	if (new_buffer != nullptr)
	{
		strcpy_s(new_buffer, sizeof(buffer), buffer); // copy original buffer to new buffer
		strcat_s(new_buffer, sizeof(string_to_attach), string_to_attach); // append string to new buffer
		return new_buffer;
	}
	else { return nullptr; }
}

void Trace::AcceptRipMessage(File& objFile)
{
	int Arc = 0;
	for (;;)
	{
		if (CircleOfRips[Arc].Reading)
		{
			KdPrint(("Data written %p and ARC IS %d\n", CircleOfRips[Arc].size(sizeof(uint64_t)), Arc));
			KdPrint(("First data %p\n", CircleOfRips[Arc].Start[0]));

			CHAR EndCharacters[] = "\r\n";
			size_t totalSize = 0;
			for (uint64_t Rip = 0; Rip < CircleOfRips[Arc].size(sizeof(uint64_t)); ++Rip)
			{
				totalSize += strlen(EndCharacters);
				totalSize += sizeof(uint64_t) * 2; // Space for Address
			}

			PCH ValuesBuffer = (PCH)ExAllocatePool(NonPagedPoolNx, totalSize);
			if (ValuesBuffer != nullptr)
			{
				uint64_t* LocalCWI = CircleOfRips[Arc].Start;
				PCH ValuesCWI = ValuesBuffer;
				size_t ValuesLen = 0;

				for (uint64_t Rip = 0; Rip < CircleOfRips[Arc].size(sizeof(uint64_t)); ++Rip)
				{
					size_t Length = 0;
					RtlInt64ToCharExsitingArray(*LocalCWI, 16, (PCH)ValuesCWI, Length);
					ValuesLen += strlen(ValuesCWI);
					ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(ValuesCWI));

					LocalCWI += sizeof(uint64_t);
				}
				objFile.WriteFile(ValuesBuffer, ValuesLen);

				KdPrint(("Fin\n"));
				ExFreePool(ValuesBuffer);
			}

			CircleOfRips[Arc].clear();
			CircleOfRips[Arc].Reading = false;
		}
		if (Arc == 15) { Arc = 0; }
		else { ++Arc; }
	}
}

void Trace::AcceptMnemonicMessage(File& objFile)
{
	int Arc = 0;
	for (;;)
	{
		if (CircleOfMnemonics[Arc].Reading)
		{
			KdPrint(("Data written %p and ARC IS %x\n", CircleOfMnemonics[Arc].size(sizeof(Mnemonic)), Arc));

			CHAR EndCharacters[] = "\n", BarCharacters[] = " | ", Bar2Characters[] = "| ", Space[] = " ";
			size_t totalSize = 0;
			for (uint64_t cMnemonic = 0; cMnemonic < CircleOfMnemonics[Arc].size(sizeof(Mnemonic)); ++cMnemonic)
			{
				totalSize += strlen(BarCharacters);
				totalSize += strlen(Bar2Characters);
				totalSize += strlen(EndCharacters);
				totalSize += sizeof(Mnemonic) * 2; // Space for Address and Opcodes

				for (uint8_t Opcode = 0; Opcode < ZYDIS_MAX_INSTRUCTION_LENGTH; ++Opcode)
				{
					totalSize += 3; // Length of each opcode
					totalSize += strlen(Space);
				}
			}

			PCH ValuesBuffer = (PCH)ExAllocatePool(NonPagedPoolNx, totalSize);
			if (ValuesBuffer != nullptr)
			{
				Mnemonic* LocalCWI = CircleOfMnemonics[Arc].Start;
				PCH ValuesCWI = ValuesBuffer;
				size_t ValuesLen = 0;
				size_t Length = 0;

				for (uint64_t cMnemonic = 0; cMnemonic < CircleOfMnemonics[Arc].size(sizeof(Mnemonic)); ++cMnemonic)
				{
					RtlInt64ToCharExsitingArray(LocalCWI->Address, 16, (PCH)ValuesCWI, Length);
					ValuesLen += strlen(ValuesCWI);
					ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(ValuesCWI));

					strcat_s((PCH)ValuesCWI, sizeof(BarCharacters), BarCharacters);
					ValuesLen += strlen(BarCharacters);
					ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(BarCharacters));

					for (uint8_t Opcode = 0; Opcode < LocalCWI->Length; ++Opcode)
					{
						RtlInt64ToCharExsitingArray(LocalCWI->Opcodes[Opcode], 16, (PCH)ValuesCWI, Length);
						ValuesLen += strlen(ValuesCWI);
						ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(ValuesCWI));

						strcat_s((PCH)ValuesCWI, sizeof(Space), Space);
						ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(Space));
						ValuesLen += strlen(Space);
					}
					strcat_s((PCH)ValuesCWI, sizeof(Bar2Characters), Bar2Characters);
					ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(Bar2Characters));
					ValuesLen += strlen(Bar2Characters);

					RtlInt64ToCharExsitingArray(LocalCWI->Length, 10, (PCH)ValuesCWI, Length);
					ValuesLen += strlen(ValuesCWI);
					ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(ValuesCWI));

					strcat_s((PCH)ValuesCWI, sizeof(EndCharacters), EndCharacters);
					ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(EndCharacters));
					ValuesLen += strlen(EndCharacters);

					LocalCWI += sizeof(Mnemonic);
				}

				objFile.WriteFile(ValuesBuffer, ValuesLen);

				KdPrint(("Fin\n"));
				ExFreePool(ValuesBuffer);
			}

			CircleOfMnemonics[Arc].clear();
			CircleOfMnemonics[Arc].Reading = false;
		}
		if (Arc == 15) { Arc = 0; }
		else { ++Arc; }
	}
}
bool Entry = false;
void Trace::AcceptGraphMessage(File& objFile)
{
	int Arc = 0;
	for (;;)
	{
		if (CircleOfMnemonics[Arc].Reading)
		{
			KdPrint(("Data written %p and ARC IS %x\n", CircleOfMnemonics[Arc].size(sizeof(Mnemonic)), Arc));
			//auto addr = (CircleOfMnemonics[Arc].End)->Address;
			//KdPrint(("Last addr %p\n", addr));

			PCH ValuesBuffer = (PCH)ExAllocatePool(NonPagedPoolNx, 4294967296);
			RtlZeroMemory(ValuesBuffer, 4294967296);
			if (ValuesBuffer != nullptr)
			{
				Mnemonic* LocalCWI = CircleOfMnemonics[Arc].Start;
				PCH ValuesCWI = ValuesBuffer;
				size_t ValuesLen = 0;
				size_t Length = 0;
				CHAR NameOfGraph[] = "test";

				if (!Entry)
				{
					EntryPointOfGraphVizLanguage(ValuesCWI, NameOfGraph, ValuesLen);
					NodeAttributesOfDigraph(ValuesCWI, ValuesLen);
					Entry = true;
				}

				for (uint64_t cMnemonic = 0; cMnemonic < CircleOfMnemonics[Arc].size(sizeof(Mnemonic)); ++cMnemonic)
				{
					Mnemonic* EndOfGraph = LocalCWI;
					Mnemonic* StartOfNextGraph = EndOfGraph + sizeof(Mnemonic);

					if (LocalCWI->Graph == true && StartOfNextGraph->Address != 0)
					{
						Mnemonic* TempLocalCWI = EndOfGraph;
						{
							for (int64_t Index = cMnemonic; Index > 0; --Index)
							{
								TempLocalCWI -= sizeof(Mnemonic);
								if (TempLocalCWI->Graph == true) { TempLocalCWI += sizeof(Mnemonic); break; }
							}
						}
						Mnemonic* StartOfGraph = TempLocalCWI;

						Mnemonic* TempNextGraph = StartOfNextGraph;
						{
							for (int64_t Index = cMnemonic + 1; Index < CircleOfMnemonics[Arc].size(sizeof(Mnemonic)); ++Index)
							{
								TempNextGraph += sizeof(Mnemonic);
								if (TempNextGraph->Graph == true) { TempNextGraph -= sizeof(Mnemonic); break; }
							}
						}
						Mnemonic* EndOfNextGraph = TempNextGraph;

						if (((EndOfGraph + sizeof(Mnemonic)) <= CircleOfMnemonics[Arc].End))
						{
							size_t LenOut = 0;
							SpecificNodeAdd(ValuesCWI, StartOfGraph->Address, 16, ValuesLen, LenOut);

							{
								SpecificNodeEntryLabel(ValuesCWI, ValuesLen);
								for (Mnemonic* PMnemonic = StartOfGraph; PMnemonic <= EndOfGraph; PMnemonic += sizeof(Mnemonic))
								{
									STRCATADDR(ValuesCWI, PMnemonic->Address, 16, LenOut, ValuesLen);

									STRCAT(ValuesCWI, ": ", ValuesLen);

									ZydisDecoder Decoder;
									ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

									ZydisFormatter Formatter;
									ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);

									ZydisDecodedInstruction Instruction;
									ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

									ZydisDecoderDecodeFull(&Decoder,
										(const void*)PMnemonic->Opcodes, PMnemonic->Length, &Instruction,
										Operands);

									ZydisFormatterFormatInstruction(
										&Formatter, &Instruction, Operands, Instruction.operand_count_visible, ValuesCWI,
										128, PMnemonic->Address, NULL);

									ValuesLen += strlen(ValuesCWI);
									ValuesCWI = (PCH)(UINT64(ValuesCWI) + strlen(ValuesCWI));

									STRCAT(ValuesCWI, "\\l", ValuesLen);
									STRCAT(ValuesCWI, "\\n", ValuesLen);
								}
								SpecificNodeFinLabel(ValuesCWI, ValuesLen);
							}

							SpecificNodeAdd(ValuesCWI, StartOfNextGraph->Address, 16, ValuesLen, LenOut);

							{
								SpecificNodeEntryLabel(ValuesCWI, ValuesLen);
								for (Mnemonic* PMnemonic = StartOfNextGraph; PMnemonic < EndOfNextGraph; PMnemonic += sizeof(Mnemonic))
								{
									STRCATADDR(ValuesCWI, PMnemonic->Address, 16, LenOut, ValuesLen);

									STRCAT(ValuesCWI, ": ", ValuesLen);

									ZydisDecoder Decoder;
									ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

									ZydisFormatter Formatter;
									ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);

									ZydisDecodedInstruction Instruction;
									ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

									ZydisDecoderDecodeFull(&Decoder,
										(const void*)PMnemonic->Opcodes, PMnemonic->Length, &Instruction,
										Operands);

									ZydisFormatterFormatInstruction(
										&Formatter, &Instruction, Operands, Instruction.operand_count_visible, ValuesCWI,
										128, PMnemonic->Address, NULL);

									ValuesLen += strlen(ValuesCWI);
									ValuesCWI = (PCH)(UINT64(ValuesCWI) + strlen(ValuesCWI));

									STRCAT(ValuesCWI, "\\l", ValuesLen);
									STRCAT(ValuesCWI, "\\n", ValuesLen);
								}
								SpecificNodeFinLabel(ValuesCWI, ValuesLen);
							}

							AddGraph(ValuesCWI, StartOfGraph->Address, StartOfNextGraph->Address, 16, ValuesLen, LenOut);

							strcat_s((PCH)ValuesCWI, sizeof("\n"), "\n");
							ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(ValuesCWI));
							ValuesLen += strlen("\n");
							//STRCAT(ValuesCWI, "\n", ValuesLen);
						}
					}
					LocalCWI += sizeof(Mnemonic);
				}
				if (EoF) { STRCAT(ValuesCWI, objGraphVizLanguage.EndOfdigraph, ValuesLen); EoF = false; }

				objFile.WriteFile(ValuesBuffer, ValuesLen);

				KdPrint(("Fin\n"));
				ExFreePool(ValuesBuffer);
			}
			CircleOfMnemonics[Arc].clear();
			CircleOfMnemonics[Arc].Reading = false;
		}
		if (Arc == 15) { Arc = 0; }
		else { ++Arc; }
	}
}

void Trace::AcceptGraphCycleFoldingMessage(File& objFile)
{
	bool Entry = false;
	int Arc = 0;
	std::unordered_set<Mnemonic, MyHashFunction> CycleFolding;
	for (;;)
	{
		if (CircleOfMnemonics[Arc].Reading)
		{
			KdPrint(("CircleOfMnemonics Data written %p and ARC IS %x\n", CircleOfMnemonics[Arc].size(sizeof(Mnemonic)), Arc));
			for (uint64_t cMnemonic = 0; cMnemonic < CircleOfMnemonics[Arc].size(sizeof(Mnemonic)); ++cMnemonic)
			{
				CycleFolding.insert(CircleOfMnemonics[Arc].Start[cMnemonic]);
			}
			KdPrint(("CycleFolding Data written %p and ARC IS %x\n", CycleFolding.size(), Arc));
			CircleOfMnemonics[Arc].clear();
			for (auto& it : CycleFolding)
			{
				CircleOfMnemonics[Arc].write_front((const void*)&it, sizeof(Mnemonic));
			}
			KdPrint(("CircleOfMnemonics after CycleFolding Data written %p and ARC IS %x\n", CircleOfMnemonics[Arc].size(sizeof(Mnemonic)), Arc));

			PCH ValuesBuffer = (PCH)ExAllocatePool(NonPagedPoolNx, 4294967296);
			if (ValuesBuffer != nullptr)
			{
				Mnemonic* LocalCWI = CircleOfMnemonics[Arc].Start;
				PCH ValuesCWI = ValuesBuffer;
				size_t ValuesLen = 0;
				size_t Length = 0;
				CHAR NameOfGraph[] = "test";

				if (!Entry)
				{
					EntryPointOfGraphVizLanguage(ValuesCWI, NameOfGraph, ValuesLen);
					NodeAttributesOfDigraph(ValuesCWI, ValuesLen);
					Entry = true;
				}

				for (uint64_t cMnemonic = 0; cMnemonic < CircleOfMnemonics[Arc].size(sizeof(Mnemonic)); ++cMnemonic)
				{
					Mnemonic* EndOfGraph = LocalCWI;
					Mnemonic* StartOfNextGraph = EndOfGraph + sizeof(Mnemonic);

					if (LocalCWI->Graph == true && StartOfNextGraph->Address != 0)
					{
						Mnemonic* TempLocalCWI = EndOfGraph;
						{
							for (int64_t Index = cMnemonic; Index > 0; --Index)
							{
								TempLocalCWI -= sizeof(Mnemonic);
								if (TempLocalCWI->Graph == true) { TempLocalCWI += sizeof(Mnemonic); break; }
							}
						}
						Mnemonic* StartOfGraph = TempLocalCWI;

						Mnemonic* TempNextGraph = StartOfNextGraph;
						{
							for (int64_t Index = cMnemonic + 1; Index < CircleOfMnemonics[Arc].size(sizeof(Mnemonic)); ++Index)
							{
								TempNextGraph += sizeof(Mnemonic);
								if (TempNextGraph->Graph == true) { TempNextGraph -= sizeof(Mnemonic); break; }
							}
						}
						Mnemonic* EndOfNextGraph = TempNextGraph;

						if (((EndOfGraph + sizeof(Mnemonic)) <= CircleOfMnemonics[Arc].End))
						{
							size_t LenOut = 0;
							SpecificNodeAdd(ValuesCWI, StartOfGraph->Address, 16, ValuesLen, LenOut);

							{
								SpecificNodeEntryLabel(ValuesCWI, ValuesLen);
								for (Mnemonic* PMnemonic = StartOfGraph; PMnemonic <= EndOfGraph; PMnemonic += sizeof(Mnemonic))
								{
									STRCATADDR(ValuesCWI, PMnemonic->Address, 16, LenOut, ValuesLen);

									STRCAT(ValuesCWI, ": ", ValuesLen);

									ZydisDecoder Decoder;
									ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

									ZydisFormatter Formatter;
									ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);

									ZydisDecodedInstruction Instruction;
									ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

									ZydisDecoderDecodeFull(&Decoder,
										(const void*)PMnemonic->Opcodes, PMnemonic->Length, &Instruction,
										Operands);

									ZydisFormatterFormatInstruction(
										&Formatter, &Instruction, Operands, Instruction.operand_count_visible, ValuesCWI,
										128, PMnemonic->Address, NULL);

									ValuesLen += strlen(ValuesCWI);
									ValuesCWI = (PCH)(UINT64(ValuesCWI) + strlen(ValuesCWI));

									STRCAT(ValuesCWI, "\\l", ValuesLen);
									STRCAT(ValuesCWI, "\\n", ValuesLen);
								}
								SpecificNodeFinLabel(ValuesCWI, ValuesLen);
							}

							SpecificNodeAdd(ValuesCWI, StartOfNextGraph->Address, 16, ValuesLen, LenOut);

							{
								SpecificNodeEntryLabel(ValuesCWI, ValuesLen);
								for (Mnemonic* PMnemonic = StartOfNextGraph; PMnemonic < EndOfNextGraph; PMnemonic += sizeof(Mnemonic))
								{
									STRCATADDR(ValuesCWI, PMnemonic->Address, 16, LenOut, ValuesLen);

									STRCAT(ValuesCWI, ": ", ValuesLen);

									ZydisDecoder Decoder;
									ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

									ZydisFormatter Formatter;
									ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);

									ZydisDecodedInstruction Instruction;
									ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

									ZydisDecoderDecodeFull(&Decoder,
										(const void*)PMnemonic->Opcodes, PMnemonic->Length, &Instruction,
										Operands);

									ZydisFormatterFormatInstruction(
										&Formatter, &Instruction, Operands, Instruction.operand_count_visible, ValuesCWI,
										128, PMnemonic->Address, NULL);

									ValuesLen += strlen(ValuesCWI);
									ValuesCWI = (PCH)(UINT64(ValuesCWI) + strlen(ValuesCWI));

									STRCAT(ValuesCWI, "\\l", ValuesLen);
									STRCAT(ValuesCWI, "\\n", ValuesLen);
								}
								SpecificNodeFinLabel(ValuesCWI, ValuesLen);
							}

							AddGraph(ValuesCWI, StartOfGraph->Address, StartOfNextGraph->Address, 16, ValuesLen, LenOut);

							strcat_s((PCH)ValuesCWI, sizeof("\n"), "\n");
							ValuesCWI = (PCH)(uint64_t(ValuesCWI) + strlen(ValuesCWI));
							ValuesLen += strlen("\n");
						}
					}
					LocalCWI += sizeof(Mnemonic);
				}
				STRCAT(ValuesCWI, objGraphVizLanguage.EndOfdigraph, ValuesLen);

				objFile.WriteFile(ValuesBuffer, ValuesLen);

				KdPrint(("Fin\n"));
				ExFreePool(ValuesBuffer);
			}

			CircleOfMnemonics[Arc].clear();
			CycleFolding.clear();
			CircleOfMnemonics[Arc].Reading = false;
		}
		if (Arc == 15) { Arc = 0; }
		else { ++Arc; }
	}
}

bool Trace::TraceInitializeRip()
{
	for (int Arc = 0; Arc < Arcs; ++Arc)
	{
		TraceMessage<uint64_t> objTraceRip;
		CircleOfRips.push_back(objTraceRip);

		CircleOfRips[Arc].Start = (uint64_t*)ExAllocatePool(NonPagedPoolNx, BufferSize);

		if (CircleOfRips[Arc].Start == nullptr) { return false; }
		RtlZeroMemory(CircleOfRips[Arc].Start, BufferSize);

		CircleOfRips[Arc].AllSize = BufferSize;
		CircleOfRips[Arc].CurrentWriteIndex = CircleOfRips[Arc].Start;
		CircleOfRips[Arc].End = CircleOfRips[Arc].Start + BufferSize;
	}

	return true;
}
TraceMessage<AddressTranslateMap> TranslationNumber;
uint64_t nextTranslation = 0;
std::unordered_map<uint64_t, uint64_t>* translationMap = nullptr;

bool Trace::TraceInitializeMnemonic()
{
	for (int Arc = 0; Arc < Arcs; ++Arc)
	{
		TraceMessage<Mnemonic> objTraceMnemonic;
		CircleOfMnemonics.push_back(objTraceMnemonic);

		CircleOfMnemonics[Arc].Start = (Mnemonic*)ExAllocatePool(NonPagedPoolNx, BufferSize);
		if (CircleOfMnemonics[Arc].Start == nullptr) { return false; }
		RtlZeroMemory(CircleOfMnemonics[Arc].Start, BufferSize);

		CircleOfMnemonics[Arc].AllSize = BufferSize;
		CircleOfMnemonics[Arc].CurrentWriteIndex = CircleOfMnemonics[Arc].Start;
		CircleOfMnemonics[Arc].End = CircleOfMnemonics[Arc].Start + BufferSize;
	}

	TranslationNumber.Start = (AddressTranslateMap*)ExAllocatePool(NonPagedPoolNx, MainNodesBytes);
	if (TranslationNumber.Start == nullptr) { return false; }
	RtlZeroMemory(TranslationNumber.Start, MainNodesBytes);

	TranslationNumber.AllSize = MainNodesBytes;
	TranslationNumber.CurrentWriteIndex = TranslationNumber.Start;
	TranslationNumber.End = TranslationNumber.Start + MainNodesBytes;

	Instruction = (ZydisDecodedInstruction*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(ZydisDecodedInstruction), 'ZIsr');
	RtlZeroMemory(Instruction, sizeof(ZydisDecodedInstruction));

	DecoderMinimal = (ZydisDecoder*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(ZydisDecoder), 'DecM');
	RtlZeroMemory(DecoderMinimal, sizeof(ZydisDecoder));
	DecoderMinimal->decoder_mode = ZYDIS_DECODER_MODE_MINIMAL;
	DecoderMinimal->machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
	DecoderMinimal->stack_width = ZYDIS_STACK_WIDTH_64;

	DecoderFull = (ZydisDecoder*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(ZydisDecoder), 'DecF');
	RtlZeroMemory(DecoderFull, sizeof(ZydisDecoder));
	ZydisDecoderInit(DecoderFull, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	Operands = (ZydisDecodedOperand*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(ZydisDecodedOperand) * ZYDIS_MAX_OPERAND_COUNT, 'Oper');
	RtlZeroMemory(Operands, sizeof(ZydisDecodedOperand) * ZYDIS_MAX_OPERAND_COUNT);

	edges = (GraphNode*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(GraphNode) * MAX_NODES), 'EDGS');
	RtlZeroMemory(edges, (sizeof(GraphNode) * MAX_NODES));
	adjList = (uint64_t**)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), 'adLF');
	RtlZeroMemory(adjList, (sizeof(uint64_t) * MAX_NODES));
	adjListT = (uint64_t**)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), 'adLT');
	RtlZeroMemory(adjListT, (sizeof(uint64_t) * MAX_NODES));

	for (uint64_t i = 0; i < MAX_NODES; ++i) {
		adjList[i] = (uint64_t*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), '2DMA');
		RtlZeroMemory(adjList[i], (sizeof(uint64_t) * MAX_NODES));
		adjListT[i] = (uint64_t*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), '2DMT');
		RtlZeroMemory(adjListT[i], (sizeof(uint64_t) * MAX_NODES));
	}

	adjListSize = (uint64_t*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), 'adjF');
	RtlZeroMemory(adjListSize, (sizeof(uint64_t) * MAX_NODES));
	adjListTSize = (uint64_t*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), 'adjT');
	RtlZeroMemory(adjListTSize, (sizeof(uint64_t) * MAX_NODES));

	visited = (int64_t*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(int64_t) * MAX_NODES), 'Vist');
	RtlZeroMemory(visited, (sizeof(int64_t) * MAX_NODES));

	postOrder = (uint64_t*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), 'Post');
	RtlZeroMemory(postOrder, (sizeof(uint64_t) * MAX_NODES));
	component = (uint64_t*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), 'Comp');
	RtlZeroMemory(component, (sizeof(uint64_t) * MAX_NODES));

	MainGraphs = (uint64_t*)ExAllocatePoolWithTag(NonPagedPoolNx, (sizeof(uint64_t) * MAX_NODES), 'Mai>');
	RtlZeroMemory(MainGraphs, (sizeof(uint64_t) * MAX_NODES));

	translationMap = new std::unordered_map<uint64_t, uint64_t>;

	return true;
}

int gArc = 0; bool WasInSysFunc = false;
extern std::vector<ULONG_PTR> AddrsFuncs;

void Trace::TraceRip(_In_ SVM::PRIVATE_VM_DATA* Private)
{
	if (gArc == (Arcs / 2 - 1))
	{
		gArc = 0;
		CircleOfRips[gArc].write_front(CircleOfRips[Arcs / 2 - 1].Start, CircleOfRips[Arcs / 2 - 1].size(sizeof(uint64_t)));
		CircleOfRips[Arcs / 2 - 1].clear();
	}

	if (!CircleOfRips[gArc].Reading)
	{
		size_t remainingSpace = (size_t)(CircleOfRips[gArc].End - CircleOfRips[gArc].CurrentWriteIndex);

		if (sizeof(uint64_t) <= remainingSpace)
		{
			CircleOfRips[gArc].write_front(&Private->Guest.StateSaveArea.Rip, sizeof(uint64_t));
		}
		else
		{
			CircleOfRips[gArc].Reading = true;
			++gArc;
			CircleOfRips[gArc].write_front(&Private->Guest.StateSaveArea.Rip, sizeof(uint64_t));
		}
	}
}

//extern "C" uint64_t PushfqHandler(_In_ uint64_t Rsp, _In_ bool CSLongMode, _In_ uint64_t RflagsValue, _In_ uint32_t VmFlag, _In_ uint32_t RFlag, _In_ uint32_t TFlag);
//extern "C" uint64_t PushfHandler(_In_ uint64_t Rsp, _In_ bool CSLongMode, _In_ uint64_t RflagsValue, _In_ uint32_t VmFlag, _In_ uint32_t RFlag);

INT64 Counter = 0;
INT64 Counter1 = 0;
bool asd = false;
Mnemonic Trace::MnemonicCreator(_In_ uint64_t Rip, _In_ SVM::PRIVATE_VM_DATA* Private)
{
	Mnemonic objMnemonic;
	bool GraphConsequence = false;

	ZydisDecoderDecodeFull(
		DecoderFull,
		(const void*)Rip,
		ZYDIS_MAX_INSTRUCTION_LENGTH,
		Instruction,
		Operands);

	for (uint8_t Operand = 0; Operand < Instruction->operand_count; ++Operand)
	{
		if (Operands[Operand].reg.value == ZYDIS_REGISTER_RIP)
		{
			if (Operands[Operand].actions == ZYDIS_OPERAND_ACTION_READWRITE || Operands[Operand].actions == ZYDIS_OPERAND_ACTION_WRITE)
			{
				if (Instruction->mnemonic != ZYDIS_MNEMONIC_CALL)
				{
					GraphConsequence = true;
				}
				else if (Rip >= ASLRSystemAddr)
				{
					GraphConsequence = true;
				}
			}
		}
	}

	objMnemonic.Address = Private->Guest.StateSaveArea.Rip;
	objMnemonic.Length = Instruction->length;
	objMnemonic.Graph = GraphConsequence;

	/*
	if (Private->Guest.StateSaveArea.Rip == 0x150942198)
	{
		++Counter1;
		KdPrint(("Counter1 is on addr 0x150942198 %p\n", Counter1));
		if (Counter1 == 0x601) { asd = true; }
	}
	if (asd)
	{
		KdPrint(("PUSHF VALUE: %p | RIP: %p\n", Private->Guest.StateSaveArea.Rflags.Value, Private->Guest.StateSaveArea.Rip));
	}
	*/
	if (Private->Guest.StateSaveArea.Rip == 0x15536BF6B)
	{
		++Counter;
		KdPrint(("0x15536BF6B COUNTER: %llu\n", Counter));
		KdPrint(("0x15536BF6B RSP IS: %p\n", Private->Guest.StateSaveArea.Rsp));
		KdPrint(("0x15536BF6B CPL IS: %p\n", Private->Guest.StateSaveArea.Cpl));
	}
	if (Counter >= 9)
	{
		++Counter1;
	}
	/*
	if (Instruction->mnemonic == ZYDIS_MNEMONIC_PUSHFQ || Instruction->mnemonic == ZYDIS_MNEMONIC_PUSHFD)
	{
		//if (Counter == 25) { KdPrint(("PUSHFQ VALUE: %p | RIP: %p\n", Private->Guest.StateSaveArea.Rflags.Value, Private->Guest.StateSaveArea.Rip)); }
		Private->Guest.StateSaveArea.Rsp = PushfqHandler(
			Private->Guest.StateSaveArea.Rsp,
			Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode,
			Private->Guest.StateSaveArea.Rflags.Value,
			Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.VM,
			Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.RF);
		//if (Counter == 25) { KdPrint(("PUSHFQ VALUE IN STACK: %p | RIP: %p\n", *(uint64_t*)Private->Guest.StateSaveArea.Rsp, Private->Guest.StateSaveArea.Rip)); }
		if (!Private->Guest.ControlArea.NextRip) { Private->Guest.StateSaveArea.Rip += Instruction->length; }
		else { Private->Guest.ControlArea.NextRip += Instruction->length; }
		//if (Counter == 25) { Counter = -1; }
		//++Counter;
	}
	else if (Instruction->mnemonic == ZYDIS_MNEMONIC_PUSHF)
	{
		Private->Guest.StateSaveArea.Rsp = PushfHandler(
			Private->Guest.StateSaveArea.Rsp,
			Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode,
			Private->Guest.StateSaveArea.Rflags.Value,
			Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.VM,
			Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.RF);
		if (!Private->Guest.ControlArea.NextRip) { Private->Guest.StateSaveArea.Rip += Instruction->length; }
		else { Private->Guest.ControlArea.NextRip += Instruction->length; }
	}
	*/

	//if()
	RtlCopyMemory(objMnemonic.Opcodes, (const void*)objMnemonic.Address, objMnemonic.Length);
	RtlZeroMemory(Instruction, sizeof(ZydisDecodedInstruction));
	RtlZeroMemory(Operands, sizeof(ZydisDecodedOperand) * ZYDIS_MAX_OPERAND_COUNT);

	return objMnemonic;
}

uint64_t Trace::TranslateNumber(uint64_t number) {
	if (translationMap->count(number) != 0) {
		// Translation already exists, return the mapped number
		return translationMap[0][number];
	}
	else {
		// Generate a new translation and store the mapping
		translationMap[0][number] = nextTranslation;
		return nextTranslation++;
	}
}

void Trace::addEdge(uint64_t** _adjList, uint64_t from, uint64_t to, uint64_t* size) {
	_adjList[from][*size] = to;
	(*size)++;
}

void Trace::dfs1(uint64_t** _adjList, uint64_t numNodes, uint64_t node, int64_t* _visited, uint64_t* _postOrder, uint64_t* index) {
	_visited[node] = 1;
	for (uint64_t i = 0; i < numNodes; ++i) {
		uint64_t neighbor = _adjList[node][i];
		if (!_visited[neighbor]) {
			dfs1(_adjList, numNodes, neighbor, _visited, _postOrder, index);
		}
	}
	_postOrder[*index] = node;
	(*index)++;
}

void Trace::dfs2(uint64_t** _adjListT, uint64_t numNodes, uint64_t node, int64_t* _visited, uint64_t* _component, uint64_t* componentIndex) {
	_visited[node] = 1;
	_component[*componentIndex] = node;
	(*componentIndex)++;
	for (uint64_t i = 0; i < numNodes; ++i) {
		uint64_t neighbor = _adjListT[node][i];
		if (!_visited[neighbor]) {
			dfs2(_adjListT, numNodes, neighbor, _visited, _component, componentIndex);
		}
	}
}

void Trace::KosarajuAlgorithm(uint64_t numNodes, uint64_t numEdges)
{
	for (uint64_t i = 0; i < numEdges; ++i) {
		uint64_t from = edges[i].first;
		uint64_t to = edges[i].second;
		addEdge(adjList, from, to, &adjListSize[from]);
		addEdge(adjListT, to, from, &adjListTSize[to]);
	}

	uint64_t postOrderIndex = 0;

	for (uint64_t i = 0; i < numNodes - 1; ++i) {
		if (!visited[i]) {
			dfs1(adjList, numNodes, i, visited, postOrder, &postOrderIndex);
		}
	}

	for (uint64_t i = 0; i < numNodes; ++i) {
		visited[i] = 0;
	}

	KdPrint(("Strongly Connected Components:\n"));
	for (uint64_t i = numNodes - 1; i > 0; --i) {
		uint64_t node = postOrder[i];
		if (!visited[node]) {
			uint64_t componentIndex = 0;
			dfs2(adjListT, numNodes, node, visited, component, &componentIndex);

			size_t LenOut = 0;

			if (componentIndex >= 2)
			{
				uint64_t HighAddr = GetOriginalTransVal(component[componentIndex - 1]);
				KdPrint(("Algo | High addr: %p\n", HighAddr));
				/*
				ZydisDecoderDecodeFull(
					DecoderFull,
					(const void*)HighAddr,
					ZYDIS_MAX_INSTRUCTION_LENGTH,
					Instruction,
					Operands);

				HighAddr += Instruction->length;

				RtlZeroMemory(Instruction, sizeof(ZydisDecodedInstruction));
				RtlZeroMemory(Operands, sizeof(ZydisDecodedOperand) * ZYDIS_MAX_OPERAND_COUNT);
				unsigned char BP = 0xCC;

				memcpy(&StolenByte, (const void*)HighAddr, 1);
				memcpy((void*)HighAddr, (const void*)&BP, 1);

				KdPrint(("StolenByte: %X\n", StolenByte));
				*/
			}
			//for (uint64_t j = 0; j < componentIndex; ++j) {
			//	//RtlInt64ToCharExsitingArray(component[j], 10, Buff, LenOut);
			//	//STRCATADDR(CWI, component[j], 10, LenOut, ValuesLen);
			//	KdPrint(("component[j]: %lu | SizeOfLine: %u | High addr: %p\n", component[j], componentIndex, GetOriginalTransVal(component[j])));
			//}
			//KdPrint(("%Z\n", Buff));
		}
	}
	KdPrint(("\n"));
}

uint64_t Trace::GetOriginalTransVal(uint64_t Val)
{
	for (const auto& pair : *translationMap) {
		if (pair.second == Val) {
			return pair.first;
		}
	}
	// Output value does not exist, return a default value or handle the error case
	// In this example, we return 0 as the default value
	return 0;
}

bool a = false;
void Trace::InitCycle()
{
	if (CircleOfMnemonics[gArc].size(sizeof(Mnemonic)) > 1 && CircleOfMnemonics[gArc].size(sizeof(Mnemonic)) < MAX_NODES)
	{
		int numEdges = 0;
		for (int MnemGrIndex = 0; MnemGrIndex <= CircleOfMnemonics[gArc].size(sizeof(Mnemonic)); ++MnemGrIndex)
		{
			Mnemonic* LocalCWI = CircleOfMnemonics[gArc].CurrentWriteIndex - (sizeof(Mnemonic) * MnemGrIndex);
			if (LocalCWI->Graph)
			{
				if (numEdges < 2)
				{
					MainGraphs[numEdges] = TranslateNumber(LocalCWI->Address);
					KdPrint(("LocalCWI: %p | MainGraphs: %p\n", LocalCWI->Address, MainGraphs[numEdges]));
					++numEdges;
				}
				else
				{
					MainGraphs[numEdges] = MainGraphs[numEdges - 1];
					++numEdges;
					MainGraphs[numEdges] = TranslateNumber(LocalCWI->Address);
					KdPrint(("LocalCWI: %p | MainGraphs: %p\n", LocalCWI->Address, MainGraphs[numEdges]));
					++numEdges;
				}
			}
		}

		if (/*((numEdges + 1) % 2) == 0 &&*/ (numEdges + 1) >= 4)
		{
			if (!a)
			{
				KdPrint(("SizeEdges: %u\n", numEdges + 1));
				uint64_t numNodes = 0;
				for (uint64_t i = 0; i < numEdges; i += 2) {
					uint64_t from = MainGraphs[i];
					uint64_t to = MainGraphs[i + 1];
					edges[i / 2].first = from;
					edges[i / 2].second = to;
					numNodes++;
				}

				KosarajuAlgorithm(numNodes, numEdges);

				RtlZeroMemory(edges, (sizeof(GraphNode) * MAX_NODES));
				RtlZeroMemory(MainGraphs, (sizeof(uint64_t) * MAX_NODES));
				numEdges = 0;
			}
			a = true;
		}
		KdPrint(("FIN\n"));
	}
	/*
	else if (CircleOfMnemonics[gArc].size(sizeof(Mnemonic)) > 50)
	{
		for (int MnemGrIndex = 0; MnemGrIndex < 50; ++MnemGrIndex)
		{

		}
	}
	*/
	translationMap->clear();
}

void Trace::CircleOfMnemonicsFiller(_In_ uint64_t Rip, _In_ SVM::PRIVATE_VM_DATA* Private)
{
	if (!CircleOfMnemonics[gArc].Reading)
	{
		size_t remainingSpace = (size_t)(CircleOfMnemonics[gArc].End - CircleOfMnemonics[gArc].CurrentWriteIndex);
		size_t remainingSize = remainingSpace / sizeof(Mnemonic);
		remainingSize = remainingSize;

		if (CircleOfMnemonics[gArc].size(sizeof(Mnemonic)) < remainingSize)
		{
			Mnemonic objMnemonic = MnemonicCreator(Rip, Private);
			CircleOfMnemonics[gArc].write_front((const void*)&objMnemonic, sizeof(Mnemonic));
			//if (objMnemonic.Graph) 
			//{ 
			//	InitCycle();
				//TranslationNumber.clear(); 
				//nextTranslation = 0;
			//}
		}
		else
		{
			CircleOfMnemonics[gArc].Reading = true;
			if (gArc != 15)
			{
				++gArc;
				Mnemonic objMnemonic = MnemonicCreator(Rip, Private);
				CircleOfMnemonics[gArc].write_front((const void*)&objMnemonic, sizeof(Mnemonic));
				//if (objMnemonic.Graph) 
				//{ 
				//	InitCycle();
					//TranslationNumber.clear(); 
					//nextTranslation = 0;
				//}
			}
			else
			{
				gArc = 0;
				Mnemonic objMnemonic = MnemonicCreator(Rip, Private);
				CircleOfMnemonics[gArc].write_front((const void*)&objMnemonic, sizeof(Mnemonic));
				//if (objMnemonic.Graph) 
				//{ 
				//	InitCycle();
					//TranslationNumber.clear(); 
					//nextTranslation = 0;
				//}
			}
		}
	}
}

void Trace::TraceMnemonic(_In_ SVM::PRIVATE_VM_DATA* Private)
{
	if (Private->Guest.StateSaveArea.Rip < ASLRSystemAddr)
	{
		WasInSysFunc = false;

		CircleOfMnemonicsFiller(Private->Guest.StateSaveArea.Rip, Private);
	}
	else
	{
		if (!WasInSysFunc)
		{
			WasInSysFunc = true;
			for (ULONG_PTR Addr = 0; Addr < AddrsFuncs.size(); ++Addr)
			{
				if (AddrsFuncs[Addr] == Private->Guest.StateSaveArea.Rip)
				{
					KdPrint(("Rip %p\n", Private->Guest.StateSaveArea.Rip));
					CircleOfMnemonicsFiller(Private->Guest.StateSaveArea.Rip, Private);
				}
			}
		}
	}
}

void Trace::TraceRipFinalization() { for (auto& Arc : CircleOfRips) { if (Arc.DataWritten > 0) { Arc.Reading = true; } } }

void Trace::TraceMnemonicFinalization() { for (auto& Arc : CircleOfMnemonics) { if (Arc.DataWritten > 0) { Arc.Reading = true; } } EoF = true; }