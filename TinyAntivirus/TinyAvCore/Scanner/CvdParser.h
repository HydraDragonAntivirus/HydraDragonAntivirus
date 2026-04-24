#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "../../include/Scanner/SignatureDatabase.h"

typedef struct SIGNATURE_DATABASE_INFO
{
	SignatureDatabaseType type;
	std::wstring sourcePath;
	std::string name;
	ULONG version;
	ULONG headerSize;
	ULONG payloadOffset;
	ULONG payloadSize;
} SIGNATURE_DATABASE_INFO, *LPSIGNATURE_DATABASE_INFO;

class CCvdParser
{
public:
	CCvdParser();
	~CCvdParser();

	void Reset();
	bool Load(const std::wstring& path);
	bool Append(const std::wstring& path);
	bool IsLoaded() const { return !m_databases.empty(); }
	
	const std::vector<unsigned char>& GetData() const { return m_data; }
	const std::string& GetHeaderName() const { return m_headerName; }
	SignatureDatabaseType GetDatabaseType() const { return m_databaseType; }
	const std::vector<SIGNATURE_DATABASE_INFO>& GetDatabases() const { return m_databases; }

private:
	bool LoadInternal(const std::wstring& path, bool append);
	void Decode();
	bool ParseDatabase(const std::wstring& path, SIGNATURE_DATABASE_INFO *databaseInfo);
	bool ParseCvdDatabase(SIGNATURE_DATABASE_INFO *databaseInfo);
	bool ParseIndexedBinaryDatabase(const std::wstring& path, SIGNATURE_DATABASE_INFO *databaseInfo);
	bool ParseAvxsDatabase(const std::wstring& path, SIGNATURE_DATABASE_INFO *databaseInfo);
	bool ParsePlaceholderDatabase(const std::wstring& path, SIGNATURE_DATABASE_INFO *databaseInfo);
	static ULONG ReadUInt32(const std::vector<unsigned char>& buffer, size_t offset);
	static std::string NarrowFileStem(const std::wstring& path);

	std::vector<unsigned char> m_data;
	std::string m_headerName;
	SignatureDatabaseType m_databaseType;
	std::vector<SIGNATURE_DATABASE_INFO> m_databases;
};
