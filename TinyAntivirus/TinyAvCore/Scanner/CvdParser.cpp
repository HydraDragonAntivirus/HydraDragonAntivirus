#include "CvdParser.h"
#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace
{
	static const ULONG kIndexedBinaryMagic = 0xDEC001C0;
	static const ULONG kIndexedBinaryMinimumHeader = 64;

	bool IsPrintableDatabaseNameChar(unsigned char value)
	{
		return std::isalnum(value) != 0 ||
			value == ' ' ||
			value == '.' ||
			value == '_' ||
			value == '-' ||
			value == '(' ||
			value == ')';
	}

	std::string TrimAsciiSpaces(const std::string& value)
	{
		const size_t first = value.find_first_not_of(' ');
		if (first == std::string::npos)
			return std::string();

		const size_t last = value.find_last_not_of(' ');
		return value.substr(first, last - first + 1);
	}

	bool EndsWithIgnoreCase(const std::string& value, const char* suffix)
	{
		const size_t suffixLength = strlen(suffix);
		if (value.length() < suffixLength)
			return false;

		for (size_t i = 0; i < suffixLength; ++i)
		{
			const unsigned char left = static_cast<unsigned char>(value[value.length() - suffixLength + i]);
			const unsigned char right = static_cast<unsigned char>(suffix[i]);
			if (std::tolower(left) != std::tolower(right))
				return false;
		}

		return true;
	}

	std::string StripKnownSignatureExtension(std::string value)
	{
		static const char* kKnownExtensions[] =
		{
			".cvd",
			".ivd",
			".rvd",
		};

		for (size_t i = 0; i < _countof(kKnownExtensions); ++i)
		{
			if (EndsWithIgnoreCase(value, kKnownExtensions[i]))
			{
				value.erase(value.length() - strlen(kKnownExtensions[i]));
				break;
			}
		}

		return value;
	}

	std::string SanitizeCvdHeaderName(const unsigned char* buffer, size_t length)
	{
		if (buffer == NULL || length == 0)
			return std::string();

		std::string value;
		value.reserve(length);

		for (size_t i = 0; i < length; ++i)
		{
			const unsigned char current = buffer[i];
			if (current == '\0' || current == '\r' || current == '\n')
				break;

			if (!IsPrintableDatabaseNameChar(current))
				break;

			value.push_back(static_cast<char>(current));
		}

		return StripKnownSignatureExtension(TrimAsciiSpaces(value));
	}
}

CCvdParser::CCvdParser()
	: m_databaseType(SignatureDatabaseUnknown)
{
}

CCvdParser::~CCvdParser()
{
}

void CCvdParser::Reset()
{
	m_data.clear();
	m_headerName.clear();
	m_databaseType = SignatureDatabaseUnknown;
	m_databases.clear();
}

bool CCvdParser::Load(const std::wstring& path)
{
	Reset();
	return LoadInternal(path, false);
}

bool CCvdParser::Append(const std::wstring& path)
{
	return LoadInternal(path, true);
}

bool CCvdParser::LoadInternal(const std::wstring& path, bool append)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file.is_open())
		return false;

	std::streamsize size = file.tellg();
	if (size <= 0)
		return false;

	file.seekg(0, std::ios::beg);

	std::vector<unsigned char> rawData(static_cast<size_t>(size));
	if (!file.read(reinterpret_cast<char*>(rawData.data()), size))
		return false;

	std::vector<unsigned char> previousData = m_data;
	std::string previousHeaderName = m_headerName;
	SignatureDatabaseType previousDatabaseType = m_databaseType;

	m_data.swap(rawData);
	m_headerName.clear();
	m_databaseType = SignatureDatabaseUnknown;

	SIGNATURE_DATABASE_INFO databaseInfo = {};
	if (!ParseDatabase(path, &databaseInfo))
	{
		m_data.swap(previousData);
		m_headerName = previousHeaderName;
		m_databaseType = previousDatabaseType;
		return false;
	}

	m_headerName = databaseInfo.name;
	m_databaseType = databaseInfo.type;
	m_databases.push_back(databaseInfo);

	if (!append)
	{
		std::vector<SIGNATURE_DATABASE_INFO> latestOnly;
		latestOnly.push_back(databaseInfo);
		m_databases.swap(latestOnly);
	}

	return true;
}

void CCvdParser::Decode()
{
	if (m_data.empty())
		return;

	unsigned char i = 0xAA;
	for (int idx = static_cast<int>(m_data.size()) - 1; idx >= 0; --idx)
	{
		unsigned char decoded = i ^ m_data[static_cast<size_t>(idx)];
		i = m_data[static_cast<size_t>(idx)];
		m_data[static_cast<size_t>(idx)] = decoded;
	}
}

bool CCvdParser::ParseDatabase(const std::wstring& path, SIGNATURE_DATABASE_INFO *databaseInfo)
{
	if (databaseInfo == NULL || m_data.empty())
		return false;

	databaseInfo->sourcePath = path;
	databaseInfo->name = NarrowFileStem(path);

	LPCWSTR extension = PathFindExtensionW(path.c_str());
	if (extension != NULL && _wcsicmp(extension, L".cvd") == 0)
	{
		const std::vector<unsigned char> originalData = m_data;
		if (ParseCvdDatabase(databaseInfo))
			return true;
		m_data = originalData;
	}

	if (ParseIndexedBinaryDatabase(path, databaseInfo))
		return true;

	if (ParseAvxsDatabase(path, databaseInfo))
		return true;

	if (ParsePlaceholderDatabase(path, databaseInfo))
		return true;

	return false;
}

bool CCvdParser::ParseCvdDatabase(SIGNATURE_DATABASE_INFO *databaseInfo)
{
	if (databaseInfo == NULL || m_data.size() < 16)
		return false;

	Decode();

	const char* magic = "\r\nXMDbegin";
	if (memcmp(m_data.data(), magic, 10) != 0)
		return false;

	databaseInfo->type = SignatureDatabaseCvd;
	databaseInfo->version = 1;
	databaseInfo->headerSize = (m_data.size() >= 64) ? 64 : static_cast<ULONG>(m_data.size());
	databaseInfo->payloadOffset = 10;
	databaseInfo->payloadSize = static_cast<ULONG>(m_data.size() - databaseInfo->payloadOffset);

	if (m_data.size() >= 64)
	{
		m_headerName = SanitizeCvdHeaderName(m_data.data() + 10, 32);
		if (m_headerName.empty())
			m_headerName = NarrowFileStem(databaseInfo->sourcePath);
		databaseInfo->name = m_headerName;
	}

	return true;
}

bool CCvdParser::ParseIndexedBinaryDatabase(const std::wstring& path, SIGNATURE_DATABASE_INFO *databaseInfo)
{
	UNREFERENCED_PARAMETER(path);

	if (databaseInfo == NULL || m_data.size() < kIndexedBinaryMinimumHeader)
		return false;

	if (ReadUInt32(m_data, 0) != kIndexedBinaryMagic)
		return false;

	const ULONG version = ReadUInt32(m_data, 32);
	const ULONG blockSize = ReadUInt32(m_data, 36);
	const ULONG headerSize = ReadUInt32(m_data, 40);
	const ULONG storedFileSize = ReadUInt32(m_data, 56);

	if (version == 0 || version > 32)
		return false;

	if (blockSize == 0)
		return false;

	if (storedFileSize != static_cast<ULONG>(m_data.size()))
		return false;

	databaseInfo->type = SignatureDatabaseIndexedBinary;
	databaseInfo->version = version;
	databaseInfo->headerSize = (headerSize > 0 && headerSize <= m_data.size()) ? headerSize : kIndexedBinaryMinimumHeader;
	databaseInfo->payloadOffset = kIndexedBinaryMinimumHeader;
	databaseInfo->payloadSize = static_cast<ULONG>(m_data.size() - databaseInfo->payloadOffset);
	return true;
}

bool CCvdParser::ParseAvxsDatabase(const std::wstring& path, SIGNATURE_DATABASE_INFO *databaseInfo)
{
	UNREFERENCED_PARAMETER(path);

	if (databaseInfo == NULL || m_data.size() < 16)
		return false;

	if (memcmp(m_data.data(), "AVXS", 4) != 0)
		return false;

	const ULONG version = ReadUInt32(m_data, 4);
	const ULONG headerSize = ReadUInt32(m_data, 8);
	const ULONG payloadCount = ReadUInt32(m_data, 12);

	if (headerSize == 0 || headerSize >= m_data.size())
		return false;

	bool hasCompressedStream = false;
	for (size_t i = headerSize; i + 1 < m_data.size(); ++i)
	{
		if (m_data[i] == 0x78 && (m_data[i + 1] == 0xDA || m_data[i + 1] == 0x9C || m_data[i + 1] == 0x01))
		{
			hasCompressedStream = true;
			break;
		}
	}

	if (!hasCompressedStream)
		return false;

	databaseInfo->type = SignatureDatabaseAvxs;
	databaseInfo->version = version;
	databaseInfo->headerSize = headerSize;
	databaseInfo->payloadOffset = headerSize;
	databaseInfo->payloadSize = static_cast<ULONG>(m_data.size() - headerSize);
	if (payloadCount > 0)
		databaseInfo->version = (version << 16) | (payloadCount & 0xFFFF);
	return true;
}

bool CCvdParser::ParsePlaceholderDatabase(const std::wstring& path, SIGNATURE_DATABASE_INFO *databaseInfo)
{
	UNREFERENCED_PARAMETER(path);

	if (databaseInfo == NULL || m_data.size() < 4)
		return false;

	if (memcmp(m_data.data(), "UNPD", 4) == 0)
	{
		const ULONG declaredSize = (m_data.size() >= 12) ? ReadUInt32(m_data, 8) : static_cast<ULONG>(m_data.size());
		if (declaredSize != static_cast<ULONG>(m_data.size()))
			return false;

		databaseInfo->type = SignatureDatabasePlaceholder;
		databaseInfo->version = (m_data.size() >= 8) ? ReadUInt32(m_data, 4) : 0;
		databaseInfo->headerSize = static_cast<ULONG>(m_data.size());
		databaseInfo->payloadOffset = static_cast<ULONG>(m_data.size());
		databaseInfo->payloadSize = 0;
		return true;
	}

	if (memcmp(m_data.data(), "VESG", 4) == 0)
	{
		databaseInfo->type = SignatureDatabasePlaceholder;
		databaseInfo->version = 0;
		databaseInfo->headerSize = static_cast<ULONG>(m_data.size());
		databaseInfo->payloadOffset = static_cast<ULONG>(m_data.size());
		databaseInfo->payloadSize = 0;
		return true;
	}

	return false;
}

ULONG CCvdParser::ReadUInt32(const std::vector<unsigned char>& buffer, size_t offset)
{
	if (offset + sizeof(ULONG) > buffer.size())
		return 0;

	ULONG value = 0;
	memcpy(&value, buffer.data() + offset, sizeof(value));
	return value;
}

std::string CCvdParser::NarrowFileStem(const std::wstring& path)
{
	WCHAR fileName[_MAX_FNAME] = {};
	_wsplitpath_s(path.c_str(), NULL, 0, NULL, 0, fileName, _countof(fileName), NULL, 0);

	int required = WideCharToMultiByte(CP_UTF8, 0, fileName, -1, NULL, 0, NULL, NULL);
	if (required <= 1)
		return std::string();

	std::vector<char> narrowBuffer(static_cast<size_t>(required), '\0');
	WideCharToMultiByte(CP_UTF8, 0, fileName, -1, narrowBuffer.data(), required, NULL, NULL);
	std::string narrow(narrowBuffer.data());
	return narrow;
}
