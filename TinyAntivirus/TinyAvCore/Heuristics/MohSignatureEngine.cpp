#include "../../include/Heuristics/MohSignatureEngine.h"
#include "../../include/FileSystem/FsStream.h"
#include <vector>
#include <algorithm>
#include <map>
#include <queue>
#include <string>

struct TrieNode
{
	std::map<unsigned char, int> children;
	int failureLink;
	std::vector<int> output; // Indices of matched signature names

	TrieNode() : failureLink(0) {}
};

class CMosSignatureEngine :
	public CRefCount,
	public IMosSignatureEngine
{
private:
	std::vector<TrieNode> m_trie;
	std::vector<std::wstring> m_signatureNames;
	bool m_isDirty;

	void AddPattern(const unsigned char* pattern, size_t length, const std::wstring& name)
	{
		int current = 0;
		for (size_t i = 0; i < length; ++i)
		{
			unsigned char c = pattern[i];
			if (m_trie[current].children.find(c) == m_trie[current].children.end())
			{
				m_trie[current].children[c] = (int)m_trie.size();
				m_trie.emplace_back();
			}
			current = m_trie[current].children[c];
		}
		m_signatureNames.push_back(name);
		m_trie[current].output.push_back((int)m_signatureNames.size() - 1);
		m_isDirty = true;
	}

	void BuildFailureLinks()
	{
		if (!m_isDirty) return;

		std::queue<int> q;
		for (auto const& [c, child] : m_trie[0].children)
		{
			m_trie[child].failureLink = 0;
			q.push(child);
		}

		while (!q.empty())
		{
			int u = q.front();
			q.pop();

			for (auto const& [c, v] : m_trie[u].children)
			{
				int f = m_trie[u].failureLink;
				while (f > 0 && m_trie[f].children.find(c) == m_trie[f].children.end())
					f = m_trie[f].failureLink;

				if (m_trie[f].children.find(c) != m_trie[f].children.end())
					m_trie[v].failureLink = m_trie[f].children[c];
				else
					m_trie[v].failureLink = 0;

				// Merge output from failure link
				int linkOutput = m_trie[v].failureLink;
				m_trie[v].output.insert(m_trie[v].output.end(), 
					m_trie[linkOutput].output.begin(), m_trie[linkOutput].output.end());

				q.push(v);
			}
		}
		m_isDirty = false;
	}

public:
	CMosSignatureEngine() : m_isDirty(true)
	{
		m_trie.emplace_back(); // Root
	}

	virtual ~CMosSignatureEngine() {}

	DECLARE_REF_COUNT();

	virtual HRESULT WINAPI QueryInterface(__in REFIID riid, __out void **ppvObject) override
	{
		if (ppvObject == NULL) return E_INVALIDARG;

		if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, __uuidof(IMosSignatureEngine)))
		{
			*ppvObject = static_cast<IMosSignatureEngine*>(this);
			AddRef();
			return S_OK;
		}

		*ppvObject = NULL;
		return E_NOINTERFACE;
	}

	virtual HRESULT WINAPI LoadSignatures(__in_bcount(size) const void* buffer, __in size_t size) override
	{
		if (buffer == NULL || size == 0) return E_INVALIDARG;
		
		const unsigned char* data = static_cast<const unsigned char*>(buffer);
		
		// Heuristic: extract patterns from the database blob
		// For MOS, we look for unique byte sequences that represent malicious logic.
		// We extract 32-byte chunks as signatures.
		
		const size_t kSigLen = 32;
		size_t count = 0;
		for (size_t i = 0; i + kSigLen <= size; i += 64) // Subsample for performance and diversity
		{
			// Filter out low-entropy patterns
			bool lowEntropy = true;
			unsigned char first = data[i];
			for (size_t j = 1; j < kSigLen; ++j)
			{
				if (data[i + j] != first)
				{
					lowEntropy = false;
					break;
				}
			}
			
			if (!lowEntropy)
			{
				wchar_t name[64];
				swprintf_s(name, L"Win32.Moh.Sig.%zx", (size_t)i);
				AddPattern(&data[i], kSigLen, name);
				count++;
			}
		}

		return count > 0 ? S_OK : S_FALSE;
	}

	virtual HRESULT WINAPI Reset() override
	{
		m_trie.clear();
		m_trie.emplace_back();
		m_signatureNames.clear();
		m_isDirty = true;
		return S_OK;
	}

	virtual HRESULT WINAPI Match(__in IVirtualFs* file, __out_bcount(maxName) WCHAR* malwareName, __in size_t maxName) override
	{
		if (file == NULL || malwareName == NULL) return E_INVALIDARG;
		if (m_signatureNames.empty()) return S_FALSE;

		if (m_isDirty) BuildFailureLinks();

		IFsStream* pStream = NULL;
		HRESULT hr = file->QueryInterface(__uuidof(IFsStream), (void**)&pStream);
		if (FAILED(hr)) return hr;

		unsigned char buffer[8192];
		ULONG bytesRead = 0;
		LARGE_INTEGER offset = {0};
		
		hr = pStream->ReadAt(offset, IFsStream::FsStreamBegin, buffer, sizeof(buffer), &bytesRead);
		if (SUCCEEDED(hr) && bytesRead > 0)
		{
			int current = 0;
			for (ULONG i = 0; i < bytesRead; ++i)
			{
				unsigned char c = buffer[i];
				while (current > 0 && m_trie[current].children.find(c) == m_trie[current].children.end())
					current = m_trie[current].failureLink;

				if (m_trie[current].children.find(c) != m_trie[current].children.end())
					current = m_trie[current].children[c];

				if (!m_trie[current].output.empty())
				{
					// Match found!
					int sigIdx = m_trie[current].output[0];
					wcscpy_s(malwareName, maxName, m_signatureNames[sigIdx].c_str());
					pStream->Release();
					return S_OK;
				}
			}
		}

		pStream->Release();
		return S_FALSE;
	}
};

extern "C" HRESULT CreateMosSignatureEngineImpl(IMosSignatureEngine** ppEngine)
{

	if (ppEngine == NULL) return E_INVALIDARG;
	*ppEngine = new CMosSignatureEngine();
	if (*ppEngine == NULL) return E_OUTOFMEMORY;
	(*ppEngine)->AddRef();
	return S_OK;
}

