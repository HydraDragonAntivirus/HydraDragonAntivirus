//
// edrav2.libcloud project
// 
// Author: Yury Ermakov (19.03.2019)
// Reviewer: Denis Bogdanov (25.03.2019)
//
///
/// @file File Lookup Service (FLS) objects implementation
///
#include "pch.h"
#include <net.hpp>
#include "flsproto4.h"

// Set component for logging
#undef CMD_COMPONENT
#define CMD_COMPONENT "fls4"

namespace cmd {
namespace cloud {
namespace fls {
namespace v4 {


//
//
//
UdpClient::UdpClient(std::string_view sHost, Size nPort) :
	Client(sHost, nPort)
{
}

//
//
//
Size UdpClient::getNextId()
{
	std::scoped_lock lock(m_mtxId);
	return m_nId++;
}

//
//
//
FileVerdictMap UdpClient::getVerdict(RequestType eRequestType, const HashList& hashList, Size nResponseAnswerSize)
{
	using boost::asio::ip::udp;
	using boost::asio::ip::address;
	
	if (hashList.size() > c_nMaxHashPerRequest)
		error::InvalidArgument(SL, "Too many hashes").throwException();

	boost::array<uint8_t, c_nPacketMaxSize> packet;
	auto pRequest = (Request*)packet.c_array();
	pRequest->requestType = eRequestType;
	pRequest->nId = static_cast<uint32_t>(getNextId());
	pRequest->nNumOfHashes = static_cast<uint8_t>(hashList.size());
	pRequest->hashType = HashType::SHA1;
	pRequest->nProtocol = 3;
	pRequest->applicationId = ApplicationId::CloudAntivirus;
	memset(pRequest->guid, 0, sizeof(pRequest->guid));
	pRequest->callerType = CallerType::FromOnAccess;

	uint8_t* pHash = &pRequest->hashes;
	for (auto& sHash : hashList)
	{
		if (sHash.size() != c_nHashSize * 2)
			error::InvalidArgument(SL, FMT("Invalid hash size. Hash <" << sHash << ">" )).throwException();
		std::string sPlainHash;
		try
		{
			sPlainHash = boost::algorithm::unhex(sHash);
		}
		catch (const std::exception& ex)
		{
			error::InvalidArgument(SL, FMT("Invalid hash (" << ex.what() << ")")).throwException();
		}
		memcpy(pHash, sPlainHash.c_str(), sPlainHash.size());
		pHash += c_nHashSize;
	}	
	Size nPacketSize = sizeof(Request) - 1 + hashList.size() * c_nHashSize;

	// Retrieve host address: resolved once (it was a DNS lookup per request)
	// and again after a request that got no answer.
	boost::system::error_code ec;
	auto addr = address::from_string(m_sHost, ec);
	if (ec)
	{
		std::string sAddr;
		{
			std::scoped_lock lock(m_mtxAddr);
			sAddr = m_sResolvedAddr;
		}
		if (sAddr.empty())
		{
			// FIXME: Why do you use only first resolved address?
			sAddr = *net::getHostByName(m_sHost).begin();
			std::scoped_lock lock(m_mtxAddr);
			m_sResolvedAddr = sAddr;
		}
		addr = address::from_string(sAddr);
	}

	udp::endpoint remoteReceiver(addr, static_cast<unsigned short>(m_nPort));

	boost::asio::io_context ioContext;
	udp::socket socket(ioContext);
	socket.open(udp::v4());

	// A lost UDP packet is resent, like tools/fls_lookup.py does. One send
	// with a single 2 s wait made every lost packet an error, and an error
	// marks the whole server unavailable (no queries for a while), so FLS
	// "went down" every time one datagram was dropped. The attempts together
	// take about the old single wait.
	static constexpr Size nSendTimeoutMs = 2000;
	static constexpr Size nAttempts = 3;
	static constexpr Size nAttemptTimeoutMs = 700;
	net::setSoketTimeout(socket, nSendTimeoutMs, nAttemptTimeoutMs);

	boost::array<uint8_t, c_nPacketMaxSize> response;
	Size nBytesReceived = 0;
	bool fAnswered = false;
	for (Size nAttempt = 0; nAttempt < nAttempts && !fAnswered; ++nAttempt)
	{
		auto nBytesSent = socket.send_to(boost::asio::buffer(packet, nPacketSize), remoteReceiver, 0);
		if (nBytesSent != nPacketSize)
			error::RuntimeError(SL, "Not all data was sent").throwException();

		const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(nAttemptTimeoutMs);
		while (std::chrono::steady_clock::now() < deadline)
		{
			udp::endpoint remoteSender;
			boost::system::error_code ecRecv;
			nBytesReceived = socket.receive_from(boost::asio::buffer(response), remoteSender, 0, ecRecv);
			if (ecRecv)
				break; // receive timeout: send again
			if (nBytesReceived < sizeof(Response))
				continue;
			// A late answer to an earlier send of this packet or to an
			// earlier request carries another id: keep waiting.
			if (((Response*)response.c_array())->nId != pRequest->nId)
				continue;
			fAnswered = true;
			break;
		}
	}
	if (!fAnswered)
	{
		std::scoped_lock lock(m_mtxAddr);
		m_sResolvedAddr.clear();
		error::ConnectionError(SL, FMT("No FLS answer after " << nAttempts << " attempts")).throwException();
	}

	auto pResponse = (Response*)response.c_array();
	if (pResponse->nNumOfAnswers != pRequest->nNumOfHashes)
		error::InvalidFormat(SL, "Number of answers doesn't match requested").throwException();
	if (nBytesReceived < sizeof(Response) - 1 + pResponse->nNumOfAnswers * nResponseAnswerSize)
		error::InvalidFormat(SL, "Not enough data received").throwException();

	FileVerdictMap verdicts;
	uint8_t* pVerdict = &pResponse->answers;
	for (Size i = 0; i < pResponse->nNumOfAnswers; ++i)
	{
		verdicts.insert({ hashList[i], static_cast<FileVerdict>(*pVerdict) });
		pVerdict += nResponseAnswerSize;
	}

	// FIXME: Do we need to use RAII for socket here?
	// FIXME: Do we need close socket after each request?
	socket.close();

	return verdicts;
}

//
//
//
FileVerdictMap UdpClient::getFileVerdict(const HashList& hashList)
{
	TRACE_BEGIN;
	return getVerdict(RequestType::SimpleRequest, hashList, 2);
	TRACE_END("Error during file verdict request");
}

//
//
//
FileVerdictMap UdpClient::getVendorVerdict(const HashList& hashList)
{
	TRACE_BEGIN;
	return getVerdict(RequestType::TrustedVendorLookup, hashList, 1);
	TRACE_END("Error during vendor verdict request");
}

} // namespace v4
} // namespace fls
} // namespace cloud
} // namespace cmd
