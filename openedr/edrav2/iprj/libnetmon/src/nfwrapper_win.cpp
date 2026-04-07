//
// edrav2.libnetmon
//
// Author: Podpruzhnikov Yury (15.10.2019)
// Reviewer:
//
///
/// @file HydraDragonFirewall named-pipe network telemetry source
///
#include "pch_win.h"
#include "nfwrapper_win.h"

#include <chrono>
#include <cstring>

#undef CMD_COMPONENT
#define CMD_COMPONENT "netmon"

namespace cmd {
namespace netmon {
namespace win {

namespace {

AddressFamily detectAddressFamily(const std::string& sIp)
{
	return sIp.find(':') == std::string::npos ? AddressFamily::Inet : AddressFamily::Inet6;
}

IpProtocol convertProtocol(const Variant& vProtocol)
{
	if (!vProtocol.isString())
		return IpProtocol::Unknown;

	const auto sProtocol = std::string(vProtocol);
	if (boost::algorithm::iequals(sProtocol, "TCP"))
		return IpProtocol::Tcp;
	if (boost::algorithm::iequals(sProtocol, "UDP"))
		return IpProtocol::Udp;

	return IpProtocol::Unknown;
}

std::shared_ptr<ConnectionInfo> createConnectionInfo(
	uint64_t nInternalId,
	uint32_t nPid,
	IpProtocol eProtocol,
	Direction eDirection,
	const std::string& sLocalIp,
	uint16_t nLocalPort,
	const std::string& sRemoteIp,
	uint16_t nRemotePort)
{
	auto pInfo = std::make_shared<ConnectionInfo>();
	pInfo->eIpProtocol = eProtocol;
	pInfo->eDirection = eDirection;
	pInfo->eFamily = detectAddressFamily(sRemoteIp.empty() ? sLocalIp : sRemoteIp);
	pInfo->nPid = nPid;
	pInfo->nInternalId = nInternalId;
	pInfo->nTickTime = getTickCount();
	pInfo->local = { sLocalIp, nLocalPort };
	pInfo->remote = { sRemoteIp, nRemotePort };
	pInfo->sDisplayName = getDisplayString(*pInfo);
	pInfo->vConnection = convertConnectionInfo(*pInfo, ConnectionStatus::Success);
	return pInfo;
}

} // namespace

NetFilterWrapper::NetFilterWrapper()
{
}

NetFilterWrapper::~NetFilterWrapper()
{
	stop();
}

void NetFilterWrapper::finalConstruct(Variant vConfig)
{
	CHECK_IN_SOURCE_LOCATION();
	m_pNetMonController = queryInterface<INetworkMonitorController>(vConfig.get("controller"));
	m_sPipeName = vConfig.get("pipeName", std::wstring(c_sDefaultPipeName));
}

void NetFilterWrapper::wakeListener() const
{
	auto hPipe = ::CreateFileW(
		m_sPipeName.c_str(),
		GENERIC_WRITE,
		0,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr);
	if (hPipe != INVALID_HANDLE_VALUE)
		::CloseHandle(hPipe);
}

void NetFilterWrapper::dispatchConnection(std::shared_ptr<ConnectionInfo> pInfo)
{
	if (!m_pNetMonController || !pInfo)
		return;

	m_pNetMonController->notifyNewConnectionInfo(pInfo);
}

void NetFilterWrapper::processNetEventLine(const std::string& sPayload)
{
	const auto nFirstSep = sPayload.find(':');
	const auto nLastSep = sPayload.rfind(':');
	if (nFirstSep == std::string::npos || nLastSep == std::string::npos || nFirstSep == nLastSep)
	{
		LOGWRN("Invalid HydraNetEvent NET_EVENT payload <" << sPayload << ">");
		return;
	}

	try
	{
		const auto nPid = static_cast<uint32_t>(std::stoul(sPayload.substr(0, nFirstSep)));
		const auto sRemoteIp = sPayload.substr(nFirstSep + 1, nLastSep - nFirstSep - 1);
		const auto nRemotePort = static_cast<uint16_t>(std::stoul(sPayload.substr(nLastSep + 1)));
		const auto sLocalIp = detectAddressFamily(sRemoteIp) == AddressFamily::Inet6 ? "::" : "0.0.0.0";

		auto pInfo = createConnectionInfo(
			m_nConnectionId.fetch_add(1),
			nPid,
			IpProtocol::Unknown,
			Direction::Out,
			sLocalIp,
			0,
			sRemoteIp,
			nRemotePort);
		dispatchConnection(pInfo);
	}
	catch (const std::exception& ex)
	{
		LOGWRN("Failed to parse HydraNetEvent NET_EVENT payload <" << sPayload << ">: " << ex.what());
	}
}

void NetFilterWrapper::processFullPacketLine(const std::string& sPayload)
{
	try
	{
		const auto vPacket = variant::deserializeFromJson(sPayload);
		if (!vPacket.isDictionaryLike())
			return;

		const bool fOutbound = vPacket.get("outbound", true);
		const auto nPid = static_cast<uint32_t>(vPacket.get("process_id", 0));
		const auto eProtocol = convertProtocol(vPacket.get("protocol", Variant()));
		const auto sSrcIp = std::string(vPacket.get("src_ip", ""));
		const auto sDstIp = std::string(vPacket.get("dst_ip", ""));
		const auto nSrcPort = static_cast<uint16_t>(vPacket.get("src_port", 0));
		const auto nDstPort = static_cast<uint16_t>(vPacket.get("dst_port", 0));

		auto pInfo = createConnectionInfo(
			m_nConnectionId.fetch_add(1),
			nPid,
			eProtocol,
			fOutbound ? Direction::Out : Direction::In,
			fOutbound ? sSrcIp : sDstIp,
			fOutbound ? nSrcPort : nDstPort,
			fOutbound ? sDstIp : sSrcIp,
			fOutbound ? nDstPort : nSrcPort);
		dispatchConnection(pInfo);
	}
	catch (error::Exception& ex)
	{
		ex.log(SL, "Failed to parse FULL_PACKET telemetry from HydraDragonFirewall");
	}
	catch (const std::exception& ex)
	{
		LOGWRN("Failed to parse FULL_PACKET telemetry from HydraDragonFirewall: " << ex.what());
	}
}

void NetFilterWrapper::processLine(const std::string& sLine)
{
	if (boost::algorithm::starts_with(sLine, "NET_EVENT:"))
	{
		processNetEventLine(sLine.substr(std::strlen("NET_EVENT:")));
		return;
	}

	if (boost::algorithm::starts_with(sLine, "FULL_PACKET:"))
	{
		processFullPacketLine(sLine.substr(std::strlen("FULL_PACKET:")));
		return;
	}

	if (boost::algorithm::starts_with(sLine, "BLOCK_EXE:"))
		return;

	LOGLVL(Detailed, "Ignoring unsupported HydraNetEvent message <" << sLine << ">");
}

void NetFilterWrapper::listenLoop()
{
	while (!m_fStopRequested)
	{
		auto hPipe = ::CreateNamedPipeW(
			m_sPipeName.c_str(),
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			0,
			static_cast<DWORD>(c_nReadBufferSize),
			0,
			nullptr);

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			LOGWRN("Failed to create HydraNetEvent pipe server <" << std::string(string::convertWCharToUtf8(m_sPipeName)) << ">");
			std::this_thread::sleep_for(std::chrono::milliseconds(250));
			continue;
		}

		const BOOL fConnected = ::ConnectNamedPipe(hPipe, nullptr) ? TRUE : (::GetLastError() == ERROR_PIPE_CONNECTED);
		if (!fConnected)
		{
			::CloseHandle(hPipe);
			if (!m_fStopRequested)
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			continue;
		}

		LOGLVL(Detailed, "HydraDragonFirewall connected to <" << std::string(string::convertWCharToUtf8(m_sPipeName)) << ">");

		std::string sCarry;
		char pBuffer[c_nReadBufferSize] = {};
		while (!m_fStopRequested)
		{
			DWORD nRead = 0;
			if (!::ReadFile(hPipe, pBuffer, static_cast<DWORD>(c_nReadBufferSize), &nRead, nullptr) || nRead == 0)
				break;

			sCarry.append(pBuffer, pBuffer + nRead);
			for (;;)
			{
				const auto nPos = sCarry.find('\n');
				if (nPos == std::string::npos)
					break;

				auto sLine = sCarry.substr(0, nPos);
				sCarry.erase(0, nPos + 1);
				boost::algorithm::trim(sLine);
				if (!sLine.empty())
					processLine(sLine);
			}
		}

		::DisconnectNamedPipe(hPipe);
		::CloseHandle(hPipe);
	}
}

void NetFilterWrapper::start()
{
	if (m_fStarted.exchange(true))
		return;

	m_fStopRequested = false;
	m_pListenerThread = std::thread([this]()
	{
		CMD_TRY
		{
			listenLoop();
		}
		CMD_PREPARE_CATCH
		catch (error::Exception& e)
		{
			e.log(SL, "HydraDragonFirewall telemetry loop failed");
		}
		catch (const std::exception& ex)
		{
			LOGWRN("HydraDragonFirewall telemetry loop failed: " << ex.what());
		}
	});
}

void NetFilterWrapper::stop()
{
	if (!m_fStarted.exchange(false))
		return;

	m_fStopRequested = true;
	wakeListener();
	if (m_pListenerThread.joinable())
		m_pListenerThread.join();
}

void NetFilterWrapper::shutdown()
{
	stop();
	m_pNetMonController.reset();
}

} // namespace win
} // namespace netmon
} // namespace cmd
