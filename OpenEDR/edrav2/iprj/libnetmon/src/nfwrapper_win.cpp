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
#include "owlyshield_integration.h"

#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>

#undef CMD_COMPONENT
#define CMD_COMPONENT "netmon"

namespace cmd {
namespace netmon {
namespace win {

namespace {

std::wstring getCurrentExecutablePath()
{
	std::wstring result(32768, L'\0');
	const auto nLength = ::GetModuleFileNameW(nullptr, result.data(), static_cast<DWORD>(result.size()));
	if (nLength == 0)
		return {};

	result.resize(nLength);
	return result;
}

AddressFamily detectAddressFamily(const std::string& sIp)
{
	return sIp.find(':') == std::string::npos ? AddressFamily::Inet : AddressFamily::Inet6;
}

/// Forward a raw firewall telemetry line to Owlyshield via the in-process FFI
/// channel. The former global named pipe has been removed so no other usermode
/// process can inject events into the behavior engine.
void forwardRawTelemetryToOwlyshield(const std::string& sLine)
{
	if (sLine.empty())
		return;

	if (!cmd::win::OwlyshieldIngestFirewallPackedData(sLine))
		LOGLVL(Trace, "Failed to forward firewall packed data to Owlyshield");
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

std::vector<std::filesystem::path> getFirewallBridgeCandidates(const std::wstring& sExplicitPath)
{
	std::vector<std::filesystem::path> result;

	if (!sExplicitPath.empty())
		result.emplace_back(sExplicitPath);

	result.emplace_back(LR"(C:\Program Files\HydraDragonAntivirus\OpenEDR\owlyshield_ransom.dll)");

	return result;
}

std::string pathToUtf8(const std::filesystem::path& path)
{
	return std::string(string::convertWCharToUtf8(path.native()));
}

} // namespace

NetFilterWrapper::NetFilterWrapper()
{
}

NetFilterWrapper::~NetFilterWrapper()
{
	stop();
	unloadFirewallBridge();
}

void NetFilterWrapper::finalConstruct(Variant vConfig)
{
	CHECK_IN_SOURCE_LOCATION();
	m_pNetMonController = queryInterface<INetworkMonitorController>(vConfig.get("controller"));
	m_sPipeName = vConfig.get("pipeName", std::wstring(c_sDefaultPipeName));
	m_fEnableFirewallBridge = vConfig.get("enableFirewallBridge", true);
	m_sFirewallBridgeDllPath = vConfig.get("firewallBridgeDllPath", std::wstring());
}

bool NetFilterWrapper::loadFirewallBridge()
{
	if (m_hFirewallBridge != nullptr)
		return m_fnFirewallStart != nullptr && m_fnFirewallStop != nullptr;

	for (const auto& candidate : getFirewallBridgeCandidates(m_sFirewallBridgeDllPath))
	{
		std::error_code ec;
		if (!std::filesystem::exists(candidate, ec) || ec)
			continue;

		HMODULE hBridge = ::LoadLibraryW(candidate.c_str());
		if (hBridge == nullptr)
			continue;

		auto fnStart = reinterpret_cast<FnHydraDragonFirewallStart>(::GetProcAddress(hBridge, "HydraDragonFirewall_Start"));
		auto fnStop = reinterpret_cast<FnHydraDragonFirewallStop>(::GetProcAddress(hBridge, "HydraDragonFirewall_Stop"));
		auto fnIsRunning = reinterpret_cast<FnHydraDragonFirewallIsRunning>(::GetProcAddress(hBridge, "HydraDragonFirewall_IsRunning"));
		auto fnGetLastError = reinterpret_cast<FnHydraDragonFirewallGetLastErrorMessage>(
			::GetProcAddress(hBridge, "HydraDragonFirewall_GetLastErrorMessage"));
		if (fnStart == nullptr || fnStop == nullptr)
		{
			::FreeLibrary(hBridge);
			continue;
		}

		m_hFirewallBridge = hBridge;
		m_fnFirewallStart = fnStart;
		m_fnFirewallStop = fnStop;
		m_fnFirewallIsRunning = fnIsRunning;
		m_fnFirewallGetLastErrorMessage = fnGetLastError;

		LOGLVL(Detailed, "Loaded HydraDragonFirewall bridge from <" << pathToUtf8(candidate) << ">");
		return true;
	}

	return false;
}

void NetFilterWrapper::unloadFirewallBridge()
{
	if (m_hFirewallBridge != nullptr)
		::FreeLibrary(m_hFirewallBridge);

	m_hFirewallBridge = nullptr;
	m_fnFirewallStart = nullptr;
	m_fnFirewallStop = nullptr;
	m_fnFirewallIsRunning = nullptr;
	m_fnFirewallGetLastErrorMessage = nullptr;
}

std::string NetFilterWrapper::getFirewallBridgeError() const
{
	if (m_fnFirewallGetLastErrorMessage == nullptr)
		return {};

	std::array<char, 512> pBuffer = {};
	const auto nLength = m_fnFirewallGetLastErrorMessage(pBuffer.data(), pBuffer.size());
	if (nLength == 0)
		return {};

	return std::string(pBuffer.data());
}

void NetFilterWrapper::startFirewallBridge()
{
	if (!m_fEnableFirewallBridge)
		return;

	if (!loadFirewallBridge())
	{
		if (!m_sFirewallBridgeDllPath.empty())
			LOGWRN("Failed to load HydraDragonFirewall bridge from <" <<
				std::string(string::convertWCharToUtf8(m_sFirewallBridgeDllPath)) << ">");
		else
			LOGLVL(Detailed, "HydraDragonFirewall bridge dll was not found. Waiting for an external telemetry producer.");
		return;
	}

	if (m_fnFirewallIsRunning != nullptr && m_fnFirewallIsRunning() != 0)
	{
		LOGLVL(Detailed, "HydraDragonFirewall engine is already running");
		return;
	}

	if (m_fnFirewallStart() == 0)
	{
		const auto sError = getFirewallBridgeError();
		if (!sError.empty())
			LOGWRN("Failed to initialize HydraDragonFirewall engine: " << sError);
		else
			LOGWRN("Failed to initialize HydraDragonFirewall engine");
		return;
	}

	LOGLVL(Detailed, "HydraDragonFirewall engine initialized");
}

void NetFilterWrapper::stopFirewallBridge()
{
	if (m_fnFirewallStop == nullptr)
		return;

	if (m_fnFirewallStop() == 0)
	{
		const auto sError = getFirewallBridgeError();
		if (!sError.empty())
			LOGWRN("Failed to stop HydraDragonFirewall engine cleanly: " << sError);
		else
			LOGWRN("Failed to stop HydraDragonFirewall engine cleanly");
	}
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
	// Forward the full raw line to Owlyshield via the in-process FFI channel
	// so it can run its own behavior rule matching on the packet.
	forwardRawTelemetryToOwlyshield(sPayload);

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

void NetFilterWrapper::processHttpBodyLine(const std::string& sPayload)
{
	try
	{
		// Format: hash|method|url||hex_data
		const auto nDataSep = sPayload.find("||");
		if (nDataSep == std::string::npos)
		{
			LOGWRN("Invalid HydraNetEvent HTTP_BODY payload (missing data separator) <" << sPayload << ">");
			return;
		}

		const auto sMetadata = sPayload.substr(0, nDataSep);
		const auto sHexData = sPayload.substr(nDataSep + 2);

		std::vector<std::string> vParts;
		boost::split(vParts, sMetadata, boost::is_any_of("|"));

		if (vParts.size() < 3)
		{
			LOGWRN("Invalid HydraNetEvent HTTP_BODY metadata <" << sMetadata << ">");
			return;
		}

		const auto& sId = vParts[0];
		const auto& sMethod = vParts[1];
		const auto& sUrl = vParts[2];

		LOGLVL(Detailed, "HydraNetEvent - HTTP " << sMethod << " " << sUrl << " [ID:" << sId << "] Payload: " << sHexData.length() / 2 << " bytes");
	}
	catch (const std::exception& ex)
	{
		LOGWRN("Failed to parse HTTP_BODY telemetry: " << ex.what());
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

	if (boost::algorithm::starts_with(sLine, "HTTP_BODY:"))
	{
		processHttpBodyLine(sLine.substr(std::strlen("HTTP_BODY:")));
		return;
	}

	if (boost::algorithm::starts_with(sLine, "SSL_DATA:") ||
		boost::algorithm::starts_with(sLine, "TCP_DATA:") ||
		boost::algorithm::starts_with(sLine, "DOMAIN_NAME:"))
	{
		// Suppress warnings for known but currently unhandled types
		return;
	}

	if (boost::algorithm::starts_with(sLine, "BLOCK_EXE:"))
		return;

	// HIPS user decision from the GUI (edrgui). Forward the full line to
	// Owlyshield via the in-process FFI channel so the behavior engine can
	// resolve the pending HIPS prompt.
	if (boost::algorithm::starts_with(sLine, "HIPS_DECISION:"))
	{
		forwardRawTelemetryToOwlyshield(sLine);
		return;
	}

	LOGLVL(Detailed, "Ignoring unsupported HydraNetEvent message <" << (sLine.length() > 256 ? sLine.substr(0, 256) + "..." : sLine) << ">");
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

	startFirewallBridge();
}

void NetFilterWrapper::stop()
{
	if (!m_fStarted.exchange(false))
		return;

	m_fStopRequested = true;
	stopFirewallBridge();
	wakeListener();
	if (m_pListenerThread.joinable())
		m_pListenerThread.join();
}

void NetFilterWrapper::shutdown()
{
	stop();
	m_pNetMonController.reset();
	unloadFirewallBridge();
}

} // namespace win
} // namespace netmon
} // namespace cmd
