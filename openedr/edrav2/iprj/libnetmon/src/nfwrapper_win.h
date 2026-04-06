//
// edrav2.libnetmon
//
// Author: Podpruzhnikov Yury (15.10.2019)
// Reviewer:
//
///
/// @file Compatibility wrapper that now sources network events from
/// HydraDragonFirewall's named-pipe telemetry bridge instead of NetFilter SDK.
///
/// @addtogroup netmon Network Monitor library
/// @{
#pragma once
#include <atomic>
#include <thread>

#include "objects.h"
#include "netmon.h"

#undef CMD_COMPONENT
#define CMD_COMPONENT "libnetmon"

namespace cmd {
namespace netmon {
namespace win {

class NetFilterWrapper : public ObjectBase<CLSID_NetFilterWrapper>,
	public INetFilterWrapper
{
private:
	inline static const wchar_t c_sDefaultPipeName[] = LR"(\\.\pipe\HydraNetEvent)";
	inline static constexpr size_t c_nReadBufferSize = 8192;

	ObjPtr<INetworkMonitorController> m_pNetMonController;
	std::wstring m_sPipeName = c_sDefaultPipeName;
	std::atomic_bool m_fStarted = false;
	std::atomic_bool m_fStopRequested = false;
	std::thread m_pListenerThread;
	std::atomic_uint64_t m_nConnectionId = 1;

	void listenLoop();
	void wakeListener() const;
	void processLine(const std::string& sLine);
	void processNetEventLine(const std::string& sPayload);
	void processFullPacketLine(const std::string& sPayload);
	void dispatchConnection(std::shared_ptr<ConnectionInfo> pInfo);

protected:
	NetFilterWrapper();
	virtual ~NetFilterWrapper() override;

public:
	void finalConstruct(Variant vConfig);

	// INetFilterWrapper interface
	void start() override;
	void stop() override;
	void shutdown() override;
};

} // namespace win
} // namespace netmon
} // namespace cmd

/// @}
