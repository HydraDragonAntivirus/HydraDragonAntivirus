//
// edrav2.libedr project
//
// Event Enricher declaration
//
// Author: Denis Kroshin (09.07.2019)
// Reviewer: Denis Bogdanov (xx.xx.2019)
//
#pragma once
#include "..\inc\objects.h"

#include <unordered_set>

namespace cmd {

///
/// Events Enricher
///
class EventEnricher : public ObjectBase<CLSID_EventEnricher>,
	public ICommandProcessor,
	public IService,
	public IDataReceiver,
	public IQueueNotificationAcceptor
{
private:
	std::mutex m_mtxStartStop;
	bool m_fInitialized = false;
	ThreadPool m_threadPool{ "EventEnricher" };
	ObjPtr<sys::win::IProcessInformation> m_pProcProvider;

	std::mutex m_mtxQueue;
	ObjWeakPtr<IDataProvider> m_pProvider;
	ObjPtr<IDataReceiver> m_pReceiver;
	void processQueueEvent();

	// Comodo-cloud trust mode state (registry: HKLM\SOFTWARE\Owlyshield\TRUST_COMODO_CLOUD)
	bool m_fTrustComodoCloud = false;
	std::mutex m_mtxTrustedPids;
	std::unordered_set<uint32_t> m_setTrustedPids;
	bool isPidCloudTrusted(uint32_t nPid);
	bool isProcessCloudTrusted(const Variant& vProcess);

	std::wstring getRegistryPath(std::wstring sPath);
	std::wstring getRegistryAbstractPath(std::wstring sPath);

public:

	///
	/// Object final construction
	///
	/// @param vConfig The object's configuration including the following fields:
	///   **receiver** - object that receive MLE events
	/// @throw error::InvalidArgument In case of invalid configuration in vConfig.
	///
	void finalConstruct(Variant vConfig);

	// IService interface
	virtual void loadState(Variant vState) override;
	virtual Variant saveState() override;
	virtual void start() override;
	virtual void stop() override;
	virtual void shutdown() override;

	// IDataReceiver
	virtual void put(const Variant& vData) override;

	// IQueueNotificationAcceptor
	virtual void notifyAddQueueData(Variant vTag) override;
	virtual void notifyQueueOverflowWarning(Variant vTag) override;

	// ICommandProcessor
	virtual Variant execute(Variant vCommand, Variant vParams) override;
};
} // namespace cmd 
