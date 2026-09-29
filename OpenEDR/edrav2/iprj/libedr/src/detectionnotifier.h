//
// edrav2.libedr project
//
// Author: Emirhan Ucan (20.08.2026)
//
///
/// @file DetectionNotifier class declaration
///
/// @addtogroup edr
/// @{
#pragma once
#include <deque>
#include <mutex>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <objects.h>

namespace cmd {

///
/// Detection notifier.
///
/// Stores MLE detection events (in cloud output format) in a bounded ring
/// buffer with monotonically increasing identifiers so external GUI clients
/// (edrgui.exe) can poll for new detections via JSON-RPC. Persists known
/// detected malware on disk so repeat file drops/runs are immediately remembered.
///
class DetectionNotifier : public ObjectBase<CLSID_DetectionNotifier>,
	public ICommandProcessor
{
private:
	using EventStorage = std::deque<Variant>;

	EventStorage m_storage; ///< Ring buffer of stored events
	std::mutex m_mtxStorage; ///< Storage mutex
	int64_t m_nLastId = 0; ///< Id of the last stored event
	Size m_nMaxSize = 1000; ///< Maximum number of stored events

	///
	/// Checks whether an event is a detection (MLE) event.
	///
	bool isDetectionEvent(const Variant& vEvent);

public:
	///
	/// Final construct.
	///
	/// @param vConfig - object's configuration including the following fields:
	///   **maxSize** [int, opt] - maximum number of stored events (default: 1000).
	///
	void finalConstruct(Variant vConfig);

	///
	/// Records a detected malware path and hash to the persistent database.
	///
	static void recordMalwareDetection(const std::string& sPath, const std::string& sHash);

	///
	/// Checks if a path or hash corresponds to previously detected malware.
	///
	static bool isKnownMalware(const std::string& sPath, const std::string& sHash);

	///
	/// Loads the persistent malware database from disk on startup.
	///
	static void loadPersistentMalwareDb();

	///
	/// Converts NT device path or \??\ path to DOS drive path.
	///
	static std::string NtPathToDosPathString(const std::string& sNt);

	///
	/// Synchronously scans a file using the local detection engines (ClamAV, YARA-X, ML, Signer, EICAR).
	/// Returns 2 for malicious (with threat name in sThreatNameOut), 1 for safe, 0 for clean/unknown.
	///
	static int scanFileWithLocalEngines(const std::string& sUtf8Path, std::string& sThreatNameOut);
	// Authenticode + signer_rules trust check via openedr_static, without a scan.
	// pSignerOut, when given, receives the publisher name (for diagnostics).
	static bool isFileSignatureTrusted(const std::string& sUtf8Path, std::string* pSignerOut = nullptr);

	///
	/// Fast query of the dynamic verdict cache (1=Clean, 2=Malicious, 3=Suspicious, 0=Unknown/Uncached).
	///
	static int getCachedFileVerdict(const std::string& sUtf8Path);

	///
	/// True while protection actions are paused (HKLM\SOFTWARE\Owlyshield!PROTECTION_PAUSED).
	/// Monitoring, telemetry and training recording keep running; only
	/// remediation/quarantine/kill actions are suppressed.
	///
	static bool isProtectionPaused();

	///
	/// Zero Trust (Lockdown) mode state & session whitelisting.
	///
	static void setZeroTrustEnabled(bool enabled);
	static bool isZeroTrustEnabled();
	static void addZeroTrustSessionWhitelist(const std::string& path);
	static void addRestrictedProcess(uint32_t pid);
	static bool resumeSuspendedProcess(uint32_t pid);

	///
	/// Configurable verdict codes loaded from edrsvc.cfg (avoids hardcoded verdict numbers)
	///
	static std::atomic<bool> s_enableCloud;
	static std::atomic<bool> s_cloudFirst;
	static std::atomic<int> s_cleanVerdict;
	static std::atomic<int> s_malwareVerdict;
	static std::atomic<int> s_unknownVerdictDefault;
	static std::atomic<int> s_unknownReputationVerdict;
	static std::atomic<int> s_staticUnknownVerdict;
	static std::vector<int> s_unknownVerdicts;
	static std::mutex s_unknownVerdictsMtx;

	static bool isUnknownVerdict(int v);
	static void loadScannerConfigFromCfg(const std::string& content);

	// ICommandProcessor

	/// @copydoc ICommandProcessor::execute(Variant,Variant)
	Variant execute(Variant vCommand, Variant vParams) override;
};

} // namespace cmd

/// @}