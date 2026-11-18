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

	///
	/// What each cloud said for one scan (scanFileWithLocalEngines merges them
	/// into one verdict). Empty strings: that cloud was not asked.
	///
	struct CloudScanDetail
	{
		std::string sSha1;         // file SHA-1 (the FLS key)
		std::string sFls;          // Comodo FLS: Absent / Safe / Malicious / Unknown / Fail
		std::string sViruskov;     // VirusKov: Clean / Malicious / Suspicious / Unknown / Error
		std::string sViruskovName; // VirusKov detection name, when it detected
		bool fFromCache = false;   // answered from the size + last-write cache
		uint64_t nSha1Us = 0;      // time spent hashing the file for FLS
		uint64_t nFlsUs = 0;       // time spent waiting on FLS
		uint64_t nStaticUs = 0;    // time spent in staticScanVerdictName (openedr_static)
	};
	static int scanFileWithLocalEngines(const std::string& sUtf8Path, std::string& sThreatNameOut,
		CloudScanDetail* pDetail);

	///
	/// Scans an in-memory buffer (e.g. a process command line) with the local
	/// openedr_static engines (ClamAV, YARA-X, ML) via openedr_static_scan_bytes.
	/// sVirtualName gives the engines a file name for type detection.
	/// Returns 2 Malicious, 3 Suspicious, 1 Clean, 0 Unknown/unavailable.
	///
	static int scanBufferWithLocalEngines(const std::string& sData, const std::string& sVirtualName, std::string& sThreatNameOut);

	///
	/// Script hosts and script file extensions from edrsvc.cfg (scanner.scriptInterpreters /
	/// scanner.scriptExtensions), lower case. Used to find the script a process runs.
	///
	static std::vector<std::wstring> getScriptInterpreters();
	static std::vector<std::wstring> getScriptExtensions();

	///
	/// scanner.cmdlineScanNames: "host=ext" entries, lower case. A process'
	/// command line is scanned as "cmdline.<ext>" of its image's entry.
	///
	static std::vector<std::wstring> getCmdlineScanNames();
	// Authenticode trust check via the fileDataProvider (SignDataProvider), without a scan.
	// pSignerOut, when given, receives the publisher name (for diagnostics).
	static bool isFileSignatureTrusted(const std::string& sUtf8Path, std::string* pSignerOut = nullptr);

	///
	/// Fast query of the dynamic verdict cache (1=Clean, 2=Malicious, 3=Suspicious, 0=Unknown/Uncached).
	///
	static int getCachedFileVerdict(const std::string& sUtf8Path, CloudScanDetail* pDetailOut = nullptr);

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
	// How long an "Unknown" answer (VirusKov looked and cannot tell) is reused
	// before the file is asked about again; 0 = never reused.
	static std::atomic<int> s_unknownAnswerCacheSeconds;
	// How long a Comodo FLS "Absent" / "Unknown" answer is reused when VirusKov
	// did not decide (e.g. Deferred); 0 = never reused.
	static std::atomic<int> s_flsAnswerCacheSeconds;
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