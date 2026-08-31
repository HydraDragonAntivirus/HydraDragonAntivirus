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

	// ICommandProcessor

	/// @copydoc ICommandProcessor::execute(Variant,Variant)
	Variant execute(Variant vCommand, Variant vParams) override;
};

} // namespace cmd

/// @}