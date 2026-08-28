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
#include <objects.h>

namespace cmd {

///
/// Detection notifier.
///
/// Stores MLE detection events (in cloud output format) in a bounded ring
/// buffer with monotonically increasing identifiers so external GUI clients
/// (edrgui.exe) can poll for new detections via JSON-RPC.
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

	// Tracks GIDs that have already been killed so that stale MLE_RANSOM_BEHAVIOR
	// events (buffered before the kill completed) do not re-trigger a kill on
	// an innocent process (e.g. explorer.exe) that happens to be the new leaf.
	std::unordered_set<uint64_t> m_killedGids;
	std::mutex m_mtxKilledGids;

	// MLE cloud base type range (see common.src: MLE_FILE_COPY = 1000001, ...)
	static constexpr int64_t c_nMinMleBaseType = 1000000;

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

	// ICommandProcessor

	/// @copydoc ICommandProcessor::execute(Variant,Variant)
	Variant execute(Variant vCommand, Variant vParams) override;
};

} // namespace cmd

/// @}