//
// edrav2.libedr project
//
// Author: Yury Ermakov (16.04.2019)
// Reviewer:
//
#pragma once

#include "extheaders.h"

#include "policy.hpp"
#include "events.hpp"
#include "lane.hpp"

#include "objects.h"
CMD_IMPORT_LIBRARY_OBJECTS(libedr)

namespace cmd
{
/// Starts loading the openedr_static engine on a background thread.
///
/// The engine loads synchronously and expensively: the ClamAV database, the
/// YARA rules and five model bundles, all in StaticEngine::init() behind a
/// OnceLock. Until now the first verdict request paid for it, on whichever
/// enrichment thread made that request, and every other caller blocked on the
/// same lock for the whole duration - so the event pipeline stalled at startup
/// and output_events.log only began filling long after the service was up.
///
/// Calling this during startup moves that cost off the first-event path: the
/// load overlaps with the rest of boot, and a later foreground call simply
/// finds the module already loaded (EnsureInitialized is one-shot). Safe to
/// call more than once; only the first call does anything.
void warmUpStaticEngine();

/// Runs the Sigma (Hayabusa) scan over the live Windows event logs once and
/// returns the engine's JSON report (empty if the engine is not usable).
/// This is the scheduled scan, and the only thing that makes the engine load
/// Hayabusa at all.
std::string runSigmaEventScan();

/// Starts a background timer that runs runSigmaEventScan() every nIntervalMs.
/// Returns immediately. nIntervalMs == 0 disables it. The timer lives in this
/// process, so there is no external artifact to remove or tamper with, and it
/// waits for the engine before its first run.
void startSigmaScanTimer(unsigned nIntervalMs);
} // namespace cmd

// Declaration of linking dependences (statical libraries)
#ifdef _MSC_VER
#pragma comment(lib, "libedr.lib")
#else
#error Declaration of linking dependences is not implemented for this compiler
#endif // _MSC_VER
