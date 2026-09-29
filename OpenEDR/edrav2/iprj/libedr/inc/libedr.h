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
} // namespace cmd

// Declaration of linking dependences (statical libraries)
#ifdef _MSC_VER
#pragma comment(lib, "libedr.lib")
#else
#error Declaration of linking dependences is not implemented for this compiler
#endif // _MSC_VER
