//
// edrav2.libedr project
//
// Author: Emirhan Ucan (20.08.2026)
//
///
/// @file DetectionNotifier class implementation
///
/// @addtogroup edr
/// @{
#include "pch.h"
#include "detectionnotifier.h"

#include <deque>

// Set component for logging
#undef CMD_COMPONENT
#define CMD_COMPONENT "detnotif"

namespace cmd {

//
//
//
void DetectionNotifier::finalConstruct(Variant vConfig)
{
	TRACE_BEGIN;
	if (!vConfig.isDictionaryLike())
		error::InvalidArgument(SL, "finalConstruct() supports only dictionary as a parameter")
		.throwException();

	m_nMaxSize = vConfig.get("maxSize", m_nMaxSize);
	if (m_nMaxSize == 0)
		m_nMaxSize = 1;

	TRACE_END("Error during configuration");
}

//
//
//
bool DetectionNotifier::isDetectionEvent(const Variant& vEvent)
{
	if (!vEvent.isDictionaryLike())
		return false;

	// MLE detection events in the cloud output format have 'baseType' in
	// the MLE range (>= 1000000, see common.src constants).
	auto vBaseType = vEvent.getSafe("baseType");
	if (vBaseType.has_value() && vBaseType->getType() == variant::ValueType::Integer)
		return (static_cast<int64_t>(vBaseType.value()) >= c_nMinMleBaseType);

	// Fallback for non-cloud (raw) events with 'scheme' field.
	auto vScheme = vEvent.getSafe("scheme");
	if (vScheme.has_value() && vScheme->getType() == variant::ValueType::String)
		return (std::string(vScheme.value()) == "mle");

	return false;
}

//
//
//
Variant DetectionNotifier::execute(Variant vCommand, Variant vParams)
{
	TRACE_BEGIN;
	LOGLVL(Debug, "Process command <" << vCommand << ">");
	if (!vParams.isEmpty())
		LOGLVL(Trace, "Command parameters:\n" << vParams);

	if (vCommand == "put")
	{
		if (!vParams.has("data"))
			error::InvalidArgument(SL, "Missing field <data> in parameters").throwException();

		Variant vEvent = vParams["data"];
		if (!isDetectionEvent(vEvent))
			return {};

		{
			std::scoped_lock _lock(m_mtxStorage);

			int64_t nId = ++m_nLastId;
			Variant vEntry = Dictionary({ {"id", nId}, {"event", vEvent} });
			m_storage.push_back(std::move(vEntry));

			while (m_storage.size() > m_nMaxSize)
				m_storage.pop_front();
		}

		LOGLVL(Detailed, "Detection event <" << vEvent.get("type", "<undefined>") << "> is stored (id <" << m_nLastId << ">)");
		return {};
	}

	if (vCommand == "getDetections")
	{
		int64_t nLastId = 0;
		if (vParams.isDictionaryLike())
			nLastId = vParams.get("lastId", nLastId);

		Variant vEvents = Sequence();
		{
			std::scoped_lock _lock(m_mtxStorage);
			for (const auto& vEntry : m_storage)
			{
				if (static_cast<int64_t>(vEntry["id"]) > nLastId)
					vEvents.push_back(vEntry);
			}
		}

		LOGLVL(Debug, "Send <" << vEvents.getSize() << "> detection event(s) after id <" << nLastId << ">");
		return Dictionary({ {"lastId", m_nLastId}, {"events", vEvents} });
	}

	if (vCommand == "getLastDetectionId")
	{
		std::scoped_lock _lock(m_mtxStorage);
		return Dictionary({ {"lastId", m_nLastId} });
	}

	error::OperationNotSupported(SL, FMT("Unsupported command <" << vCommand << ">")).throwException();
	TRACE_END(FMT("Error during execution of a command <" << vCommand << ">"));
}

} // namespace cmd

/// @}