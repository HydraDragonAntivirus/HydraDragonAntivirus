//
// EDRAv2.libcore
// 
// Author: Vasily Plotnikov (20.10.2020)
// Reviewer: ???
//
///
/// @file LocalEventsLogFile class implementation
///
/// @weakgroup io IO subsystem
/// @{
#include "pch.h"
#include "localeventslogfile.h"
#include <utilities.hpp>

// Set component for logging
#undef CMD_COMPONENT
#define CMD_COMPONENT "locevents"

namespace cmd {
namespace io {

//
//
//
void LocalEventsLogFile::finalConstruct(Variant vConfig)
{
	TRACE_BEGIN;
	if (!vConfig.isDictionaryLike())
		error::InvalidArgument(SL, "finalConstruct() supports only dictionary as a parameter")
		.throwException();

	if (!vConfig.has("path") || vConfig["path"].getType() != variant::ValueType::String)
		error::InvalidArgument(SL, "Parameter <path> isn't found or invalid").throwException();

	m_nDaysStore = vConfig.get("daysStore", m_nDaysStore);
	m_sLogPath = std::filesystem::path(vConfig["path"]);
	m_bMultiline = vConfig.get("multiline", m_bMultiline);

	std::string sMode = vConfig.get("mode", "");

	if (sMode.find("create") != std::string::npos &&
		!std::filesystem::exists(m_sLogPath))
		std::filesystem::create_directory(m_sLogPath);

	if (!std::filesystem::exists(m_sLogPath) ||
		!std::filesystem::is_directory(m_sLogPath))
		error::NotFound(SL, FMT("Data directory <" << m_sLogPath
			<< "> doesn't exist or invalid")).throwException();

	// Start the day check from now and today. checkFullPathValid() used to do
	// this, but only when 5 minutes had passed since steady_clock's epoch -
	// the boot. Started within 5 minutes of boot, the day stayed unset, and
	// the first check 5 minutes later took it for a new day and reopened
	// (then truncated) the file.
	{
		auto tnow = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		tm tmData;
		gmtime_s(&tmData, &tnow);
		m_currentMonthDay = tmData.tm_mday;
		m_lastCheckTime = std::chrono::steady_clock::now();
	}
	updateFullPath();

	TRACE_END("Error during configuration");
}

//
//
//
bool LocalEventsLogFile::save(const Variant& vData)
{
	if (!checkFullPathValid())
	{
		updateFullPath();
		removeOutdated();
	}

	if (m_pWriteStream)
	{
		recordOutputLag(vData);
		variant::serializeToJson(m_pWriteStream, vData, m_bMultiline ? variant::JsonFormat::Pretty : variant::JsonFormat::SingleLine);
		io::write(m_pWriteStream, "\r\n");
		return true;
	}

	return false;
}

// How late events are written (now - event "time"), logged once a minute: the
// whole way from the driver to this file. Set against the enricher's
// "eventlag" line, it shows whether the delay is before, in or after the
// enricher (the scenarios between it and here).
void LocalEventsLogFile::recordOutputLag(const Variant& vData)
{
	try
	{
		if (!vData.isDictionaryLike() || !vData.has("time"))
			return;
		const Time nEventTime = vData["time"];
		const Time nNow = getCurrentTime();
		const uint64_t nLag = nNow > nEventTime ? static_cast<uint64_t>(nNow - nEventTime) : 0;
		std::scoped_lock lock(m_mtxLag);
		++m_nLagCount;
		m_nLagSum += nLag;
		m_nLagMax = (std::max)(m_nLagMax, nLag);
		const auto now = std::chrono::steady_clock::now();
		if (m_lagWindowStart == std::chrono::steady_clock::time_point{})
			m_lagWindowStart = now;
		if (now - m_lagWindowStart < std::chrono::seconds(60))
			return;
		LOGLVL(Critical, "outputlag: " << m_nLagCount << " events written in "
			<< std::chrono::duration_cast<std::chrono::seconds>(now - m_lagWindowStart).count()
			<< " s | lag avg " << m_nLagSum / m_nLagCount << " ms, max " << m_nLagMax << " ms");
		m_nLagCount = m_nLagSum = m_nLagMax = 0;
		m_lagWindowStart = now;
	}
	catch (...) {}
}

void LocalEventsLogFile::updateFullPath()
{
	std::filesystem::path pathToFile(m_sLogPath);
	auto filename = getFilename();

	if (!pathToFile.empty())
	{
		m_sLogFullPath = (pathToFile / filename).string();

		// Append to the day's file, never truncate it. The name changes per day,
		// so truncation only ever hit today's own events: every reopen (a
		// service restart, or the day check below firing on the same day)
		// wiped what had been written so far.
		m_pWriteStream = queryInterface<io::IWritableStream>(io::createFileStream(m_sLogFullPath,
			io::FileMode::Write | io::FileMode::ShareRead | io::FileMode::ShareWrite | io::FileMode::CreatePath));
		m_pWriteStream->setPosition(0, io::StreamPos::End);
	}
}

bool LocalEventsLogFile::checkFullPathValid()
{
	using namespace std::chrono;

	auto currentTime = steady_clock::now();
	if(duration_cast<minutes>(currentTime - m_lastCheckTime).count() > 5)
	{
		m_lastCheckTime = currentTime;
		auto tnow =system_clock::to_time_t(system_clock::now());
		tm tmData;
		gmtime_s(&tmData, &tnow);
		if (m_currentMonthDay != tmData.tm_mday)
		{
			m_currentMonthDay = tmData.tm_mday;
			return false;
		}
	}
	
	return true;
}

std::string LocalEventsLogFile::getFilename()
{
	//name format: %Y-%m-%d.log
	using namespace std::chrono;
	auto now = system_clock::now();
	auto in_time_t = system_clock::to_time_t(now);

	tm tmTime;
	gmtime_s(&tmTime, &in_time_t);

	std::stringstream ss;
	ss << std::put_time(&tmTime, "%Y-%m-%d") << ".log";
	return ss.str();
}

void LocalEventsLogFile::removeOutdated()
{
	using namespace std::filesystem;
	using namespace std::chrono;
	auto now = file_time_type::clock::now();
	auto maxdurationhrs = 24 * m_nDaysStore;

	auto isOutdated = [now, maxdurationhrs](const directory_entry& p) -> bool
	{
		auto last_write_time = p.last_write_time();
		if (duration_cast<hours>(now - last_write_time).count() > maxdurationhrs )
			return true;
		return false;
	};

	for (auto& sub_path : directory_iterator(m_sLogPath))
	{
		if (sub_path.is_directory())
			continue;
		auto ext = string::convertToLower(sub_path.path().extension().c_str());
		if (ext.compare(L".log") != 0)
			continue;

		if (isOutdated(sub_path))
			remove(sub_path);
	}
}

//
//
//
Variant LocalEventsLogFile::execute(Variant vCommand, Variant vParams)
{
	TRACE_BEGIN;
	LOGLVL(Debug, "Process command <" << vCommand << ">");
	if (!vParams.isEmpty())
		LOGLVL(Trace, "Command parameters:\n" << vParams);

	if (vCommand == "put")
	{
		if (!vParams.has("data"))
			error::InvalidArgument(SL, "Missing field <data> in parameters").throwException();
		if (!vParams.has("default"))
			return save(vParams["data"]);

		CMD_TRY
		{
			return save(vParams["data"]);
		}
		CMD_PREPARE_CATCH
		catch (const error::Exception& ex)
		{
			LOGLVL(Debug, ex.what());
			return vParams["default"];
		}
	}

	error::OperationNotSupported(SL, FMT("Unsupported command <" << vCommand << ">")).throwException();
	TRACE_END(FMT("Error during execution of a command <" << vCommand << ">"));
}

} // namespace io
} // namespace cmd

/// @}