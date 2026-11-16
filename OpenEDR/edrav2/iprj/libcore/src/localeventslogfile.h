//
// EDRAv2.libcore
// 
// Author: Vasily Plotnikov (20.10.2020)
// Reviewer: 
//
///
/// @file LocalEventsLogFile class declaration
///
/// @weakgroup io IO subsystem
/// @{
#pragma once
#include <common.hpp>
#include <command.hpp>
#include <io.hpp>
#include <objects.h>

namespace cmd {
namespace io {
///
/// Local mode events writer.
///
/// Save events accroding a policy to the local file.
///
	class LocalEventsLogFile : public ObjectBase<CLSID_LocalEventsLogFile>,
		public ICommandProcessor
	{
		int m_nDaysStore = 3;
		bool m_bMultiline = false;
		std::chrono::steady_clock::time_point m_lastCheckTime;
		int m_currentMonthDay = -1;
		std::filesystem::path m_sLogPath;
		std::string m_sLogFullPath;
		ObjPtr<io::IWritableStream>	m_pWriteStream;

		// Output lag (now - event time), logged once a minute.
		std::mutex m_mtxLag;
		uint64_t m_nLagCount = 0;
		uint64_t m_nLagSum = 0;
		uint64_t m_nLagMax = 0;
		std::chrono::steady_clock::time_point m_lagWindowStart{};
		void recordOutputLag(const Variant& vData);

		bool save(const Variant& vData);
		void updateFullPath();
		bool checkFullPathValid();
		std::string getFilename();

		void removeOutdated();
	public:
		
		void finalConstruct(Variant vConfig);
		// ICommandProcessor

		/// @copydoc ICommandProcessor::execute(Variant,Variant)
		Variant execute(Variant vCommand, Variant vParams) override;
	};
} // namespace io
} // namespace cmd

/// @}
