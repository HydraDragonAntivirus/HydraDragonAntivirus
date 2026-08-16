//
// edrav2.edrsvc project
//
// Autor: Denis Bogdanov (10.02.2019)
// Reviewer: Yury Podpruzhnikov (11.02.2019)
//
///
/// @file Start mode handler for edrsvc.
///
/// Invoked as: edrsvc.exe start
///
/// Starts the edrsvc Windows service (elevating via UAC when needed).
///
#include "pch.h"
#include "service.h"

#include <windows.h>
#include <cstdint>
#include <string>

namespace cmd {
namespace win {

//
//
//
class AppMode_start : public IApplicationMode
{

public:

	//
	//
	//
virtual ErrorCode main(Application* pApp) override
	{
		ObjPtr<ICommandProcessor> pProcessor;

		try
		{
			pProcessor = startElevatedInstance(true);

			if (pProcessor)
			{
				auto vRes = execCommand(pProcessor, "execute", Dictionary({
					{ "command", "start" },
					{ "processor", "objects.application" }
				}));

				if (vRes.getType() == variant::ValueType::Boolean && vRes == false)
					std::cout << "Service <" << getCatalogData("app.fullName")
						<< "> has already run." << std::endl;
				else
					std::cout << "Service <" << getCatalogData("app.fullName")
						<< "> is started." << std::endl;
			}

			launchDefenderUi();
		}
		catch (const std::exception& ex)
		{
			std::cerr << "Failed to start service: " << ex.what() << std::endl;
		}
		catch (...)
		{
			std::cerr << "Unknown error while starting service." << std::endl;
		}
		if (pProcessor)
			stopElevatedInstance(pProcessor, true);

		return ErrorCode::OK;
	}

private:

	//
	// Launches the HydraDragonAntivirus UI (DefenderUI.exe) next to edrsvc.
	// Tray handling is owned entirely by the UI; edrsvc only starts it.
	//
	void launchDefenderUi()
	{
		try
		{
			std::filesystem::path svcPath;
			wchar_t szPath[MAX_PATH] = { 0 };
			if (::GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0)
				return;

			std::filesystem::path uiPath =
				std::filesystem::path(szPath).parent_path() / "defenderui" / "DefenderUI.exe";

			if (!std::filesystem::exists(uiPath))
				return;

			sys::executeApplication(uiPath, L"", false, 0);
		}
		catch (...)
		{
			// UI başlatılamazsa servis çalışmaya devam eder.
		}
	}
};

} // namespace win

 //
//
//
std::shared_ptr<IApplicationMode> createAppMode_start()
{
	return std::make_shared<win::AppMode_start>();
}

} // namespace cmd