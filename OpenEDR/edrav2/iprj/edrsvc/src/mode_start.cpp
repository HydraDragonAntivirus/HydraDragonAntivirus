//
// edrav2.edrsvc project
//
// Autor: Denis Bogdanov (10.02.2019)
// Reviewer: Yury Podpruzhnikov (11.02.2019)
//
///
/// @file comtrol mode handler for edrsvc
///
#include "pch.h"
#include "service.h"

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
		ObjPtr<ICommandProcessor> pProcessor = startElevatedInstance(true);

		// Starting the service must never prevent the tray from showing: even if
		// the SCM start fails (e.g. driver not loaded), the tray is still useful
		// for Status/Start/Stop/Exit.
		try
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
		catch (const std::exception& ex)
		{
			stopElevatedInstance(pProcessor, true);
			std::cerr << "Failed to start service: " << ex.what()
				<< " - starting tray anyway." << std::endl;
		}
		catch (...)
		{
			stopElevatedInstance(pProcessor, true);
			std::cerr << "Unknown error while starting service - starting tray anyway."
				<< std::endl;
		}
		stopElevatedInstance(pProcessor, true);

		// After the service is up, show the tray UI
		return runTray();
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