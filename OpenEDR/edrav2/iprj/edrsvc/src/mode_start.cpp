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