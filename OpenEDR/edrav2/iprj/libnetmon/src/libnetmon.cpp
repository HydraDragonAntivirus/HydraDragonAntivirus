//
// edrav2.libnetmon project
//
// Reviewer: Denis Bogdanov (02.09.2019)
//
// Library classes registration
//
#include "pch.h"
#include "controller.h"
#include "nfwrapper_win.h"

//
// Classes registration
//
CMD_BEGIN_LIBRARY_DEFINITION(libnetmon)
CMD_DEFINE_LIBRARY_CLASS(netmon::win::NetFilterWrapper)
CMD_DEFINE_LIBRARY_CLASS(netmon::NetworkMonitorController)
CMD_END_LIBRARY_DEFINITION(libnetmon)
