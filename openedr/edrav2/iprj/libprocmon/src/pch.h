#ifndef PCH_H
#define PCH_H

#define OS_DEPENDENT_PCH
#include "extheaders.h"
#include <../../libsyswin/inc/libsyswin.h>

#ifndef NOMINMAX
# define NOMINMAX
#endif
#include <windows.h>
#include <Shlobj.h>
#include <Knownfolders.h>
#include <tlhelp32.h>
#include <winternl.h>

#include "procmon.hpp"

#endif //PCH_H
