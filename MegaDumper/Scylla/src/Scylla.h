#pragma once

#include "ConfigurationHolder.h"
#include "Logger.h"
#include "PluginLoader.h"
#include "ProcessLister.h"

#define DONATE_BTC_ADDRESS "1GmVrhWwUhwLohaCLP4SKV5kkz8rd16N8h"

class Scylla {
 public:
  static void initAsGuiApp();
  static void initAsDll();

  static ConfigurationHolder config;
  static PluginLoader plugins;

  static ProcessLister processLister;

  static FileLog debugLog;
  static ListboxLog windowLog;

 private:
  static const WCHAR DEBUG_LOG_FILENAME[];
};
