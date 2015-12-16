#ifndef __COMMON_H_
#define _COMMON_H_

#include "debug.h"

#define hb_print(level, format...) debug(level, format)
extern struct debug_info debug_global;

#define DEFAULT_DEBUGLEVEL LOG_INFO
#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON

#endif
