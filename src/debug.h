#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

struct debug_info {
	int debuglevel;
	int log_syslog;
	int syslog_facility;
};


void debug_init(int debug_level,int syslog,int syslog_facility);

/** @brief Used to output messages.
 *The messages will include the finlname and line number, and will be sent to syslog if so configured in the config file 
 */
#define debug(level, format...) _debug(__FILE__, __LINE__, level, format)

/** @internal */
void _debug(char *filename, int line, int level, char *format, ...);

#define critTrace(level, format...)									\
	do {														\
		_debug(__FILE__, __LINE__,level,format);				 	    \
		_critTrace(format);										\
	} while (0)
	
void _critTrace(const char *_fmt, ...);

#endif /* _DEBUG_H_ */
