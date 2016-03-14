#include "debug.h"

struct debug_info debug_global;

#define time_format tm_now->tm_year+1900,tm_now->tm_mon,tm_now->tm_mday,tm_now->tm_hour,tm_now->tm_min,tm_now->tm_sec

void
_debug(char *filename, int line, int level, char *format, ...)
{
    va_list vlist;
/*
	struct tm {
	        int tm_sec;           // 秒 – 取值区间为[0,59] 
	        int tm_min;           // 分 - 取值区间为[0,59] 
	        int tm_hour;          // 时 - 取值区间为[0,23] 
	        int tm_mday;        // 一个月中的日期 - 取值区间为[1,31] 
	        int tm_mon;          // 月份（从一月开始，0代表一月） - 取值区间为[0,11] 
	        int tm_year;          // 年份，其值等于实际年份减去1900 
	        int tm_wday;        // 星期 – 取值区间为[0,6]，其中0代表星期天，1代表星期一 
	        int tm_yday;         // 从每年1月1日开始的天数– 取值区间[0,365]，其中0代表1月1日 
	        int tm_isdst;   //夏令时标识符，夏令时tm_isdst为正；不实行夏令时tm_isdst为0；
	};
*/
	time_t now;
 	struct tm *tm_now;
	time(&now);
	tm_now = gmtime(&now);

    if (debug_global.debuglevel >= level) {
		fprintf(stderr, "[%d][%04d-%02d-%02d %02d:%02d:%02d][%u](%s:%d) ", level,time_format,
				getpid(),filename, line);
		va_start(vlist, format);
		vfprintf(stderr, format, vlist);
		va_end(vlist);
		fputc('\n', stderr);

    }
	if (debug_global.log_syslog) {
		openlog("market_cpkgcli", LOG_PID, debug_global.syslog_facility);
		va_start(vlist, format);
		vsyslog(level, format, vlist);
		va_end(vlist);
		closelog();
	}

}

