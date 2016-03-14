#include "debug.h"

struct debug_info debug_global;

#define time_format tm_now->tm_year+1900,tm_now->tm_mon,tm_now->tm_mday,tm_now->tm_hour,tm_now->tm_min,tm_now->tm_sec

void
_debug(char *filename, int line, int level, char *format, ...)
{
    va_list vlist;
/*
	struct tm {
	        int tm_sec;           // �� �C ȡֵ����Ϊ[0,59] 
	        int tm_min;           // �� - ȡֵ����Ϊ[0,59] 
	        int tm_hour;          // ʱ - ȡֵ����Ϊ[0,23] 
	        int tm_mday;        // һ�����е����� - ȡֵ����Ϊ[1,31] 
	        int tm_mon;          // �·ݣ���һ�¿�ʼ��0����һ�£� - ȡֵ����Ϊ[0,11] 
	        int tm_year;          // ��ݣ���ֵ����ʵ����ݼ�ȥ1900 
	        int tm_wday;        // ���� �C ȡֵ����Ϊ[0,6]������0���������죬1��������һ 
	        int tm_yday;         // ��ÿ��1��1�տ�ʼ�������C ȡֵ����[0,365]������0����1��1�� 
	        int tm_isdst;   //����ʱ��ʶ��������ʱtm_isdstΪ������ʵ������ʱtm_isdstΪ0��
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

