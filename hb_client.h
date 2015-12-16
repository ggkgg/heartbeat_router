#include "common.h"
#include "profile.h"
#include "hb_core.h"


struct glob_arg {
	char* configFile;
	int debuglevel;
	int log_syslog;
	//struct in_addr beforeserverip;
	//int heartbeatcycle;
};


#define CHANLLENGE_KEY  ((char *)"CVNCHINA")
#define DEFAULT_CONFIG_PATH "./hb_client.conf"


