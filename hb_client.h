#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <pthread.h>

#include "common.h"

struct glob_arg {
	char* configFile;
	int debuglevel;
	int log_syslog;
	//struct in_addr beforeserverip;
	//int heartbeatcycle;
};


#define CHANLLENGE_KEY  ((char *)"CVNCHINA")
#define DEFAULT_CONFIG_PATH "./hb_client.conf"


