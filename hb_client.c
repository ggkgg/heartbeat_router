#include "hb_client.h"

struct glob_arg G;

#define DEBUG_DES 0
#define DEBUG_CONF 1


static int init_resource()
{	

	G.configFile = strdup(DEFAULT_CONFIG_PATH);
	debug_global.debuglevel = DEFAULT_DEBUGLEVEL;
	debug_global.log_syslog = DEFAULT_LOG_SYSLOG;
	debug_global.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	
	hb_print(LOG_INFO, "init_resource success!");
	return 0;
}

static void init_signals(void)
{
	//signal(SIGINT, unregister_heartbeatserver);
	//signal(SIGTERM, unregister_heartbeatserver);
	return;
}


static void usage(void)
{
	const char *cmd = "hb_client";
	fprintf(stderr,
		"Usage:\n"
		"%s arguments\n"
		"\t-f --file : get hb_client config file\n"
		"\t-d --debuglevel :  set debug level\n"
		"\t-s --syslog :  use syslog \n"
		"\t-h --help : usage help\n"
		"", cmd);

	exit(0);
}

static void parse_commandline(int argc, char **argv) {
	int c;
	
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"file", 1, NULL, 'f'},
			{"help", 0, NULL, 'h'},
			{"debuglevel", 1, NULL, 'd'},
			{"syslog", 0, NULL, 's'},
			{0, 0, 0, 0}
		};
	
		c = getopt_long(argc, argv, "f:d:sh",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'f':
				G.configFile = strdup(optarg);
				break;
			case 'd':
				debug_global.debuglevel = atoi(optarg);
				break;
			case 's':
				debug_global.log_syslog = 1;
				break;
			case 'h':
				usage();
				break;	
			default:
				usage();
		}
	}
}	

int main(int argc, char **argv)
{
	int c,ret;

	//初始化必要的资源	
	if( init_resource() < 0 ){
		hb_print(LOG_ERR, " init_resource fail !");
		return -1;	
	}	
	
	parse_commandline(argc, argv);

	init_signals();

	
#if DEBUG_DES
#ifdef CRYTO_DES
	char str[32] = "hello world";
	int str_len = strlen(str);
	unsigned char en_str[32] = {0};
	unsigned char de_str[32] = {0};
	
	des_encode((const void *)str, en_str, CHANLLENGE_KEY, str_len);

	hb_print(LOG_INFO, "%s      (%d) -> %s    (%d) ",str,str_len,en_str,strlen(en_str));

	des_decode((const void *)en_str, de_str, CHANLLENGE_KEY, strlen(en_str));

	hb_print(LOG_INFO, "%s      (%d) -> %s    (%d) ",en_str,strlen(en_str),de_str,strlen(de_str));	

#endif
#endif

#if DEBUG_CONF
#endif

exit:
	return 0;
}
