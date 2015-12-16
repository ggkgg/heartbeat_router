#include "hb_client.h"

struct glob_arg G;

#define DEBUG_DES 0
#define DEBUG_CONF 1
#define DEBUG_RESOLVE 1
#define DEBUG_NETWORK 1


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
	char str_ipdomain[256] = {0};
	char str_int[16] = {0};
	int conn_interval = 0;
	
	if(GetProfileString(G.configFile, "server_conf", "ip-domain", str_ipdomain) < 0){
		hb_print(LOG_ERR, " not found ip-domain!");
		return -1;
	}

	if(GetProfileString(G.configFile, "connect_conf", "connect-interval", str_int) < 0){
		hb_print(LOG_ERR, " not found ip-domain!");
		return -1;
	}
	conn_interval = atoi(str_int);
	hb_print(LOG_INFO, "ipdomain(%s) conn_interval(%d)",str_ipdomain,conn_interval);
#endif

#if DEBUG_RESOLVE
	if (str_ipdomain[0] > 0 && str_ipdomain[0] < 9)
		hb_print(LOG_INFO,"ipdomain is ip\n");
	else
		hb_print(LOG_INFO,"ipdomain is domain\n");
		
	/*
	struct hostent
	 {
		char	*h_name;		// official name of host
		char	**h_aliases;	// alias list 
		int 	h_addrtype; 	// host address type 
		int 	h_length;		// length of address 
		char	**h_addr_list;	// list of addresses
	}；
	*/
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
	if ((he = gethostbyname(str_ipdomain)) == NULL) {  // get the host info
		hb_print(LOG_ERR, "Can't resolve domain (%s)", str_ipdomain);
		return -1;
	}

	hb_print(LOG_INFO,"Official name is: %s\n", he->h_name);
	printf("IP addresses: ");
	addr_list = (struct in_addr **)he->h_addr_list;
	for(i = 0; addr_list[i] != NULL; i++) {
		printf("%s ", inet_ntoa(*addr_list[i]));
	}
	printf("\n");
#endif

#if DEBUG_NETWORK
	int clientfd;
	char revBuffer[1024] = {0};
	int recbytes;
	unsigned char de_msgstr[256] = {0};
	
	if ((clientfd = hb_connect("127.0.0.1",20020)) < 0) {
		hb_print(LOG_ERR, "Connect HeartBeat Fail!");
		return -1;
	}

	do_challange(clientfd);
	
	if(-1 == (recbytes = read(clientfd, revBuffer, 1024))){
	  hb_print(LOG_ERR,"read data fail !");
	  close(clientfd);
	  return -1;
	}

	hb_print(LOG_INFO,"msg(%d) %s\n",recbytes,revBuffer);

	//des_decode((const void *)revBuffer, de_msgstr, CHANLLENGE_KEY, strlen(revBuffer));
	
    THDR *pHdr;
    pHdr = (THDR *)revBuffer;
    int datalen = sizeof(THDR) + pHdr->pktlen;

    hb_print(LOG_INFO,"recv packet, type = %d\n", pHdr->pktType);

#endif

exit:
	return 0;
}
