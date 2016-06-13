#include "hb_client.h"

struct glob_arg G;
pthread_mutex_t SEND_MUTEX = PTHREAD_MUTEX_INITIALIZER;


#define DEBUG_IPC 0

static int init_resource()
{	
	G.configFile = strdup(DEFAULT_CONFIG_PATH);

	g_echoThread.echo_thpid = 0;
	g_echoThread.pause_flag = 1;

	g_recvThread.recv_thpid = 0;
	g_recvThread.pause_flag = 1;


	g_udpThread.udpserver_thpid = 0;
	g_udpThread.pause_flag = 1;
	return 0;
}

void handle_socket_I( int sig )
{
	hb_print(LOG_ERR,"Socket Abort\n");
}

void sig_watch_status( int sig )
{
	hb_log(LOG_ERR,"thread status(run) : echo(%d) recv(%d) udpserver(%d) \n",!g_echoThread.pause_flag,!g_recvThread.pause_flag,!g_udpThread.pause_flag);
	hb_log(LOG_ERR,"sn : send(%d) recv(%d) \n",G.hbrc->sendsn,G.hbrc->recvsn);
	hb_log(LOG_ERR,"echo sn : last echo request(%d) last echo response(%d) \n",G.hbrc->last_req_echosn,G.hbrc->last_resp_echosn);
}

static void init_signals(void)
{
	//signal(SIGINT, unregister_heartbeatserver);
	//signal(SIGTERM, unregister_heartbeatserver);
	signal(SIGPIPE, handle_socket_I);
	signal(SIGUSR1, sig_watch_status);
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

int amts_getmac(char *emac)
{
	char ifr[32] = {0};
	FILE *file;

	file = popen("amts r emac","r");
	if(!file) {
		pclose(file);
		return -1;
	}

	
	if (fgets(ifr,32,file) != NULL) {
		if(ifr[strlen(ifr)-1] == '\n') {
			ifr[strlen(ifr)-1] = '\0';
		}
		sscanf(ifr,"success,%s",emac);
	}
	
	if(emac == NULL) {
		pclose(file);
		return -1;
	}

	pclose(file);
	return 0;	
}

static struct hb_server* get_hbs()
{
	struct hb_server* hbs;
	hbs = (struct hb_server*)malloc(sizeof(struct hb_server));
	inet_aton("127.0.0.1",&hbs->hbs_ip);
	hbs->hbs_port = 0;
	hbs->hbs_index = -1;
	return hbs;
}

/*判断是否为域名，依靠inet_aton函数特性，域名是无法被inet_aton转换，因此
dip还会是255.255.255.255，只要依靠dip来判断就可以了*/
static int hb_isdns(char *dnsip)
{
	struct in_addr dip;
	
	inet_aton("255.255.255.255",&dip);
	inet_aton(dnsip,&dip);
	if(strncmp(inet_ntoa(dip),"255.255.255.255",strlen(inet_ntoa(dip))) == 0){
		return 1;
	} else {
		return 0;
	}
}

static int parse_hb_dnsip(struct heartbeat_route_client *hbrc, char *dnsip)
{
    /* Establish string and get the first token: */
    char* token = strtok(dnsip,",");	
    while( token != NULL )
    {
		char ipDns[32] = {0};
		char port[6] = {0};
		int iPort = 80;

		/* 通过strlen解析，如果无端口号，port不表示为NULL, 而是strlen为0 */
		sscanf(token,"%[^:]:%s",ipDns,port);
		if(strlen(port) != 0 && atoi(port) != 0) {
			iPort = atoi(port);
		} 
		
        hb_print(LOG_INFO, "token(%s) dnsip(%s) iPort(%d)",token,ipDns,iPort);
		if(hb_isdns(ipDns)) {				
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
			if ((he = gethostbyname(ipDns)) == NULL) {  // get the host info
				hb_print(LOG_ERR, "Can't resolve domain (%s)", ipDns);
				return -1;
			}
			
			hb_print(LOG_INFO,"Official name is: %s", he->h_name);
			hb_print(LOG_INFO,"IP addresses: ");
			addr_list = (struct in_addr **)he->h_addr_list;
			for(i = 0; addr_list[i] != NULL; i++) {
				printf("%s ", inet_ntoa(*addr_list[i]));
			}
			printf("\n");
			
			for(i = 0; addr_list[i] != NULL; i++) {
				struct hb_server* hbs;			
				hbs = get_hbs();
				hbs->hbs_ip = *addr_list[i];
				hbs->hbs_port= iPort;
				hbs->hbs_index = hbrc->hbs_count++;
				hbrc->hbs_head[hbs->hbs_index] = hbs;
				hb_print(LOG_INFO, "hbrc->hbs_count (%d) hbSever(%s)",hbrc->hbs_count,inet_ntoa(hbs->hbs_ip));
			}
		}
		else {
			struct hb_server* hbs;			
			hbs = get_hbs();
			inet_aton(ipDns,&hbs->hbs_ip);
			hbs->hbs_port= iPort;
			hbs->hbs_index = hbrc->hbs_count++;
			hbrc->hbs_head[hbs->hbs_index] = hbs;
			hb_print(LOG_INFO, "hbrc->hbs_count (%d) hbSever(%s)",hbrc->hbs_count,inet_ntoa(hbs->hbs_ip));			
		}
			
        /* Get next token: */
        token = strtok(NULL,",");
    }
    return 0;

}


#if CVNWARE
static int parse_startup(struct heartbeat_route_client *hbrc)
{
    HEARTBEAT_CFG_S Cfg;
	char hbAddr[HEARTBEAT_EXTADDR_LEN] = {0};
	char hbDefaultAddr[BUF_SIZE_256] = {0};
	//char hbDefaultAddr[BUF_SIZE_256];
	int ret;
	
    memset(&Cfg, 0, sizeof(HEARTBEAT_CFG_S));
    ret = HEARTBEAT_GetConfig(&Cfg);
    if (ret != OK)
    {
	    hb_print(LOG_ERR, "Get HeartBeat Config faild, Ret=%d",ret);
        return -1;
    }

	//hbrc->hbrc_conf.echo_interval = Cfg.ConnectInterval;
	hbrc->hbrc_conf.echo_interval = 30;
	hbrc->hbrc_conf.noecho_interval = Cfg.UnconnectInterval;
	hbrc->hbrc_conf.retry_count = Cfg.RetryCount;
	hbrc->hbrc_conf.retry_interval = Cfg.RetryInterval;

	hb_print(LOG_INFO, "echo(%d) noecho(%d) retry_count(%d) retry_interval(%d)",
			hbrc->hbrc_conf.echo_interval,hbrc->hbrc_conf.noecho_interval,hbrc->hbrc_conf.retry_count,hbrc->hbrc_conf.retry_interval);
	hb_print(LOG_INFO, "Cfg.DefaultAddr(%d) %s  Cfg.ExtAddr(%d) %s",strlen(Cfg.DefaultAddr),Cfg.DefaultAddr,strlen(Cfg.ExtAddr),Cfg.ExtAddr);
	
	strncpy(hbDefaultAddr,Cfg.DefaultAddr,strlen(Cfg.DefaultAddr));
	strncpy(hbAddr,Cfg.ExtAddr,strlen(Cfg.ExtAddr));

	parse_hb_dnsip(hbrc,hbDefaultAddr);
	parse_hb_dnsip(hbrc,hbAddr);

	return 1;
}
#endif

#if MTK
static int parse_startup_mtk(struct heartbeat_route_client *hbrc)
{

	char *hbAddr;
	char *hbDefaultAddr;

	hbAddr = (char *)nvram_bufget(RT2860_NVRAM, "heartbeat_extaddress");
	hbDefaultAddr = (char *)nvram_bufget(RT2860_NVRAM, "heartbeat_default_address");

	hbrc->hbrc_conf.echo_interval = atoi(nvram_bufget(RT2860_NVRAM, "heartbeat_connect_interval"));
	hbrc->hbrc_conf.noecho_interval = atoi(nvram_bufget(RT2860_NVRAM, "heartbeat_unconnect_inerval"));
	hbrc->hbrc_conf.retry_count = atoi(nvram_bufget(RT2860_NVRAM, "heartbeat_retry_count"));
	hbrc->hbrc_conf.retry_interval = atoi(nvram_bufget(RT2860_NVRAM, "heartbeat_retry_inerval"));

	hb_print(LOG_INFO, "echo(%d) noecho(%d) retry_count(%d) retry_interval(%d)",
			hbrc->hbrc_conf.echo_interval,hbrc->hbrc_conf.noecho_interval,hbrc->hbrc_conf.retry_count,hbrc->hbrc_conf.retry_interval);
	hb_print(LOG_INFO, "Cfg.DefaultAddr(%d) %s	Cfg.ExtAddr(%d) %s",strlen(hbDefaultAddr),hbDefaultAddr,
			strlen(hbAddr),hbAddr);

	parse_hb_dnsip(hbrc,hbDefaultAddr);
	parse_hb_dnsip(hbrc,hbAddr);
	return 1;
}
#endif

static int parse_file(struct heartbeat_route_client* hbrc)
{
	char hbAddr[128] = {0};
	char hbDefaultAddr[128] = {0};

	if(GetProfileString(G.configFile, "server_conf", "addr", hbAddr) < 0){
		hb_print(LOG_ERR, " not found addr!");
		return -1;
	}
	
	if(GetProfileString(G.configFile, "server_conf", "default_addr", hbDefaultAddr) < 0){
		hb_print(LOG_ERR, " not found default_addr!");
		return -1;
	}

	hbrc->hbrc_conf.echo_interval = 20;
	hbrc->hbrc_conf.noecho_interval = 20;
	hbrc->hbrc_conf.retry_count = 3;
	hbrc->hbrc_conf.retry_interval = 120;

	hb_print(LOG_INFO, "echo(%d) noecho(%d) retry_count(%d) retry_interval(%d)",
			hbrc->hbrc_conf.echo_interval,hbrc->hbrc_conf.noecho_interval,hbrc->hbrc_conf.retry_count,hbrc->hbrc_conf.retry_interval);
	hb_print(LOG_INFO, "Cfg.DefaultAddr(%d) %s	Cfg.ExtAddr(%d) %s",strlen(hbDefaultAddr),hbDefaultAddr,
			strlen(hbAddr),hbAddr);

	parse_hb_dnsip(hbrc,hbDefaultAddr);
	parse_hb_dnsip(hbrc,hbAddr);
	
	return 0;
}

int main(int argc, char **argv)
{
	int c,ret;
	void *status;
	struct heartbeat_route_client *hbrc;	

	debug_init(DEFAULT_DEBUGLEVEL,DEFAULT_LOG_SYSLOG,DEFAULT_SYSLOG_FACILITY);

	//初始化必要的资源	
	if( init_resource() < 0 ){
		hb_print(LOG_ERR, " init_resource fail !");
		return -1;	
	}	
	init_signals();

	hb_log(LOG_INFO, "Start Up Hb_client! \n");

	if( init_hbrc(&G.hbrc) < 0 ){
		return -1;	
	}	
	hbrc = G.hbrc;

	hbrc->hbrc_sm = HBRC_INVALID;
	
	parse_commandline(argc, argv);

	hbrc->hbrc_sm = HBRC_STRAT;
#if CVNWARE
	if(parse_startup(hbrc) < 0) {
		return -1;
	}
#else
#if MTK
	if(parse_startup_mtk(hbrc) < 0) {
		return -1;
	}	
#else
	parse_file(hbrc);
#endif
#endif

#ifdef HB_IPC
	hb_ipc_init(hbrc);
	ipc_mye_init();
#endif
	business_init(hbrc);

	hb_do_process(hbrc);
exit:
	return 0;
}
