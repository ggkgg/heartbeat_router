#include "hb_client.h"

struct glob_arg G;

#define DEBUG_DES 0
#define DEBUG_CONF 1
#define DEBUG_RESOLVE 1
#define DEBUG_NETWORK 1
#define DEBUG_ECHO 1
#define DEBUG_XOR 1
#define DEBUG_NOTIFY 1

#if 0
static u32_t session_client_key = 0;
static u32_t session_server_key = 0;

static int sendsn = 10002;
#endif

static int init_resource()
{	

	G.configFile = strdup(DEFAULT_CONFIG_PATH);
	G.echoThread.echo_thpid = 0;
	G.echoThread.pause_flag = 1;

	G.recvThread.recv_thpid = 0;
	G.recvThread.pause_flag = 1;

	
	debug_global.debuglevel = DEFAULT_DEBUGLEVEL;
	debug_global.log_syslog = DEFAULT_LOG_SYSLOG;
	debug_global.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	
	hb_print(LOG_INFO, "init_resource success!");
	return 0;
}

void handle_socket_I( int sig )
{
	hb_print(LOG_ERR,"Socket Abort\n");
}

static void init_signals(void)
{
	//signal(SIGINT, unregister_heartbeatserver);
	//signal(SIGTERM, unregister_heartbeatserver);
	signal(SIGPIPE, handle_socket_I);
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

static int amts_getmac(char *emac)
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

static int parse_file(struct heartbeat_route_client* hbrc)
{
#if 0
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
	return 0;
}


static struct hb_server* get_hbs()
{
	struct hb_server* hbs;
	hbs = (struct hb_server*)malloc(sizeof(struct hb_server));
	//hbs->hbs_sm = HBS_INVALID;
	inet_aton("127.0.0.1",&hbs->hbs_ip);
	hbs->hbs_port = 20020;
	hbs->hbs_index = -1;
	//hbs->hbs_sm = HBS_STRAT;
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
        hb_print(LOG_INFO, "dnsip %s",token);
		if(hb_isdns(token)) {				
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
			if ((he = gethostbyname(token)) == NULL) {  // get the host info
				hb_print(LOG_ERR, "Can't resolve domain (%s)", token);
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
				hbs->hbs_index = hbrc->hbs_count++;
				hbrc->hbs_head[hbs->hbs_index] = hbs;
				hb_print(LOG_INFO, "hbrc->hbs_count (%d) hbSever(%s)",hbrc->hbs_count,inet_ntoa(hbs->hbs_ip));					
			}
		}
		else {
			struct hb_server* hbs;			
			hbs = get_hbs();
			inet_aton(token,&hbs->hbs_ip);
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



static int init_default_hbc_config(struct hbc_conf *conf)
{
	conf->echo_interval = 20;
	conf->retry_count = 3;
	conf->retry_interval = 30;
	conf->noecho_interval = 60;
}

static int init_hbrc(struct heartbeat_route_client** hbrcp)
{
	struct heartbeat_route_client *hbrc;
	struct hb_server* hbs;
	struct hbc_conf* hbcConf;
   	char emac[16] = {0}; 
	
	*hbrcp = (struct heartbeat_route_client *)malloc(sizeof(struct heartbeat_route_client));
	hbrc = *hbrcp;
	hbrc->hbrc_sm = HBRC_INVALID;


	/* connect conf*/
	hbrc->equipmentSn[0] = '\0';
	hbrc->sendsn = 0;
	hbrc->hbrc_sockfd = 0;
	hbrc->session_client_key = 0;
	hbrc->session_server_key = 0;

	/* recv buff*/
	hbrc->gbuf = NULL;
	hbrc->dataLen = 0;
	hbrc->maxLen = 0;

	/* init hbs  */
	hbrc->hbs_count = 0;
	hbrc->hbs_head = (struct hb_server **)malloc(MAX_HB_COUNT*sizeof(struct hb_server *));


	/* init hbrc conf */
	//hbcConf = (struct hbc_conf *)malloc(sizeof(struct hbc_conf));
	//init_default_hbc_config(hbcConf);	
	//hbrc->hbrc_conf = hbcConf;
	//(*hbrcp)->hbrc_conf = (struct hbc_conf *)malloc(sizeof(struct hbc_conf));
	init_default_hbc_config(&hbrc->hbrc_conf);	

#if CVNWARE
	DRV_AmtsGetEMac(emac);
#endif
	
#if MTK
	if(amts_getmac(emac) < 0) {
		hb_print(LOG_ERR,"get device mac error");
		return -1;
	}
#endif

	hb_print(LOG_INFO,"############ emac = %s",emac);
	sscanf(emac,"%02x%02x%02x%02x%02x%02x",
		&hbrc->equipmentSn[0],&hbrc->equipmentSn[1],&hbrc->equipmentSn[2],
		&hbrc->equipmentSn[3],&hbrc->equipmentSn[4],&hbrc->equipmentSn[5]); 

	return 0;
}


void thread_echo(void *arg)
{
	struct heartbeat_route_client* hbrc = (struct heartbeat_route_client*)arg;
	//struct heartbeat_route_client* hbrc = (struct heartbeat_route_client*)&arg;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec timeout;
	
	while (1) {
		if(!G.echoThread.pause_flag) {
			net_echo(hbrc);
		}
		/* Sleep for config.crondinterval seconds... */
		timeout.tv_sec = time(NULL) + hbrc->hbrc_conf.echo_interval;
		//timeout.tv_sec = time(NULL) + 10;
		timeout.tv_nsec = 0;
	
		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	}
}

void thread_recv(void *arg)
{
	struct heartbeat_route_client* hbrc = (struct heartbeat_route_client*)arg;

	while (1) {
		int sock_fd = hbrc->hbrc_sockfd;
		struct sockaddr_un clt_addr;
		int clt_len = sizeof(struct sockaddr_un);	
		int ret;
		fd_set read_fds;
		int maxsock;
		struct timeval tv;
		
		if(G.recvThread.pause_flag) {
			pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
			pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
			struct	timespec timeout;	
			/* Sleep for config.crondinterval seconds... */
			timeout.tv_sec = time(NULL) + 10;
			timeout.tv_nsec = 0;
			
			/* Mutex must be locked for pthread_cond_timedwait... */
			pthread_mutex_lock(&cond_mutex);
			
			/* Thread safe "sleep" */
			pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
			
			/* No longer needs to be locked */
			pthread_mutex_unlock(&cond_mutex);

			continue;
		}
		
		/* 设置fd为非阻塞模式，执行select*/
		set_noblock(sock_fd);
		maxsock = sock_fd;

		// timeout setting
		tv.tv_sec = 30;
		tv.tv_usec = 0;

		// initialize file descriptor set
		FD_ZERO(&read_fds);
		FD_SET(sock_fd, &read_fds);

		hb_print(LOG_DEBUG, " select data !");
		ret = select(maxsock + 1, &read_fds, NULL, NULL, &tv);
		if (ret < 0) {
			hb_print(LOG_ERR, "[Fail] create select !");
			break;
		} else if (ret == 0) {
			hb_print(LOG_INFO, "select timeout!");
			continue;
		}

		// check whether a new connection comes
		if (FD_ISSET(sock_fd, &read_fds)) {
			if (net_recv_msg(hbrc) < 0) {
				debug(LOG_ERR, "[ECHO -> CLEAN] session have closed !");
				G.recvThread.pause_flag = 1;
				hbrc->hbrc_sm = HBRC_CLEAN;
			}	
			hb_print(LOG_DEBUG, " complete one recv data !");
		}
	}
#if 0
    if(!hbrc->activeRecvFlag)
    {
		hb_print(LOG_ERR, "[Fail] create select !");
    }
#endif

}


static int clean_hbrc(struct heartbeat_route_client* hbrc)
{
	/* init firest hbs */
	hbrc->sendsn = 0;
	hbrc->hbrc_sockfd = 0;
	hbrc->session_client_key = 0;
	hbrc->session_server_key = 0;

	if(hbrc->gbuf) {
		free(hbrc->gbuf);
	}
	hbrc->gbuf = NULL;
	hbrc->dataLen = 0;
	hbrc->maxLen = 0;
}

int main(int argc, char **argv)
{
	int c,ret;
	void *status;
	struct heartbeat_route_client *hbrc;	

	//初始化必要的资源	
	if( init_resource() < 0 ){
		hb_print(LOG_ERR, " init_resource fail !");
		return -1;	
	}	
	init_signals();

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

	hbrc->hbrc_sm = HBRC_INIT;

	while(1){
		if ( HBRC_INIT == hbrc->hbrc_sm ){
			if ( search_hbs(hbrc) <= 0 ){
				debug(LOG_ERR, "[INIT -> IDLE] Failed to connect all heartbeat server!");
				hbrc->hbrc_sm = HBRC_IDLE;
				continue;
			}
			debug(LOG_ERR, "[INIT -> CHANLLENGE] ");
			hbrc->hbrc_sm = HBRC_CHANLLENGE;
		}
		else if ( HBRC_IDLE == hbrc->hbrc_sm ) {
			//sleep(hbrc->hbrc_conf.noecho_interval);
			sleep(10);
			debug(LOG_ERR, "[IDLE -> INIT] rest for %d(s), connect heartbeat server!",hbrc->hbrc_conf.noecho_interval);
			hbrc->hbrc_sm = HBRC_INIT;
		}
		else if ( HBRC_CHANLLENGE == hbrc->hbrc_sm ) {
			if(G.echoThread.echo_thpid == 0 ){
				debug(LOG_INFO, "Creation of thread_echo!");
				ret = pthread_create(&G.echoThread.echo_thpid, NULL, (void *)thread_echo, hbrc);
				if (ret != 0) {
					debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_echo)!");
				}
			}
			G.echoThread.pause_flag = 0;

			if(G.recvThread.recv_thpid == 0 ){
				debug(LOG_INFO, "Creation of thread_recv!");
				ret = pthread_create(&G.recvThread.recv_thpid, NULL, (void *)thread_recv, hbrc);
				if (ret != 0) {
					debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_recv)!");
				}
			}
			G.recvThread.pause_flag = 0;

#if 0				
			debug(LOG_INFO, "Creation of thread_dispatch!");
			ret = pthread_create(&G.dispatchThread.dispatch_thpid, NULL, (void *)thread_dispatch, NULL);
			if (ret != 0) {
				debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_dispatch)!");
			}
#endif
			debug(LOG_ERR, "[CHANLLENGE -> ECHO] ");
			hbrc->hbrc_sm = HBRC_ECHO;
		}
		else if ( HBRC_ECHO == hbrc->hbrc_sm ) {
			sleep(30);
		}		
		else if ( HBRC_CLEAN == hbrc->hbrc_sm ) {
			G.echoThread.pause_flag = 1;
			G.recvThread.pause_flag = 1;
			clean_hbrc(hbrc);
			debug(LOG_ERR, "[CLEAN -> INIT] Pause echo thread and recv thread,reinit!");
			hbrc->hbrc_sm = HBRC_INIT;
		}
		
	}
	

#if 0
	main_debug();
#else

#endif

exit:
	return 0;
}
