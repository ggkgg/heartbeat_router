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


static void print_hdr(THDR  *tHdr)
{
	hb_print(LOG_ERR,"[hdr] : flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext);
}


static void print_chalreq(THDR  *tHdr, TCHALREQ  *chalReq)
{

	hb_print(LOG_ERR,"[challange resquest] -->> [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{magic(0x%08x),key(%d),res(%02x%02x%02x%02x%02x%02x%02x%02x)}", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		chalReq->magic,
		chalReq->key,
		chalReq->u8res[0],chalReq->u8res[1],chalReq->u8res[2],chalReq->u8res[3],
		chalReq->u8res[4],chalReq->u8res[5],chalReq->u8res[6],chalReq->u8res[7]);

#if 0
	hb_print(LOG_ERR,"[challange resquest] -->> : magic(0x%08x),key(0x%08x),res(%02x%02x%02x%02x%02x%02x%02x%02x)", 
		chalReq->magic,
		chalReq->key,
		chalReq->u8res[0],chalReq->u8res[1],chalReq->u8res[2],chalReq->u8res[3],
		chalReq->u8res[4],chalReq->u8res[5],chalReq->u8res[6],chalReq->u8res[7]);

	unsigned char* magic = (unsigned char*)&chalReq->magic;
	hb_print(LOG_ERR,"[challange resquest] -->> : magic(%02x%02x%02x%02x),key(%08x),res(0x%02x%02x%02x%02x%02x%02x%02x%02x)", 
		magic[0],magic[1],magic[2],magic[3],
		chalReq->key,
		chalReq->u8res[0],chalReq->u8res[1],chalReq->u8res[2],chalReq->u8res[3],
		chalReq->u8res[4],chalReq->u8res[5],chalReq->u8res[6],chalReq->u8res[7]);
#endif

}


static void print_chalresp(THDR  *tHdr, TCHALRESP  *chalResp)
{
		hb_print(LOG_ERR,"<<-- [challange response] [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{sn(%d),magic(0x%08x),key(%d),res(0x%02x%02x%02x%02x%02x%02x)}", 
			tHdr->flag,
			tHdr->pktlen,
			tHdr->version,
			tHdr->pktType,
			tHdr->sn,
			tHdr->ext,
			chalResp->client_sn,
			(u32_t)chalResp->magic,
			//chalResp->magic[0],chalResp->magic[1],chalResp->magic[2],chalResp->magic[3],
			(u32_t)chalResp->key,
			//chalResp->key[0],chalResp->key[1],chalResp->key[2],chalResp->key[3],
			chalResp->u8res[0],chalResp->u8res[1],chalResp->u8res[2],chalResp->u8res[3],chalResp->u8res[4],chalResp->u8res[5]);
#if 0
	hb_print(LOG_ERR,"<<-- [challange response]: sn(%d),magic(0x%02x%02x%02x%02x),key(0x%02x%02x%02x%02x),res(0x%02x%02x%02x%02x%02x%02x)", 
		chalResp->client_sn,
		chalResp->magic[0],chalResp->magic[1],chalResp->magic[2],chalResp->magic[3],
		chalResp->key[0],chalResp->key[1],chalResp->key[2],chalResp->key[3],
		chalResp->u8res[0],chalResp->u8res[1],chalResp->u8res[2],chalResp->u8res[3],chalResp->u8res[4],chalResp->u8res[5]);
#endif
}


static void print_echoreq(THDR  *tHdr, TECHOREQ  *echoReq)
{
	hb_print(LOG_ERR,"[echo resquest] -->> [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{equipmentSn(0x%02x%02x%02x%02x%02x%02x)}", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		(unsigned char)echoReq->equipmentSn[0],(unsigned char)echoReq->equipmentSn[1],(unsigned char)echoReq->equipmentSn[2],
		(unsigned char)echoReq->equipmentSn[3],(unsigned char)echoReq->equipmentSn[2],(unsigned char)echoReq->equipmentSn[5]);

#if 0
	hb_print(LOG_ERR,"[echo resquest] -->> : equipmentSn(0x%02x%02x%02x%02x%02x%02x)", 
		(unsigned char)echoReq->equipmentSn[0],(unsigned char)echoReq->equipmentSn[1],(unsigned char)echoReq->equipmentSn[2],
		(unsigned char)echoReq->equipmentSn[3],(unsigned char)echoReq->equipmentSn[2],(unsigned char)echoReq->equipmentSn[5]);
#endif
}


static void print_echoresp(THDR  *tHdr, TECHORESP *echoResp)
{
	hb_print(LOG_ERR,"<<-- [echo response] [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{client_sn(%d)}", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		echoResp->client_sn);
#if 0
	hb_print(LOG_ERR,"<<-- [echo response]: client_sn(%d)", 
		echoResp->client_sn);
#endif
}


static void print_notifyreq(THDR  *tHdr,TNOTIFYREQ  *notifyReq)
{
	hb_print(LOG_ERR,"<<-- [notify resquest] [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{equipmentSn(0x%c%c%c%c%c%c), command(%d), sendtime(%d)}", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		notifyReq->equipmentSn[0],notifyReq->equipmentSn[1],notifyReq->equipmentSn[2],
		notifyReq->equipmentSn[3],notifyReq->equipmentSn[4],notifyReq->equipmentSn[5],
		notifyReq->command,notifyReq->sendTime);

#if 0
	hb_print(LOG_ERR,"[notify resquest] -->> : equipmentSn(0x%c%c%c%c%c%c), command(%d), sendtime(%d)", 
		notifyReq->equipmentSn[0],notifyReq->equipmentSn[1],notifyReq->equipmentSn[2],
		notifyReq->equipmentSn[3],notifyReq->equipmentSn[4],notifyReq->equipmentSn[5],
		notifyReq->command,notifyReq->sendTime);
#endif
}


static void print_notifyresp(THDR  *tHdr,TNOTIFYRESP* notifyResp)
{
	hb_print(LOG_ERR,"[notify response] -->> [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{returnSn(%d), returnCode(%d)}", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		notifyResp->returnSn,notifyResp->returnCode);
#if 0
	hb_print(LOG_ERR,"<<-- [notify response]: returnSn(%d), returnCode(%d)", 
		notifyResp->returnSn,notifyResp->returnCode);
#endif
}


int do_challange(struct heartbeat_route_client *hbrc)
{
	int fd = hbrc->hbrc_sockfd;

    if(fd <= 0)
    {
        printf("%s error fd = %d\n", __FUNCTION__, fd);
        return -1;
    }

    THDR chal_header;
    THDR *pHdr = &chal_header;

    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->pktlen = sizeof(TCHALREQ);
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_CHALLENGE_REQUEST;
    pHdr->sn = hbrc->sendsn++;

    TCHALREQ chal_reqmsg;
    TCHALREQ *pReq = &chal_reqmsg;

    pReq->magic = PKT_CHALLENGE_MAGIC;
    //pReq->magic = htonl(PKT_CHALLENGE_MAGIC);
    pReq->key = (u32_t)time(NULL);
	hbrc->session_client_key = pReq->key;
		
    memset(pReq->u8res, 0x08, sizeof(pReq->u8res));

    unsigned char deschal[64];
    memset(deschal, 0, sizeof(deschal));

    int bytes = sizeof(TCHALREQ);
	//print_hdr(pHdr);
	print_chalreq(pHdr,pReq);

    des_encode((const void *)pReq, deschal, CHANLLENGE_KEY, bytes);
    pHdr->pktlen = bytes;
    send(fd, pHdr, sizeof(THDR), 0);
    send(fd, deschal, bytes, 0);

    return 1;
}

#if 0
int do_echofun(int fd, char* equipmentSn)
{
    THDR echo_hdr;
    THDR *pHdr = &echo_hdr;

    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->pktlen = sizeof(TECHOREQ);
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_ECHO_REQUEST;
    pHdr->sn = sendsn;

    TECHOREQ echo_reqmsg;
    TECHOREQ *pReq = &echo_reqmsg;

    strncpy(pReq->equipmentSn, equipmentSn, 6);
	print_hdr(pHdr);
	print_echoreq(&echo_reqmsg);
	
    TECHOREQ secho_reqmsg;
    int bytes = sizeof(TECHOREQ);

    XORencode(&echo_reqmsg, &secho_reqmsg, session_client_key, bytes);

    send(fd, pHdr, sizeof(THDR), 0);
    send(fd, &secho_reqmsg, bytes, 0);
    return 1;
}


static int main_debug()
{
#if DEBUG_DES
#ifdef CRYTO_DES
		char str[32] = "hello world";
		int str_len = strlen(str);
		unsigned char en_str[32] = {0};
		unsigned char de_str[32] = {0};
		
		des_encode((const void *)str, en_str, CHANLLENGE_KEY, str_len);
	
		hb_print(LOG_INFO, "%s		(%d) -> %s	  (%d) ",str,str_len,en_str,strlen(en_str));
	
		des_decode((const void *)en_str, de_str, CHANLLENGE_KEY, strlen(en_str));
	
		hb_print(LOG_INFO, "%s		(%d) -> %s	  (%d) ",en_str,strlen(en_str),de_str,strlen(de_str));	
	
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
		}£»
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
	
		//do_challange(clientfd);
		
		if(-1 == (recbytes = read(clientfd, revBuffer, 1024))){
		  hb_print(LOG_ERR,"read data fail !");
		  close(clientfd);
		  return -1;
		}
		
		THDR *pHdr;
		pHdr = (THDR *)revBuffer;
		int datalen = sizeof(THDR) + pHdr->pktlen;
	
		
		TCHALRESP  Rchal_respmsg;
		TCHALRESP  *pReq = &Rchal_respmsg;
		des_decode((void *)(revBuffer + sizeof(THDR)), pReq, CHANLLENGE_KEY, sizeof(*pReq));
		u32_t* pchage = (u32_t *)&Rchal_respmsg.key;
		session_server_key = *pchage;
		
		print_hdr(pHdr);
		print_chalresp(pReq);
		
#endif
	
#if DEBUG_ECHO
		//char equipmentSn[6] = {0x88,0x90,0x22,0x33,0x44,0x55};
		char equipmentSn[6]= "112233";
		do_echofun(clientfd,equipmentSn);
	
		sleep(1);
		memset(revBuffer,0,1024);
		if(-1 == (recbytes = read(clientfd, revBuffer, 1024))){
		  hb_print(LOG_ERR,"read data fail !");
		  close(clientfd);
		  return -1;
		}
		
		hb_print(LOG_INFO,"recbytes(%d)",recbytes);
		pHdr = (THDR *)revBuffer;
		TECHORESP Recho_reqmsg;
		hb_print(LOG_INFO,"session_client_key = %d",session_client_key);
		hb_print(LOG_INFO,"session_server_key = %d",session_server_key);
		XORencode(revBuffer + sizeof(THDR), &Recho_reqmsg, session_server_key, pHdr->pktlen);
		print_hdr(pHdr);
		print_echoresq(&Recho_reqmsg);
	
#endif
	
#if DEBUG_XOR
	
		//TECHORESP echoRespMsg;
		//TECHORESP *pechoRespMsg = &echoRespMsg;
		//pechoRespMsg->client_sn = sendsn;
	
	
		//char strXor[16]="10002";
		u16_t strXor = sendsn;
		char en_strXor[16]={0};
		//char de_strXor[16]={0};
		u16_t de_strXor;
	
		XORencode(&strXor, en_strXor, session_server_key, 2);
		hb_print(LOG_INFO,"%d  -> %s  (%d)",strXor,en_strXor,strlen(en_strXor));
		XORencode(en_strXor, &de_strXor, session_server_key, 2);
		hb_print(LOG_INFO,"%s  (%d) -> %d",en_strXor,strlen(en_strXor),de_strXor);
	
#endif
	
	
#if DEBUG_NOTIFY
		memset(revBuffer,0,1024);
		if(-1 == (recbytes = read(clientfd, revBuffer, 1024))){
		  hb_print(LOG_ERR,"read data fail !");
		  close(clientfd);
		  return -1;
		}
	
		hb_print(LOG_INFO,"notify? recbytes(%d)",recbytes);
		pHdr = (THDR *)revBuffer;
		TNOTIFYREQ Notify_reqmsg;
		XORencode(revBuffer + sizeof(THDR), &Notify_reqmsg, session_server_key, pHdr->pktlen);
		print_hdr(pHdr);
		print_notifyresq(&Notify_reqmsg);
	
	
#endif
		close(clientfd);


}
#endif


int set_noblock(int sClient)
{
    int opts;

    opts = fcntl(sClient, F_GETFL);

    if(opts < 0)
    {
        perror("fcntl(sock,GETFL)");
        exit(1);
    }

    opts = opts | O_NONBLOCK;

    if(fcntl(sClient, F_SETFL, opts) < 0)
    {
        perror("fcntl(sock, SETFL, opts)");
        exit(1);
    }

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
	
	hbrc->hbrc_conf.echo_interval = Cfg.ConnectInterval;
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

#if 0
	struct in_addr tip;
	inet_aton("127.0.0.1",&tip);
	hb_print(LOG_INFO, " 111 tip (%s)",inet_ntoa(tip));
	
	inet_aton("www.baidu.com",&tip);
	hb_print(LOG_INFO, " 2222 tip (%s)",inet_ntoa(tip));

	inet_aton("255.255.255.256",&tip);
	hb_print(LOG_INFO, " 3333 tip (%s)",inet_ntoa(tip));

	inet_aton("255.255.255.255",&tip);
	hb_print(LOG_INFO, " 4444 tip (%s)",inet_ntoa(tip));

	
#endif

}
#endif

static int init_default_hbc_config(struct hbc_conf *conf)
{
	int i = 0;

	conf->echo_interval = 20;
	conf->retry_count = 3;
	conf->retry_interval = 30;
	conf->noecho_interval = 60;
	/*
	for( i=0;i<3;i++ ){
		inet_aton("0",&conf->default_hb_ip[i]);
	}
	*/
}

static int init_hbrc(struct heartbeat_route_client** hbrcp)
{
	struct heartbeat_route_client *hbrc;
	struct hb_server* hbs;
	struct hbc_conf* hbcConf;
	
	*hbrcp = (struct heartbeat_route_client *)malloc(sizeof(struct heartbeat_route_client));
	hbrc = *hbrcp;
	hbrc->hbrc_sm = HBRC_INVALID;


	/* connect conf*/
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


	hbrc->hbrc_sm = HBRC_STRAT;

	
	return 0;
}

/* ÂÖÑ¯ÐÄÌø·þÎñÆ÷£¬Èç¹ûÈ«²¿Ê§°Ü£¬·µ»Ø-1*/
static int net_challage(struct heartbeat_route_client *hbrc)
{
	int i=0;
	int conectFlag = 0;
	struct hbc_conf conf = hbrc->hbrc_conf;

	for( i=0;i<hbrc->hbs_count;i++) {
		struct hb_server* hbs;
		int clientfd;
		char revBuffer[1024] = {0};
		int recbytes;
		unsigned char de_msgstr[256] = {0};

		hbs = hbrc->hbs_head[i];
		if ((clientfd = hb_connect(inet_ntoa(hbs->hbs_ip),hbs->hbs_port)) < 0) {
			/*Connect HeartBeat Fail!*/
			sleep(5);
			continue;
		}

		hbrc->hbrc_sockfd = clientfd;
		
		do_challange(hbrc);
 
		if(-1 == (recbytes = read(clientfd, revBuffer, 1024))){
		  hb_print(LOG_ERR,"read data fail !");
		  close(clientfd);
		  return -1;
		}
		
		THDR *pHdr;
		pHdr = (THDR *)revBuffer;
		int datalen = sizeof(THDR) + pHdr->pktlen;
	
		
		TCHALRESP  Rchal_respmsg;
		TCHALRESP  *pReq = &Rchal_respmsg;
		des_decode((void *)(revBuffer + sizeof(THDR)), pReq, CHANLLENGE_KEY, sizeof(*pReq));
		u32_t* pchage = (u32_t *)&Rchal_respmsg.key;
		hbrc->session_server_key = *pchage;
		hbrc->current_hbs = hbs;
		
		//print_hdr(pHdr);
		print_chalresp(pHdr,pReq);
		conectFlag = 1;
		break;

	}

	return conectFlag;

}


static int net_echo(struct heartbeat_route_client *hbrc)
{
   // THDR chal_header;
    //THDR *pHdr = &chal_header;
	//char equipmentSn[6] = {0x88,0x90,0x22,0x33,0x44,0x55};
	
	char equipmentSn[6]= "112233";
    THDR echo_hdr;
    THDR *pHdr = &echo_hdr;

    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->pktlen = sizeof(TECHOREQ);
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_ECHO_REQUEST;
    pHdr->sn = hbrc->sendsn++;

    TECHOREQ echo_reqmsg;
    TECHOREQ *pReq = &echo_reqmsg;

    //strncpy(pReq->equipmentSn, equipmentSn, 6);
    memcpy(pReq->equipmentSn, equipmentSn, 6);
	//print_hdr(pHdr);
	print_echoreq(pHdr,&echo_reqmsg);
	
    TECHOREQ secho_reqmsg;
    int bytes = sizeof(TECHOREQ);

    XORencode(&echo_reqmsg, &secho_reqmsg, hbrc->session_client_key, bytes);

    send(hbrc->hbrc_sockfd, pHdr, sizeof(THDR), 0);
    send(hbrc->hbrc_sockfd, &secho_reqmsg, bytes, 0);
    return 1;

#if 0
	sleep(1);
	memset(revBuffer,0,1024);
	if(-1 == (recbytes = read(clientfd, revBuffer, 1024))){
	  hb_print(LOG_ERR,"read data fail !");
	  close(clientfd);
	  return -1;
	}
	
	hb_print(LOG_INFO,"recbytes(%d)",recbytes);
	pHdr = (THDR *)revBuffer;
	TECHORESP Recho_reqmsg;
	hb_print(LOG_INFO,"session_client_key = %d",session_client_key);
	hb_print(LOG_INFO,"session_server_key = %d",session_server_key);
	XORencode(revBuffer + sizeof(THDR), &Recho_reqmsg, session_server_key, pHdr->pktlen);
	print_hdr(pHdr);
	print_echoresq(&Recho_reqmsg);
#endif
}


static int net_notify(struct heartbeat_route_client *hbrc, struct notify_response* pnotifyRespMsg)
{
	THDR notifyRespHdr;
	THDR *pHdr = &notifyRespHdr;
	memset(pHdr, 0, sizeof(*pHdr));

	pHdr->flag = PKT_HDR_MAGIC;
	pHdr->version = PKT_VERSION;
	pHdr->pktType = PKT_NOTIFY_RESPONSE;
	pHdr->sn = hbrc->sendsn++;

	TNOTIFYRESP  sendNotifyRespMsg;
	pHdr->pktlen = sizeof(sendNotifyRespMsg);

	print_notifyresp(pHdr,pnotifyRespMsg);

	XORencode(pnotifyRespMsg, &sendNotifyRespMsg, hbrc->session_client_key, pHdr->pktlen);

	send(hbrc->hbrc_sockfd, pHdr, sizeof(THDR), 0);
	send(hbrc->hbrc_sockfd, &sendNotifyRespMsg, pHdr->pktlen, 0);


}


int dispatch_notify(struct heartbeat_route_client* hbrc, char *pBuff)
{

    THDR *pHdr;
    pHdr = (THDR *)pBuff;
    int clientSn = 0;

#if CVNWARE
	HEARTBEAT_EventSend();
#endif

    TNOTIFYRESP notifyRespMsg;
    memset(&notifyRespMsg, 0, sizeof(notifyRespMsg));
	clientSn = pHdr->sn;
    notifyRespMsg.returnSn = clientSn;
    notifyRespMsg.returnCode = NOF_OK;
    net_notify(hbrc, &notifyRespMsg);

    return 1;
}



int proc_echoresp(struct heartbeat_route_client* hbrc, char *pBuff)
{
	THDR* pHdr;
	TECHORESP Recho_reqmsg;

	pHdr = (THDR *)pBuff;
	XORencode(pBuff + sizeof(THDR), &Recho_reqmsg, hbrc->session_server_key, pHdr->pktlen);
	//print_hdr(pHdr);
	print_echoresp(pHdr,&Recho_reqmsg);

}

int proc_notifyreq(struct heartbeat_route_client* hbrc, char *pBuff)
{
	THDR* pHdr;
	TECHORESP Recho_reqmsg;

	pHdr = (THDR *)pBuff;
	TNOTIFYREQ Notify_reqmsg;
	XORencode(pBuff + sizeof(THDR), &Notify_reqmsg, hbrc->session_server_key, pHdr->pktlen);
	//print_hdr(pHdr);
	print_notifyreq(pHdr,&Notify_reqmsg);

	dispatch_notify(hbrc,pBuff);


}


int proc_packet(struct heartbeat_route_client* hbrc, char *pBuff, int readLen)
{
    THDR *pHdr;
    pHdr = (THDR *)pBuff;

    /*æœ¬æ¬¡å¤„ç†çš„æ•°æ®é•¿åº¦*/
    int dataLen = sizeof(THDR) + pHdr->pktlen;

    if(pHdr->pktType == PKT_ECHO_RESPONSE)
    {
        proc_echoresp(hbrc, pBuff);
    }
    else if(pHdr->pktType == PKT_NOTIFY_REQUEST)
    {
        proc_notifyreq(hbrc, pBuff);
    }
#if 0
    else if(pHdr->pktType == PKT_NOTIFY_REQUEST)
    {
        recv_notifyreq_fun(fd, pBuff);
    }
    else if(pHdr->pktType == PKT_NOTIFY_RESPONSE)
    {
        recv_notifyresp_fun(fd, pBuff);
    }
#endif
    else
    {
	    hb_print(LOG_ERR, "[Fail] invalid pocket!");
    }
	
    int remainData = readLen - dataLen;

    if(remainData > 0)
    {
        return remainData;
    }
    else
    {
        return 0;
    }

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

int ishdrValid(char *pBuff, u32_t len)
{
    THDR *pHdr;

    if(len < sizeof(THDR))
    {
        return -1;
    }

    pHdr = (THDR *)pBuff;

    unsigned int needlen = sizeof(THDR) + pHdr->pktlen;

    if(len < needlen)
    {
        return -2;
    }

    if(pHdr->flag != PKT_HDR_MAGIC)
    {
        hb_print(LOG_ERR, "recv invalid pkt, recv magic=0x%X, right=0x%X\n", pHdr->flag, PKT_HDR_MAGIC);
        return -3;
    }

    return 1;
}

void * recvMalloc(u32_t len)
{
    void *p = malloc(len);

    if(p == NULL)
    {
        return NULL;
    }
    else
    {
        memset(p, 0, len);
        return p;
    }
}


int recv_from_hbs(struct heartbeat_route_client* hbrc)
{
    char buff[512] = {0};

    char * oldBuff = hbrc->gbuf;
    int dataLen = hbrc->dataLen;
    int maxLen = hbrc->maxLen;

	int fd = hbrc->hbrc_sockfd;


    while(1)
    {
        int len = read(fd, buff, 256);

        if(len < 0)
        {
            buff[0] = 0;
			/* ·Ç×èÈûÄ£Ê½ÏÂ£¬Ã»ÓÐÊý¾Ý·µ»ØEAGAIN£¬Ìø³öÑ­»· 
			hb_print(LOG_ERR, "[Fail] read < 0 bytes ,errno(%d) %s!",errno,strerror(errno));
			*/
            if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
            {
                break;
            }
#if 0
            else
            {
            	hb_print(LOG_ERR, "[Fail] read < 0 bytes ,set activeRecvFlag 0!");
                hbrc->activeRecvFlag = 0;
                return -1;
            }
#endif
        }
		/* µ±·þÎñÆ÷¹Ø±Õ£¬Á´½Ó¶Ï¿ª£¬select»áÁ¢¼´·µ»Ø¿É¶Á£¬readºóµÄlenµÈÓÚ0*/
        else if(len == 0)
        {
			hb_print(LOG_ERR, "[Fail] read = 0 bytes, seesion have closed!");
            buff[len] = 0;
#if 0
            hbrc->activeRecvFlag = true;
#endif
            return -1;
        }

        int totalLen = dataLen + len;

        if(oldBuff == NULL && maxLen == 0)
        {
            oldBuff = (char *)recvMalloc(512);

            if(oldBuff == 0)
            {
#if 0
                hbrc->activeRecvFlag = 0;
#endif
				hb_print(LOG_ERR, "Fail to malloc memory for oldBuff!");
                return -1;
            }

            hbrc->gbuf = oldBuff ;
            hbrc->maxLen = 512;
            maxLen = 512;
        }

        if(totalLen <= maxLen)
        {
            memcpy(oldBuff + dataLen, buff, len);
            dataLen += len;
            hbrc->dataLen = dataLen;
        }
        else
        {
            char *newBuff = (char *)recvMalloc(totalLen);

            if(newBuff == 0)
            {
#if 0
                hbrc->activeRecvFlag = 0;
#endif
				hb_print(LOG_ERR, "Fail to malloc memory for newBuff!");
                return -1;
            }

            hbrc->gbuf = newBuff ;
            hbrc->maxLen = totalLen;
            maxLen = totalLen;

            memcpy(newBuff, oldBuff, dataLen);
            memcpy(newBuff + dataLen, buff, len);

            dataLen += len;
            hbrc->dataLen = dataLen;
            free(oldBuff);
            oldBuff = newBuff;

        }

        char *recvBuff = hbrc->gbuf;

		/* È¡³öÊý¾Ý£¬Íê³ÉÊÂ¼þ·Ö·¢ */
        while(1)
        {
            if(dataLen == 0)
            {
                break;
            }

            int invalidFlag = ishdrValid(recvBuff, dataLen);

            if(invalidFlag < 0 && invalidFlag != -3)
            {
                break;
            }

            if(invalidFlag == -3)
            {
                THDR *pHdr;
                pHdr = (THDR *)recvBuff;
                int needLen = 0;
                needLen = sizeof(THDR) + pHdr->pktlen;
                dataLen = dataLen - needLen;
                memcpy(recvBuff, recvBuff + needLen, dataLen);
                hbrc->dataLen = dataLen;
                continue;
            }

            int remainLen = proc_packet(hbrc, recvBuff, dataLen);

            if(remainLen > 0)
            {
                memcpy(recvBuff, recvBuff + dataLen - remainLen, remainLen);
            }

            dataLen = remainLen;
            hbrc->dataLen = dataLen;
        }
    }	
}

void thread_recv(void *arg)
{
	struct heartbeat_route_client* hbrc = (struct heartbeat_route_client*)arg;
	//struct heartbeat_route_client* hbrc = (struct heartbeat_route_client*)&arg;
#if 0
	int sock_fd = hbrc->hbrc_sockfd;
	struct sockaddr_un clt_addr;
	int clt_len = sizeof(struct sockaddr_un);	
	int ret;

	fd_set read_fds;
	int maxsock;
	struct timeval tv;

	/* ÉèÖÃfdÎª·Ç×èÈûÄ£Ê½£¬Ö´ÐÐselect*/
	set_noblock(sock_fd);
	maxsock = sock_fd;
#endif

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
		
		/* ÉèÖÃfdÎª·Ç×èÈûÄ£Ê½£¬Ö´ÐÐselect*/
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
			if (recv_from_hbs(hbrc) < 0) {
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

	//³õÊ¼»¯±ØÒªµÄ×ÊÔ´	
	if( init_resource() < 0 ){
		hb_print(LOG_ERR, " init_resource fail !");
		return -1;	
	}	
	init_signals();

	init_hbrc(&G.hbrc);
	hbrc = G.hbrc;

	hbrc->hbrc_sm = HBRC_INVALID;
	
	parse_commandline(argc, argv);

	hbrc->hbrc_sm = HBRC_STRAT;
	parse_file(hbrc);
#if CVNWARE
	if(parse_startup(hbrc) < 0) {
		return -1;
	}
#endif

	hbrc->hbrc_sm = HBRC_INIT;

	
	while(1){
		if ( HBRC_INIT == hbrc->hbrc_sm ){
			if ( net_challage(hbrc) <= 0 ){
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
