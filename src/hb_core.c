#include "protype.h"
#include "des.h"
#include "xorcode.h"
#include "hb_core.h"
#include "udpserver.h"


extern struct glob_arg G;

struct echo_thread g_echoThread;
struct recv_thread g_recvThread;
struct udp_thread g_udpThread;

/* 轮询心跳服务器，如果全部失败，返回0*/
int search_hbs(struct heartbeat_route_client *hbrc)
{
	int i=0;
	int conectFlag = 0;
	struct hbc_conf conf = hbrc->hbrc_conf;

	if(!hbrc->hbs_count) {
		hb_print(LOG_INFO,"There is no heartbeat server!");
	}
	
	for( i=0;i<hbrc->hbs_count;i++) {
		struct hb_server* hbs;
		int clientfd;
		unsigned char de_msgstr[256] = {0};

		hbs = hbrc->hbs_head[i];
		hb_print(LOG_INFO,"try to connect heartbeat server(%s:%d)",inet_ntoa(hbs->hbs_ip),hbs->hbs_port);
		
		/* hb_connect可判断出服务器是否可连接 */
		if ((clientfd = hb_connect(inet_ntoa(hbs->hbs_ip),hbs->hbs_port)) == -1) {
			/*Connect HeartBeat Fail!*/
			sleep(5);
			continue;
		}

		hbrc->hbrc_sockfd = clientfd;
		
		net_challange(hbrc);
		
		TCHALRESP  Rchal_respmsg;
		TCHALRESP  *pReq = &Rchal_respmsg;
		THDR hdr;
		THDR *pHdr = &hdr;
		
		if (net_recv_challage_msg(hbrc,pHdr,pReq) < 0){
			continue;
		}

		u32_t* pchage = (u32_t *)&Rchal_respmsg.key;
		hbrc->session_server_key = *pchage;
		hbrc->current_hbs = hbs;

		print_chalresp(pHdr,pReq);
		conectFlag = 1;
		break;
	}

	return conectFlag;

}

int dispatch_notify(struct heartbeat_route_client* hbrc, char *pBuff)
{

    THDR *pHdr;
    pHdr = (THDR *)pBuff;

#if CVNWARE
	hb_print(LOG_INFO,"[CVNWARE] dispatch nofity,inform tr069!");
	HEARTBEAT_EventSend();
#endif

#if MTK
	hb_print(LOG_INFO,"[MTK] dispatch nofity,inform tr069!");
	system("kill -USR2 `ps|grep cwmpd|grep -v grep|awk -F' ' '{print $1}'|sed -n 1p`");
#endif

#if 0
    TNOTIFYRESP notifyRespMsg;
    memset(&notifyRespMsg, 0, sizeof(notifyRespMsg));
	clientSn = pHdr->sn;
    notifyRespMsg.returnSn = clientSn;
    notifyRespMsg.returnCode = NOF_OK;
    net_notify(hbrc, &notifyRespMsg);
#else
	net_notify(hbrc);
#endif
    return 1;
}

void thread_echo(void *arg)
{
	struct heartbeat_route_client* hbrc = (struct heartbeat_route_client*)arg;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec timeout;
	
	while (1) {
		/* Sleep for config.crondinterval seconds... */
		//timeout.tv_sec = time(NULL) + hbrc->hbrc_conf.echo_interval;
		timeout.tv_sec = time(NULL) + 20;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		
		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);

		if(g_echoThread.pause_flag) {
			continue;
		}

		debug(LOG_INFO, "last_reqsn(%d) last_respsn(%d)",hbrc->last_req_echosn,hbrc->last_resp_echosn);
		if ( hbrc->last_req_echosn > hbrc->last_resp_echosn ) {
			hbrc->lost_echo_count++;				
		} else if ( hbrc->last_req_echosn == hbrc->last_resp_echosn ) {
			hbrc->lost_echo_count = 0;
		} else{
			debug(LOG_ERR, "last_req_echosn <  last_resp_echosn ??????? ");
		}
		
		/* 如果心跳包丢失超过3个，表示网关上行数据出现了问题(比如中间路由设备发出rst报文【定向3G网卡】)，心跳路由客户端状态变成清理状态。 */
		if ( hbrc->lost_echo_count > 3 ) {
			//debug(LOG_ERR, "[ECHO -> CLEAN] echo responce timeout !");
			hb_log(LOG_ERR, "[ECHO -> CLEAN] echo responce timeout !");
			g_echoThread.pause_flag = 1;
			hbrc->hbrc_sm = HBRC_CLEAN;				
		}
		net_echo(hbrc);
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
		
		if(g_recvThread.pause_flag) {
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

		if (FD_ISSET(sock_fd, &read_fds)) {
			/* 当返回值小于0的时候，只能表示服务器被关闭，如果是网关上行不通，则不能检测出来 */
			if (net_recv_msg(hbrc) < 0) {
				//debug(LOG_ERR, "[ECHO -> CLEAN] heartbeat server session have closed !");
				hb_log(LOG_ERR, "[ECHO -> CLEAN] heartbeat server session have closed !");
				g_recvThread.pause_flag = 1;
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


int process_ipc_msg(ipc_udp_server_st *ipcServ)
{
	int udpfd;
	char mesg[MAXLINE];
	socklen_t	len;
	ipc_udp_client_st *ipCli;
	struct heartbeat_route_client *hbrc = ipcServ->priv_data;
	struct hbc_ipc *pHbcIpc = hbrc->hbc_ipc;

	if(g_udpThread.pause_flag) {
		return 0;
	}

	udpfd = ipcServ->listenfd;

#if 0

	ipCli = (ipc_udp_client_st *)malloc(sizeof(ipc_udp_client_st));
	bzero(ipCli,sizeof(ipc_udp_client_st));
	ipCli->recvMsg = (char *)malloc(MAXLINE*sizeof(char));
	memset(ipCli->recvMsg,0,MAXLINE*sizeof(char));
	ipCli->ipcServ = ipcServ;
	
	len = sizeof(ipCli->cliAddr);
	ipCli->recvMsgLen = net_recvfrom(udpfd, ipCli->recvMsg, MAXLINE, 0, (struct sockaddr*)&ipCli->cliAddr, &len);

	printf("ipCli->recvMsg(%d)(%s)\n",ipCli->recvMsgLen,ipCli->recvMsg);

	/*  当前udp只处理ipc消息，调用錭all_ipchelper触发ipc消息解析  */
	if (call_ipchelper(ipCli) < 0) {
		hb_print(LOG_ERR,"parse json udp packet error!");
		delete_ipcli(ipCli);
		return -1;
	}
#endif

	pHbcIpc->recvMsg = (char *)malloc(MAXLINE*sizeof(char));
	memset(pHbcIpc->recvMsg,0,MAXLINE*sizeof(char));
	len = sizeof(pHbcIpc->cliAddr);
	pHbcIpc->recvMsgLen = net_recvfrom(udpfd, pHbcIpc->recvMsg, MAXLINE, 0, (struct sockaddr*)&pHbcIpc->cliAddr, &len);

	if(pHbcIpc->parse_ipc_msg(pHbcIpc) < 0) {
		hb_print(LOG_ERR,"parse ipc msg error!");
		clean_hbc_ipc(pHbcIpc);
		return -1;
	}
		
	pHbcIpc->dispatch_ipc_msg(pHbcIpc);


#if 0
	ipCli->sendMsg = strdup(ipCli->recvMsg);
	ipCli->sendMsgLen = ipCli->recvMsgLen;
	printf("ipCli->sendMsg(%d)(%s)\n",ipCli->sendMsgLen,ipCli->sendMsg);
	net_sendto(ipCli->listenfd, ipCli->sendMsg, ipCli->sendMsgLen, 0, (struct sockaddr*) &ipCli->cliAddr, len);
#endif
	//delete_ipcli(ipCli);
	clean_hbc_ipc(pHbcIpc);
	return 0;
}


void thread_udp_server(void *arg)
{
	struct heartbeat_route_client* hbrc = (struct heartbeat_route_client*)arg;
	ipc_udp_server_st *ipcServ;

	ipcServ = get_udp_server(10400);
	ipcServ->priv_data = (void *)hbrc;
	ipcServ->recv_msg = process_ipc_msg;
	start_recv_msg(ipcServ);
}

static int init_default_hbc_config(struct hbc_conf *conf)
{
	conf->echo_interval = 20;
	conf->retry_count = 3;
	conf->retry_interval = 30;
	conf->noecho_interval = 60;
}


int init_hbrc(struct heartbeat_route_client** hbrcp)
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
	hbrc->recvsn = 0;
	hbrc->hbrc_sockfd = 0;
	hbrc->session_client_key = 0;
	hbrc->session_server_key = 0;

	hbrc->last_req_echosn = 0;
	hbrc->last_resp_echosn = 0;
	hbrc->lost_echo_count = 0;

	/* recv buff*/
	hbrc->gbuf = NULL;
	hbrc->dataLen = 0;
	hbrc->maxLen = 0;

	/*function*/
	hbrc->chall_encode = des_encode;
	hbrc->chall_decode = des_decode;
	hbrc->msg_encode = XORencode;
	hbrc->msg_decode = XORencode;

	/* init hbs  */
	hbrc->hbs_count = 0;
	hbrc->hbs_head = (struct hb_server **)malloc(MAX_HB_COUNT*sizeof(struct hb_server *));

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

#if x86
	char emac_src[16] = "112233005566";
	strncpy(emac,emac_src,strlen(emac_src));
#endif


	hb_print(LOG_INFO,"############ emac = %s",emac);
	sscanf(emac,"%02x%02x%02x%02x%02x%02x",
		&hbrc->equipmentSn[0],&hbrc->equipmentSn[1],&hbrc->equipmentSn[2],
		&hbrc->equipmentSn[3],&hbrc->equipmentSn[4],&hbrc->equipmentSn[5]); 

	return 0;
}

static int clean_hbrc(struct heartbeat_route_client* hbrc)
{
	/* init firest hbs */
	hbrc->sendsn = 0;
	hbrc->recvsn = 0;
	hbrc->hbrc_sockfd = 0;
	hbrc->session_client_key = 0;
	hbrc->session_server_key = 0;

	hbrc->last_req_echosn = 0;
	hbrc->last_resp_echosn = 0;
	hbrc->lost_echo_count = 0;

	if(hbrc->gbuf) {
		free(hbrc->gbuf);
	}
	hbrc->gbuf = NULL;
	hbrc->dataLen = 0;
	hbrc->maxLen = 0;
}


int hb_do_process(struct heartbeat_route_client* hbrc)
{
	hbrc->hbrc_sm = HBRC_INIT;
	int ret;

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
			if(g_echoThread.echo_thpid == 0 ){
				debug(LOG_INFO, "Creation of thread_echo!");
				ret = pthread_create(&g_echoThread.echo_thpid, NULL, (void *)thread_echo, hbrc);
				if (ret != 0) {
					debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_echo)!");
				}
			}
			g_echoThread.pause_flag = 0;

			if(g_recvThread.recv_thpid == 0 ){
				debug(LOG_INFO, "Creation of thread_recv!");
				ret = pthread_create(&g_recvThread.recv_thpid, NULL, (void *)thread_recv, hbrc);
				if (ret != 0) {
					debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_recv)!");
				}
			}
			g_recvThread.pause_flag = 0;

			if(g_udpThread.udpserver_thpid == 0 ){
				debug(LOG_ERR, "%s : Creation of thread_udp_server!",__FUNCTION__);
				ret = pthread_create(&g_udpThread.udpserver_thpid, NULL, (void *)thread_udp_server, hbrc);
				if (ret != 0) {
					debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_udp_server)!");
				
				}
				pthread_detach(g_udpThread.udpserver_thpid);
			}
			g_udpThread.pause_flag = 0;

			debug(LOG_ERR, "[CHANLLENGE -> ECHO] ");
			hbrc->hbrc_sm = HBRC_ECHO;
		}
		else if ( HBRC_ECHO == hbrc->hbrc_sm ) {
			sleep(30);
		}		
		else if ( HBRC_CLEAN == hbrc->hbrc_sm ) {
			g_echoThread.pause_flag = 1;
			g_recvThread.pause_flag = 1;
			g_udpThread.pause_flag = 1;
			clean_hbrc(hbrc);
			debug(LOG_ERR, "[CLEAN -> INIT] Pause echo thread and recv thread,reinit!");
			hbrc->hbrc_sm = HBRC_INIT;
		}
		
	}

}


