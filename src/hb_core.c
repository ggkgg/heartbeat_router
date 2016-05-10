#include "hb_core.h"

extern struct glob_arg G;


/* 轮询心跳服务器，如果全部失败，返回-1*/
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
		//char revBuffer[128] = {0};
		//int recbytes,recTolBytes = 0;
		unsigned char de_msgstr[256] = {0};

		hbs = hbrc->hbs_head[i];
		hb_print(LOG_INFO,"try to connect heartbeat server(%s:%d)",inet_ntoa(hbs->hbs_ip),hbs->hbs_port);
		if ((clientfd = hb_connect(inet_ntoa(hbs->hbs_ip),hbs->hbs_port)) == -1) {
			/*Connect HeartBeat Fail!*/
			sleep(5);
			continue;
		}

		hbrc->hbrc_sockfd = clientfd;
		
		net_challange(hbrc);
#if 0
		fd_set read_fds;
		int maxsock;
		struct timeval tv;
		int ret;
		int chanResqLen;

		chanResqLen = sizeof(THDR) + sizeof(TCHALRESP);
		while (recTolBytes < chanResqLen) {
			char revdata[128] = {0};
			maxsock = clientfd;
			// timeout setting
			tv.tv_sec = 5;
			tv.tv_usec = 0;

			// initialize file descriptor set
			FD_ZERO(&read_fds);
			FD_SET(clientfd, &read_fds);
			ret = select(maxsock + 1, &read_fds, NULL, NULL, &tv);
			if (ret < 0) {
				hb_print(LOG_ERR, "[Fail] create select !");
				break;
			} else if (ret == 0) {
				hb_print(LOG_INFO, "select timeout!");
				continue;
			}			
			if (FD_ISSET(clientfd, &read_fds)) {
				recbytes = read(clientfd, revdata, 128);
				memcpy(&revBuffer[recTolBytes],revdata,recbytes);
				recTolBytes += recbytes;
			}
		}



		THDR *pHdr;
		pHdr = (THDR *)revBuffer;
		int datalen = sizeof(THDR) + pHdr->pktlen;	

		TCHALRESP  Rchal_respmsg;
		TCHALRESP  *pReq = &Rchal_respmsg;

		/*pengruofeng debug mips*/
		int j;
		unsigned char *Chaldata = revBuffer + sizeof(THDR);
		printf("EDS cryto data(%d): \n",recTolBytes);
		for(j=0;j<sizeof(TCHALRESP);j++)
			printf("%02x",Chaldata[j]);
		printf("\n");

		des_decode((void *)(revBuffer + sizeof(THDR)), pReq, CHANLLENGE_KEY, sizeof(*pReq));
#else
		TCHALRESP  Rchal_respmsg;
		TCHALRESP  *pReq = &Rchal_respmsg;
		THDR hdr;
		THDR *pHdr = &hdr;
		
		if (net_recv_challage_msg(hbrc,pHdr,pReq) < 0){
			continue;
		}
#endif

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

int dispatch_notify(struct heartbeat_route_client* hbrc, char *pBuff)
{

    THDR *pHdr;
    pHdr = (THDR *)pBuff;

#if CVNWARE
	hb_print(LOG_INFO,"dispatch nofity,inform tr069!");
	HEARTBEAT_EventSend();
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
	//struct heartbeat_route_client* hbrc = (struct heartbeat_route_client*)&arg;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec timeout;
	
	while (1) {
		if(!G.echoThread.pause_flag) {
			debug(LOG_INFO, "echo send sn(%d) last_sn(%d)",hbrc->last_req_echosn,hbrc->last_resp_echosn);
			if ( hbrc->last_req_echosn > hbrc->last_resp_echosn ) {
				hbrc->lost_echo_count++;				
			} else if ( hbrc->last_req_echosn == hbrc->last_resp_echosn ) {
				hbrc->lost_echo_count = 0;
			} else{
				debug(LOG_ERR, "last_req_echosn <  last_resp_echosn ??????? ");
			}
			/* 如果心跳包丢失超过3个，表示网关上行数据出现了问题(比如中间路由设备发出rst报文【定向3G网卡】)，心跳路由客户端状态变成清理状态。 */
			if ( hbrc->lost_echo_count > 3 ) {
				debug(LOG_ERR, "[ECHO -> CLEAN] echo responce timeout !");
				G.echoThread.pause_flag = 1;
				hbrc->hbrc_sm = HBRC_CLEAN;				
			}
			net_echo(hbrc);
		}
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

		if (FD_ISSET(sock_fd, &read_fds)) {
			/* 当返回值小于0的时候，只能表示服务器被关闭，如果是网关上行不通，则不能检测出来 */
			if (net_recv_msg(hbrc) < 0) {
				debug(LOG_ERR, "[ECHO -> CLEAN] heartbeat server session have closed !");
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

void thread_udp_server(void *arg)
{
	udp_server(10400);
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

			if(G.udpThread.udpserver_thpid == 0 ){
				debug(LOG_ERR, "%s : Creation of thread_udp_server check zigbee station !",__FUNCTION__);
				ret = pthread_create(&G.udpThread.udpserver_thpid, NULL, (void *)thread_udp_server, NULL);
				if (ret != 0) {
					debug(LOG_ERR, "FATAL: Failed to create a new thread (thread_recv)!");
				
				}
				pthread_detach(G.udpThread.udpserver_thpid);
			}
			G.udpThread.pause_flag = 0;

			debug(LOG_ERR, "[CHANLLENGE -> ECHO] ");
			hbrc->hbrc_sm = HBRC_ECHO;
		}
		else if ( HBRC_ECHO == hbrc->hbrc_sm ) {
			sleep(30);

#if DEBUG_IPC		
			u32_t vendor = 0x11223344;
			business_report(vendor);
#endif
		}		
		else if ( HBRC_CLEAN == hbrc->hbrc_sm ) {
			G.echoThread.pause_flag = 1;
			G.recvThread.pause_flag = 1;
			G.udpThread.pause_flag = 1;
			clean_hbrc(hbrc);
			debug(LOG_ERR, "[CLEAN -> INIT] Pause echo thread and recv thread,reinit!");
			hbrc->hbrc_sm = HBRC_INIT;
		}
		
	}

}


