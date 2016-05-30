#include "net.h"

extern pthread_mutex_t SEND_MUTEX;

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

#if 1
int hb_connect(char *host, int port)
{
    struct sockaddr_in addr;
    int error = -1, len;
    int ret = -1;	
    int err = 0;
    struct timeval tm;
    fd_set read_set;
    fd_set write_Set;


    int clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if(0 >= clientfd)
    {
        hb_print(LOG_ERR,"socket failed\n");
        return -1;
    }

	set_noblock(clientfd);//设置为非阻塞模式
    
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    ret = connect(clientfd, (struct sockaddr *)&addr, sizeof(addr));
    if (0 == ret)
    {
        //printf("connect to heartbeat server ok");
		hb_log(LOG_INFO, "connect to heartbeat server(%s:$d) ok!\n",host,port);
        return (clientfd);
    }

    tm.tv_sec = 5;
    tm.tv_usec = 0;
    FD_ZERO(&read_set);
    FD_SET(clientfd, &read_set);
    write_Set = read_set;
    ret = select(clientfd+1, &read_set, &write_Set, NULL, &tm);
    if (0 > ret)
    {
        hb_print(LOG_ERR,"select failed\n");
        close(clientfd);
        return (-1);
    }

    if (0 == ret)
    {   
        hb_print(LOG_ERR,"timeout, connect to server failed\n");
        close(clientfd);
        return (-1);
    }

    if (FD_ISSET(clientfd, &read_set) && FD_ISSET(clientfd,  &write_Set)) 
    {
        hb_print(LOG_ERR,"readable and writable, Connect to server failed\n");
        close(clientfd);
        return (-1);
    }

    if (!FD_ISSET(clientfd, &read_set) && FD_ISSET(clientfd,  &write_Set)) 
    {
        hb_print(LOG_INFO,"Unreadable but writable, connect to server OK\n");
		hb_log(LOG_INFO, "connect to heartbeat server(%s:$d) successfully!\n",host,port);
        return (clientfd);
    }

    close(clientfd);
    return (-1);
}
#else 
int hb_connect(char *host, int port)
{
    struct sockaddr_in addr;

    int clientfd = socket(AF_INET, SOCK_STREAM, 0);

    if(clientfd <= 0)
    {
        return -1;
    }

    hb_print(LOG_INFO," socket new fd %d \n", clientfd);
  
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    int i = connect(clientfd, (struct sockaddr *)&addr, sizeof(addr));

    hb_print(LOG_INFO," new connect %d \n",i);

    if(i < 0 && errno != EINPROGRESS)
    {

        hb_print(LOG_ERR,"errno(%d) %s", errno,strerror(errno));
        close(clientfd);
        return -1;
    }
    else
    {
        return clientfd;
    }
}

#endif

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

void *recvMalloc(u32_t len)
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


int net_recv_challage_msg(struct heartbeat_route_client* hbrc,THDR *pHdr,TCHALRESP  *pResp)
{
	fd_set read_fds;
	int maxsock;
	struct timeval tv;
	int ret;
	int chanResqLen;
	char revBuffer[128] = {0};
	int recbytes,recTolBytes = 0;
	
	chanResqLen = sizeof(THDR) + sizeof(TCHALRESP);
	while (recTolBytes < chanResqLen) {
		char revdata[128] = {0};
		maxsock = hbrc->hbrc_sockfd;
		// timeout setting
		tv.tv_sec = 5;
		tv.tv_usec = 0;
	
		// initialize file descriptor set
		FD_ZERO(&read_fds);
		FD_SET(hbrc->hbrc_sockfd, &read_fds);
		ret = select(maxsock + 1, &read_fds, NULL, NULL, &tv);
		if (ret < 0) {
			hb_print(LOG_ERR, "[Fail] create select !");
			break;
		} else if (ret == 0) {
			hb_print(LOG_INFO, "select timeout!");
			return -1;
		}			
		if (FD_ISSET(hbrc->hbrc_sockfd, &read_fds)) {
			recbytes = read(hbrc->hbrc_sockfd, revdata, 128);			
			if(recbytes < 0)
			{
				hb_print(LOG_ERR, "recbytes = %d after read , errno = %d(%s)!",recbytes,errno,strerror(errno));
				
				/* 非阻塞模式下，没有数据返回EAGAIN，跳出循环 
				hb_print(LOG_ERR, "[Fail] read < 0 bytes ,errno(%d) %s!",errno,strerror(errno));
				*/
				if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
				{
					return -1;
				}

				/*  errno = 131(Connection reset by peer */
				if( errno == 131 )
					return -1;
				
				/* mips平台下，设置非阻塞模式，没有数据返回0，表示success，平台bug? (x86平台errno=0表示成功) */
				if(errno == 0)
					return -1;
			}
			/* 当服务器关闭，链接断开，select会立即返回可读，read后的len等于0*/
			else if(recbytes == 0)
			{
				hb_print(LOG_ERR, "[Fail] read = 0 bytes, seesion have closed!");
				return -1;
			}
			else 
			{
				memcpy(&revBuffer[recTolBytes],revdata,recbytes);
				recTolBytes += recbytes;
			}
		}
	}
	
	//pHdr = (THDR *)revBuffer;
	memcpy(pHdr,revBuffer,sizeof(THDR));
	
	//des_decode((void *)(revBuffer + sizeof(THDR)), pResp, CHANLLENGE_KEY, sizeof(*pResp));
	hbrc->chall_decode((void *)(revBuffer + sizeof(THDR)), pResp, CHANLLENGE_KEY, sizeof(*pResp));
	return 0;
}

int net_send_challage_msg(struct heartbeat_route_client *hbrc,THDR* pHdr,char* pMsg,int msgLen)
{
	int fd;
    unsigned char deschal[64];
	int ret;


	fd = hbrc->hbrc_sockfd;
    if(fd <= 0)
    {
        printf("%s error fd = %d\n", __FUNCTION__, fd);
        return -1;
    }

	pHdr->pktlen = msgLen;
    memset(deschal, 0, sizeof(deschal));
    //des_encode((const void *)pMsg, deschal, CHANLLENGE_KEY, msgLen);
    hbrc->chall_encode((const void *)pMsg, deschal, CHANLLENGE_KEY, msgLen);

#if 1
	send(fd, pHdr, sizeof(THDR), 0);
    send(fd, deschal, msgLen, 0);
#else
	ret = send(fd, pHdr, sizeof(THDR), 0);
	hb_print(LOG_INFO, "ret = %d;",ret);
#endif
}

/*
接收网络数据，处理粘包和分包。
hbrc : 心跳路由客户端
*/
int net_recv_msg(struct heartbeat_route_client* hbrc)
{
    char buff[512] = {0};

    char *oldBuff = hbrc->gbuf;
    int dataLen = hbrc->dataLen;
    int maxLen = hbrc->maxLen;

	int fd = hbrc->hbrc_sockfd;


    while(1)
    {
        int len = read(fd, buff, 256);
		
        if(len < 0)
        {
            buff[0] = 0;
			/* 非阻塞模式下，没有数据返回EAGAIN，跳出循环 
			hb_print(LOG_ERR, "[Fail] read < 0 bytes ,errno(%d) %s!",errno,strerror(errno));
			*/
            if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
            {
                break;
            }
			
			/* mips平台下，设置非阻塞模式，没有数据返回0，表示success，平台bug? (x86平台errno=0表示成功) */
			if(errno == 0)
				return -1;
			
			/* errno(104)=Connection reset by peer 
			[6][2016-05-30 17:38:56][28039](src/net.c:301) alread read ? errno(104)=Connection reset by peer
			*/
			if(errno == 104)
				return -1;

			hb_print(LOG_ERR, "[Fail] read < 0 bytes, errno(%d)=%s!",errno,strerror(errno));
			return -1;
#if 0
            else
            {
            	hb_print(LOG_ERR, "[Fail] read < 0 bytes ,set activeRecvFlag 0!");
                hbrc->activeRecvFlag = 0;
                return -1;
            }
#endif
        }
		/* 当服务器关闭，链接断开，select会立即返回可读，read后的len等于0*/
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

		/* pengruofeng debug core dump*/
		hb_print(LOG_INFO, "totalLen(%d),dataLen(%d),len(%d)",totalLen,dataLen,len);

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

		/* 取出数据, 分析报文 */
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


/*
hbrc : 心跳客户端
pHdr : 心跳协议头
pMsg : 心跳数据报文
msgLen : 心跳数据报文长度
*/
int net_send_msg(struct heartbeat_route_client *hbrc,THDR* pHdr,char* pMsg,int msgLen)
{
	int fd = hbrc->hbrc_sockfd;
	char netMsg[1024] = {0};
	int hdrLen = 0;
	int netLen = 0;

    if(fd <= 0)
    {
        hb_print(LOG_ERR,"send msg error,(error fd = %d)",fd);
        return -1;
    }

	char encodeMsg[1024]={0};

	//XORencode(pMsg, encodeMsg, hbrc->session_server_key, pHdr->pktlen);
	hbrc->msg_encode(pMsg, encodeMsg, hbrc->session_server_key,msgLen);

	hb_print(LOG_ERR,"########## encodeMsg = %s ",encodeMsg);

	hdrLen = sizeof(THDR);
    memcpy(netMsg, pHdr, hdrLen);
    memcpy(netMsg + hdrLen, encodeMsg, msgLen);

	netLen = hdrLen + msgLen;
	
#if 0
    send(fd, netMsg, netLen, 0);
#else
	pthread_mutex_lock(&SEND_MUTEX);
	send(fd, netMsg, netLen, 0);
	pthread_mutex_unlock(&SEND_MUTEX);
#endif
}


int proc_echoresp(struct heartbeat_route_client* hbrc, char *pBuff)
{
	THDR* pHdr;
	TECHORESP Recho_reqmsg;

	pHdr = (THDR *)pBuff;
	//XORencode(pBuff + sizeof(THDR), &Recho_reqmsg, hbrc->session_client_key, pHdr->pktlen);
	hbrc->msg_decode(pBuff + sizeof(THDR), &Recho_reqmsg, hbrc->session_client_key, pHdr->pktlen);
	/* 记录收到心跳回应包对应的sn号 */
	debug(LOG_INFO, "echo responce last_sn(%d)",Recho_reqmsg.client_sn);
	hbrc->last_resp_echosn = Recho_reqmsg.client_sn;
	print_echoresp(pHdr,&Recho_reqmsg);
}

int proc_notifyreq(struct heartbeat_route_client* hbrc, char *pBuff)
{
	THDR* pHdr;
	TECHORESP Recho_reqmsg;

	pHdr = (THDR *)pBuff;

	hbrc->recvsn = pHdr->sn;
	TNOTIFYREQ Notify_reqmsg;
	//XORencode(pBuff + sizeof(THDR), &Notify_reqmsg, hbrc->session_client_key, pHdr->pktlen);
	hbrc->msg_decode(pBuff + sizeof(THDR), &Notify_reqmsg, hbrc->session_client_key, pHdr->pktlen);
	print_notifyreq(pHdr,&Notify_reqmsg);

	/*分发通知消息*/
	dispatch_notify(hbrc,pBuff);
}


int proc_packet(struct heartbeat_route_client* hbrc, char *pBuff, int readLen)
{
    THDR *pHdr;
    pHdr = (THDR *)pBuff;

    /*鏈澶勭悊鐨勬暟鎹暱搴*/
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
    else if(pHdr->pktType == PKT_REPORT_RESPONSE)
    {
        proc_reportresp(hbrc, pBuff);
    }
	else if(pHdr->pktType == PKT_ISSUE_REQUEST)
	{
		proc_issuereq(hbrc, pBuff);
	}
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

int net_challange(struct heartbeat_route_client *hbrc)
{

	char msg[256] = {0};
    THDR chal_header;
    THDR *pHdr = &chal_header;

	memset(pHdr,0,sizeof(*pHdr));
    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->pktlen = sizeof(TCHALREQ);
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_CHALLENGE_REQUEST;
    pHdr->sn = hbrc->sendsn++;

    TCHALREQ chal_reqmsg;
    TCHALREQ *pReq = &chal_reqmsg;
    int msgLen = sizeof(TCHALREQ);


    pReq->magic = PKT_CHALLENGE_MAGIC;
	pReq->key = (u32_t)time(NULL);
	hbrc->session_client_key = pReq->key;		
    memset(pReq->u8res, 0x08, sizeof(pReq->u8res));

	print_chalreq(pHdr,pReq);
#if 0
    des_encode((const void *)pReq, deschal, CHANLLENGE_KEY, bytes);
    pHdr->pktlen = bytes;
    send(fd, pHdr, sizeof(THDR), 0);
    send(fd, deschal, bytes, 0);
#else
	memcpy(msg,pReq,msgLen);
	msg[msgLen] = '\0';
	net_send_challage_msg(hbrc,pHdr,msg,msgLen);

#endif
    return 1;
}

int net_echo(struct heartbeat_route_client *hbrc)
{
   	char emac[16] = {0}; 
	unsigned int emac_x[12] = {0};
    THDR echo_hdr;
    THDR *pHdr = &echo_hdr;
	int i = 0;
	char msg[256] = {0};

	memset(pHdr,0,sizeof(*pHdr));
    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->pktlen = sizeof(TECHOREQ);
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_ECHO_REQUEST;
    pHdr->sn = hbrc->sendsn++;

	/* 记录收到心跳回应包对应的sn号 */
	hbrc->last_req_echosn = pHdr->sn;

    TECHOREQ echo_reqmsg;
    TECHOREQ *pReq = &echo_reqmsg;
    int msgLen = sizeof(TECHOREQ);

    memcpy(pReq->equipmentSn, hbrc->equipmentSn, 6);
	print_echoreq(pHdr,&echo_reqmsg);
	
#if 0
    XORencode(&echo_reqmsg, &secho_reqmsg, hbrc->session_server_key, bytes);

    send(hbrc->hbrc_sockfd, pHdr, sizeof(THDR), 0);
    send(hbrc->hbrc_sockfd, &secho_reqmsg, bytes, 0);
#else
	memcpy(msg,&echo_reqmsg,msgLen);
	msg[msgLen] = '\0';
	net_send_msg(hbrc,pHdr,msg,msgLen);
#endif
    return 1;
}


int net_notify(struct heartbeat_route_client *hbrc)
{
	THDR notifyRespHdr;
	THDR *pHdr = &notifyRespHdr;
	char msg[256] = {0};

	memset(pHdr,0,sizeof(*pHdr));
	pHdr->flag = PKT_HDR_MAGIC;
	pHdr->version = PKT_VERSION;
	pHdr->pktType = PKT_NOTIFY_RESPONSE;
	pHdr->sn = hbrc->sendsn++;


	TNOTIFYRESP  sendNotifyRespMsg;
	memset(&sendNotifyRespMsg, 0, sizeof(sendNotifyRespMsg));
	sendNotifyRespMsg.returnSn = hbrc->recvsn;
	sendNotifyRespMsg.returnCode = NOF_OK;

	int msgLen = sizeof(TNOTIFYRESP);
	pHdr->pktlen = msgLen;
	print_notifyresp(pHdr,&sendNotifyRespMsg);

#if 0
	XORencode(pnotifyRespMsg, &sendNotifyRespMsg, hbrc->session_server_key, pHdr->pktlen);

	send(hbrc->hbrc_sockfd, pHdr, sizeof(THDR), 0);
	send(hbrc->hbrc_sockfd, &sendNotifyRespMsg, pHdr->pktlen, 0);
#else
	memcpy(msg,&sendNotifyRespMsg,msgLen);
	msg[msgLen] = '\0';
	net_send_msg(hbrc,pHdr,msg,msgLen);
#endif
	return 1;
}

void print_hdr(THDR  *tHdr)
{
	hb_print(LOG_ERR,"[hdr] : flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext);
}


void print_chalreq(THDR  *tHdr, TCHALREQ  *chalReq)
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
}


void print_chalresp(THDR  *tHdr, TCHALRESP  *chalResp)
{
	u32_t server_key;
    memcpy(&server_key, chalResp->key, sizeof(server_key));
	u32_t magic;
    memcpy(&magic, chalResp->magic, sizeof(magic));

	
	hb_print(LOG_ERR,"<<-- [challange response] [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{sn(%d),magic(%08x),key(%d),res(0x%02x%02x%02x%02x%02x%02x)}", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		chalResp->client_sn,
		magic,
		server_key,
		chalResp->u8res[0],chalResp->u8res[1],chalResp->u8res[2],chalResp->u8res[3],chalResp->u8res[4],chalResp->u8res[5]);
}


void print_echoreq(THDR  *tHdr, TECHOREQ  *echoReq)
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
		(unsigned char)echoReq->equipmentSn[3],(unsigned char)echoReq->equipmentSn[4],(unsigned char)echoReq->equipmentSn[5]);
}


void print_echoresp(THDR  *tHdr, TECHORESP *echoResp)
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
}


void print_notifyreq(THDR  *tHdr,TNOTIFYREQ  *notifyReq)
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
}


void print_notifyresp(THDR  *tHdr,TNOTIFYRESP* notifyResp)
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
}


