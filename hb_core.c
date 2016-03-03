#include "hb_core.h"

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


/* 轮询心跳服务器，如果全部失败，返回-1*/
int search_hbs(struct heartbeat_route_client *hbrc)
{
	int i=0;
	int conectFlag = 0;
	struct hbc_conf conf = hbrc->hbrc_conf;

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
		THDR notifyRespHdr;
		THDR *pHdr = &notifyRespHdr;
		
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
	int clientSn = 0;
	char msg[256] = {0};

	memset(pHdr,0,sizeof(*pHdr));
	pHdr->flag = PKT_HDR_MAGIC;
	pHdr->version = PKT_VERSION;
	pHdr->pktType = PKT_NOTIFY_RESPONSE;
	pHdr->sn = hbrc->sendsn++;


	TNOTIFYRESP  sendNotifyRespMsg;
	memset(&sendNotifyRespMsg, 0, sizeof(sendNotifyRespMsg));
	clientSn = pHdr->sn;
	sendNotifyRespMsg.returnSn = clientSn;
	sendNotifyRespMsg.returnCode = NOF_OK;

	int msgLen = sizeof(TNOTIFYRESP);
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


int proc_echoresp(struct heartbeat_route_client* hbrc, char *pBuff)
{
	THDR* pHdr;
	TECHORESP Recho_reqmsg;

	pHdr = (THDR *)pBuff;
	XORencode(pBuff + sizeof(THDR), &Recho_reqmsg, hbrc->session_client_key, pHdr->pktlen);
	//print_hdr(pHdr);
	print_echoresp(pHdr,&Recho_reqmsg);

}

int proc_notifyreq(struct heartbeat_route_client* hbrc, char *pBuff)
{
	THDR* pHdr;
	TECHORESP Recho_reqmsg;

	pHdr = (THDR *)pBuff;
	TNOTIFYREQ Notify_reqmsg;
	XORencode(pBuff + sizeof(THDR), &Notify_reqmsg, hbrc->session_client_key, pHdr->pktlen);
	//print_hdr(pHdr);
	print_notifyreq(pHdr,&Notify_reqmsg);

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

