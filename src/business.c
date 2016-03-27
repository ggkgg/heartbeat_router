#include "hb_core.h"


extern struct glob_arg G;

static void print_reportreq(THDR  *tHdr, TREPORTREQ  *reportReq)
{
	hb_print(LOG_ERR,"[report resquest] -->> [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{vendor(0x%08x)}", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		reportReq->vendor);
}

static void print_reportresp(THDR  *tHdr, TREPORTRESP *reportResp)
{
	hb_print(LOG_ERR,"<<-- [report response] [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{client_sn(%d)}", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		reportResp->client_sn);
}

static void print_issuereq(THDR  *tHdr, TISSUEREQ  *issueReq)
{
	printf("<<-- [issue resquest] [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{vendor(0x%08x)}\n", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		issueReq->vendor);
}

static void print_issueresp(THDR  *tHdr, TISSUERESP *issueResp)
{
	printf("[issue response] -->> [hdr]:{flag(0x%04x),pktlen(%d),version(%d),pktType(%d),sn(%d),ext(0x%08x)} \
[data]:{client_sn(%d),response_code(%d)}\n", 
		tHdr->flag,
		tHdr->pktlen,
		tHdr->version,
		tHdr->pktType,
		tHdr->sn,
		tHdr->ext,
		issueResp->client_sn,
		issueResp->response_code);
}


int business_report(u32_t vendor,char* vendorMsg,int vendorMsgLen)
{
	struct heartbeat_route_client *hbrc = G.hbrc;
   	char emac[16] = {0}; 
	unsigned int emac_x[12] = {0};
    THDR echo_hdr;
    THDR *pHdr = &echo_hdr;
	int i = 0;
	char msg[256] = {0};

	memset(pHdr,0,sizeof(*pHdr));
    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_REPORT_REQUEST;
    pHdr->sn = hbrc->sendsn++;

	TREPORTREQ report_reqmsg;
    TREPORTREQ *pReq = &report_reqmsg;
    int msgLen = sizeof(TREPORTREQ);

	memcpy((char *)&pReq->vendor,(char *)&vendor,4);
	//pReq->vendor = vendor;
	print_reportreq(pHdr,pReq);

	memcpy(msg,pReq,msgLen);	
	memcpy(msg+msgLen,vendorMsg,vendorMsgLen);
	msgLen += vendorMsgLen;

	msg[msgLen] = '\0';
	net_send_msg(hbrc,pHdr,msg,msgLen);

    return 1;
}


int proc_reportresp(struct heartbeat_route_client* hbrc, char *pBuff)
{
	THDR* pHdr;
	TREPORTRESP reportRespMsg;

	pHdr = (THDR *)pBuff;
	hbrc->msg_decode(pBuff + sizeof(THDR), &reportRespMsg, hbrc->session_client_key, pHdr->pktlen);
	print_reportresp(pHdr,&reportRespMsg);
}

int proc_issuereq(struct heartbeat_route_client* hbrc, char *pBuff)
{
	THDR* pHdr;
	TISSUEREQ issueReqMsg;
	char *vendorMsg;
	int vendorMsgLen;

	pHdr = (THDR *)pBuff;
	hbrc->recvsn = pHdr->sn;
	hbrc->msg_decode(pBuff + sizeof(THDR), &issueReqMsg, hbrc->session_client_key, pHdr->pktlen);
	print_issuereq(pHdr,&issueReqMsg);

	vendorMsg = &issueReqMsg + 4;
	vendorMsgLen = pHdr->pktlen - (sizeof(THDR)+4);
	business_issue_resp();
}


int business_issue_resp()
{
	struct heartbeat_route_client *hbrc = G.hbrc;
	THDR issueRespHdr;
	THDR *pHdr = &issueRespHdr;
	char msg[256] = {0};

	memset(pHdr,0,sizeof(*pHdr));
	pHdr->flag = PKT_HDR_MAGIC;
	pHdr->version = PKT_VERSION;
	pHdr->pktType = PKT_ISSUE_RESPONSE;
	pHdr->sn = hbrc->sendsn++;


	TISSUERESP  sendIssueRespMsg;
	memset(&sendIssueRespMsg, 0, sizeof(sendIssueRespMsg));
	sendIssueRespMsg.client_sn = hbrc->recvsn;
	sendIssueRespMsg.response_code = NOF_OK;

	int msgLen = sizeof(TISSUERESP);
	print_issueresp(pHdr,&sendIssueRespMsg);

#if 0
	XORencode(pnotifyRespMsg, &sendNotifyRespMsg, hbrc->session_server_key, pHdr->pktlen);

	send(hbrc->hbrc_sockfd, pHdr, sizeof(THDR), 0);
	send(hbrc->hbrc_sockfd, &sendNotifyRespMsg, pHdr->pktlen, 0);
#else
	memcpy(msg,&sendIssueRespMsg,msgLen);
	msg[msgLen] = '\0';
	net_send_msg(hbrc,pHdr,msg,msgLen);
#endif
	return 1;

}



