#include "hb_core.h"
#include "business.h"


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


int business_report(struct heartbeat_route_client *hbrc,u32_t vendor)
{
   	char emac[16] = {0}; 
	unsigned int emac_x[12] = {0};
    THDR echo_hdr;
    THDR *pHdr = &echo_hdr;
	int i = 0;
	char msg[256] = {0};

	memset(pHdr,0,sizeof(*pHdr));
    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->pktlen = sizeof(TREPORTREQ);
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_REPORT_REQUEST;
    pHdr->sn = hbrc->sendsn++;

	TREPORTREQ report_reqmsg;
    TREPORTREQ *pReq = &report_reqmsg;
    int msgLen = sizeof(TREPORTREQ);

	pReq->vendor = vendor;
	print_reportreq(pHdr,pReq);

	memcpy(msg,pReq,msgLen);
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


