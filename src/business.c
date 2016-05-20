#include "hb_core.h"
#include "cJSON.h"

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
[data]:{vendor(0x%08x),equipmentSn(0x%02x%02x%02x%02x%02x%02x)}\n", 
			tHdr->flag,
			tHdr->pktlen,
			tHdr->version,
			tHdr->pktType,
			tHdr->sn,
			tHdr->ext,
			issueReq->vendor,
			issueReq->equipmentSn[0],issueReq->equipmentSn[1],issueReq->equipmentSn[2],
			issueReq->equipmentSn[3],issueReq->equipmentSn[4],issueReq->equipmentSn[5]
		);
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

int send_issuedata_to_mye(char* issueReqMsg)
{
    struct sockaddr_in addr;
    int sock;
	char *medMsg;

	medMsg = issueReqMsg + 10;
    if ( (sock=socket(AF_INET, SOCK_DGRAM, 0)) <0)
    {
        perror("socket");
        exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(10300);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (addr.sin_addr.s_addr == INADDR_NONE)
    {
        printf("Incorrect ip address!");
        close(sock);
        exit(1);
    }

    char buff[1024];
    int len = sizeof(addr);
   
    int n;

	cJSON *root,*value, *med;
	
	char *out;

	root=cJSON_CreateObject();


	cJSON_AddStringToObject(root,"cmd_url","/heartbeatclient/business");

	cJSON_AddStringToObject(root,"cmd_name","issue");

	cJSON_AddStringToObject(root,"vendor","myed");
	
	cJSON_AddItemToObject(root,"value",value=cJSON_CreateArray());

	cJSON_AddItemToArray(value,med=cJSON_CreateObject());
	
	cJSON_AddStringToObject(med,"med",medMsg);

	out = cJSON_Print(root);
	int outLen = strlen(out);
	
	printf("[send_issuedata_to_mye] root(%d) = %s\n",outLen,out);
	strncpy(buff,out,outLen);
	buff[outLen] = '\0';

    n = sendto(sock, buff, strlen(buff), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (n < 0)
    {
        perror("sendto");
        close(sock);
    }
	
	cJSON_Delete(root);
	free(out);
    return 0;	
}

int dispatch_issuedata(char* issueReqMsg)
{
	char *vendor;

	vendor = issueReqMsg;
	if(0 == strncmp(vendor,"myed",4)) {
		send_issuedata_to_mye(issueReqMsg);
	}	
	return 0;
}

int test_issue()
{
    printf("This is a UDP client\n");
    struct sockaddr_in addr;
    int sock;

    if ( (sock=socket(AF_INET, SOCK_DGRAM, 0)) <0)
    {
        perror("socket");
        exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(10300);
    addr.sin_addr.s_addr = inet_addr("192.168.13.164");
    if (addr.sin_addr.s_addr == INADDR_NONE)
    {
        printf("Incorrect ip address!");
        close(sock);
        exit(1);
    }

    char buff[512];
    int len = sizeof(addr);
    while (1)
    {
//        gets(buff);
        int n;

		cJSON *root,*value, *med;
		
		char *out;

		root=cJSON_CreateObject();


		cJSON_AddStringToObject(root,"cmd_url","/heartbeatclient/business");

		cJSON_AddStringToObject(root,"cmd_name","report");

		cJSON_AddStringToObject(root,"vendor","myed");
		
		cJSON_AddItemToObject(root,"value",value=cJSON_CreateArray());

		cJSON_AddItemToObject(value,"value",med=cJSON_CreateObject());

		cJSON_AddStringToObject(med,"med","cccccccccccccccccccccccccccccccccccccccccxxxxxxx");		

		out = cJSON_Print(root);
		int outLen = strlen(out);
		
		printf("root(%d) = %s\n",outLen,out);
		strncpy(buff,out,outLen);
		buff[outLen] = '\0';

        n = sendto(sock, buff, strlen(buff), 0, (struct sockaddr *)&addr, sizeof(addr));
        if (n < 0)
        {
            perror("sendto");
            close(sock);
            break;
        }
		
		cJSON_Delete(root);
		free(out);
		break;
    }
    
    return 0;
}


/*
vendor:  厂商字段
vendorMsg:  厂商自定义消息
vendorMsgLen: 厂商自定义消息长度
*/
int business_report(u32_t vendor,char* vendorMsg,int vendorMsgLen)
{
	struct heartbeat_route_client *hbrc = G.hbrc;
   	char emac[16] = {0}; 
	unsigned int emac_x[12] = {0};
    THDR echo_hdr;
    THDR *pHdr = &echo_hdr;
	int i = 0;
	char msg[512] = {0};

	memset(pHdr,0,sizeof(*pHdr));
    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_REPORT_REQUEST;
    pHdr->sn = hbrc->sendsn++;

	TREPORTREQ report_reqmsg;
    TREPORTREQ *pReq = &report_reqmsg;
    int msgLen = sizeof(TREPORTREQ);

	memcpy((char *)&pReq->vendor,(char *)&vendor,4);
	
	memcpy(msg,pReq,msgLen);	
	memcpy(msg+msgLen,vendorMsg,vendorMsgLen);
	msgLen += vendorMsgLen;
	pHdr->pktlen = msgLen;
	print_reportreq(pHdr,pReq);
	hb_print(LOG_INFO,"************** med = %s",msg+sizeof(TREPORTREQ));

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
	//char *vendorMsg;
	//int vendorMsgLen;
	char issueReqMsg[1024];

	

	pHdr = (THDR *)pBuff;
	hbrc->recvsn = pHdr->sn;
	//hbrc->recvsn = pHdr->sn;
	hbrc->msg_decode(pBuff + sizeof(THDR), issueReqMsg, hbrc->session_client_key, pHdr->pktlen);

	TISSUEREQ *pIssueReq;
	pIssueReq = (TISSUEREQ *)issueReqMsg;
	print_issuereq(pHdr,pIssueReq);

	dispatch_issuedata(issueReqMsg);

	//vendorMsg = &issueReqMsg + 4;
	//vendorMsgLen = pHdr->pktlen - (sizeof(THDR)+4);
	business_issue_resp();
}


int business_issue_resp()
{
	struct heartbeat_route_client *hbrc = G.hbrc;
	THDR issueRespHdr;
	THDR *pHdr = &issueRespHdr;
	char msg[512] = {0};

	memset(pHdr,0,sizeof(*pHdr));
	pHdr->flag = PKT_HDR_MAGIC;
	pHdr->version = PKT_VERSION;
	pHdr->pktType = PKT_ISSUE_RESPONSE;
	pHdr->sn = hbrc->sendsn++;


	TISSUERESP  sendIssueRespMsg;
	memset(&sendIssueRespMsg, 0, sizeof(sendIssueRespMsg));
	sendIssueRespMsg.client_sn = hbrc->recvsn;
	sendIssueRespMsg.response_code = NOF_OK;
	pHdr->pktlen = sizeof(TISSUERESP);
	int msgLen = pHdr->pktlen;
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



