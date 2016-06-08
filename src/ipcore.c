#include <stdlib.h>

#include "hb_core.h"
#include "cJSON.h"
//#include "udpserver.h"
#include "common.h"

LIST_HEAD(head_ipc_client); 

#if 0
int parse_json_udpmsg(ipc_udp_client_st *ipCli) {
	cJSON *pJson;
	char appAddr[32];
	char module[32];
	
	pJson = cJSON_Parse(ipCli->recvMsg);

	if(!pJson)
		return -1;

	
	cJSON *pJsonCmdUrl = cJSON_GetObjectItem(pJson, "cmd_url");
	if(!pJsonCmdUrl)
		goto exit1;


	sscanf(pJsonCmdUrl->valuestring,"/%[^/]/%[^/]",appAddr,module);
	if (!appAddr && !strncmp(appAddr,"heartbeatclient",strlen(appAddr))) {		
		hb_print(LOG_ERR,"app address error(%s)!",appAddr);
		goto exit1;
	}
	ipCli->jsonModule = strdup(module);



	cJSON *pJsonCmdName = cJSON_GetObjectItem(pJson, "cmd_name");
	if(!pJsonCmdName)
		goto exit1;
	ipCli->jsonCmdName = strdup(pJsonCmdName->valuestring);

	
	cJSON *pJsonVendor = cJSON_GetObjectItem(pJson, "vendor");
	if(!pJsonVendor)
		goto exit1;
	ipCli->jsonVendor = strdup(pJsonVendor->valuestring);

	hb_print(LOG_INFO,"pCmdUrl(%s) pCmdName(%s) pVendor(%s)",
		pJsonCmdUrl->valuestring,ipCli->jsonCmdName,ipCli->jsonVendor);

	ipCli->jsonMsg = pJson;
	return 0;

exit1:
	cJSON_Delete(pJson);
	return -1;
}

int dispatch_json_udpmsg(ipc_udp_client_st *ipCli)
{
	if(0 == strncmp(ipCli->jsonVendor,"myed",4)) {
		call_mye_interface(ipCli);
	}
	return 0;
}
#endif


int parse_json_udpmsg(struct hbc_ipc *hbcIpc) {
	cJSON *pJson;
	char appAddr[32];
	char module[32];
	
	pJson = cJSON_Parse(hbcIpc->recvMsg);

	if(!pJson)
		return -1;

	
	cJSON *pJsonCmdUrl = cJSON_GetObjectItem(pJson, "cmd_url");
	if(!pJsonCmdUrl)
		goto exit1;


	sscanf(pJsonCmdUrl->valuestring,"/%[^/]/%[^/]",appAddr,module);
	if (!appAddr && !strncmp(appAddr,"heartbeatclient",strlen(appAddr))) {		
		hb_print(LOG_ERR,"app address error(%s)!",appAddr);
		goto exit1;
	}
	//ipCli->jsonModule = strdup(module);



	cJSON *pJsonCmdName = cJSON_GetObjectItem(pJson, "cmd_name");
	if(!pJsonCmdName)
		goto exit1;
	//ipCli->jsonCmdName = strdup(pJsonCmdName->valuestring);

	
	cJSON *pJsonVendor = cJSON_GetObjectItem(pJson, "vendor");
	if(!pJsonVendor)
		goto exit1;
	//ipCli->jsonVendor = strdup(pJsonVendor->valuestring);
	hbcIpc->vendor = strdup(pJsonVendor->valuestring);

	hb_print(LOG_INFO,"pCmdUrl(%s) pCmdName(%s) pVendor(%s)",
		pJsonCmdUrl->valuestring,pJsonCmdName->valuestring,pJsonVendor->valuestring);

	cJSON *pJsonValue = cJSON_GetObjectItem(pJson, "value");

	hbcIpc->data = cJSON_Print(pJsonValue); 
	//ipCli->jsonMsg = pJson;
	cJSON_Delete(pJson);
	return 0;

exit1:
	cJSON_Delete(pJson);
	return -1;
}

int dispatch_json_udpmsg(struct hbc_ipc *hbcIpc)
{
	struct ipc_core_client_s* pos_item = NULL;

	list_for_each_entry(pos_item, &head_ipc_client, ipcCoreList) {
		if(0 == strncmp(hbcIpc->vendor,pos_item->vendor,strlen(pos_item->vendor))) {
			break;
		}
	}

	if(!pos_item)
		return -1;

	pos_item->handle_msg(hbcIpc->data);

	return 0;
}

#if 0
void call_ipchelper(ipc_udp_client_st *ipCli)
{
	/*  解析json格式数据，分析第一层协议数据 cmd_url , cmd_name,vendor  */
	if (parse_json_udpmsg(ipCli) < 0) {
		hb_print(LOG_ERR,"parse json udp packet error!");
		return;
	}

	/*  通过vendor字段分发数据  */
	if (dispatch_json_udpmsg(ipCli) < 0) {
		hb_print(LOG_ERR,"dispatch json udp packet error!");
		return;
	}
	return;
}
#endif

int clean_hbc_ipc(struct hbc_ipc *hbcIpc)
{
	if(!hbcIpc->recvMsg) {
		free(hbcIpc->recvMsg);
		hbcIpc->recvMsg = NULL;
	}
	hbcIpc->recvMsgLen = 0;

	if(!hbcIpc->vendor) {
		free(hbcIpc->vendor);
		hbcIpc->vendor = NULL;
	}

	if(!hbcIpc->data) {
		free(hbcIpc->data);
		hbcIpc->data = NULL;
	}

	bzero(&hbcIpc->cliAddr,sizeof(struct sockaddr_in));
	return 0;
}

void register_ipcore(struct ipc_core_client_s* ipcCoreClient)
{
	INIT_LIST_HEAD(&ipcCoreClient->ipcCoreList);
	list_add_tail(&ipcCoreClient->ipcCoreList, &head_ipc_client);	
}


int hb_ipc_init(struct heartbeat_route_client* hbrc)
{
	struct hbc_ipc *hbcIpc;
	
	hbcIpc = (struct hbc_ipc*)malloc(sizeof(struct hbc_ipc));
	bzero(hbcIpc,sizeof(struct hbc_ipc));
	
	hbcIpc->priv_data = (void *)hbrc;
	hbcIpc->parse_ipc_msg = parse_json_udpmsg;
	hbcIpc->dispatch_ipc_msg = dispatch_json_udpmsg;

	hbcIpc->recvMsg = NULL;
	hbcIpc->recvMsgLen = 0;

	hbcIpc->vendor = NULL;
	hbcIpc->data = NULL;

	INIT_LIST_HEAD(&head_ipc_client);
	hbrc->hbc_ipc = hbcIpc;
}


