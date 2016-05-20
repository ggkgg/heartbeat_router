#include <stdlib.h>

#include "cJSON.h"
#include "udpserver.h"



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


void call_ipchelper(ipc_udp_client_st *ipCli)
{
	/*  解析json格式数据，分析第一层协议数据 cmd_url , cmd_name,vendor  */
	if (parse_json_udpmsg(ipCli) < 0) {
		hb_print(LOG_ERR,"parse json udp packet error!");
		delete_ipcli(ipCli);
		return;
	}

	/*  通过vendor字段分发数据  */
	if (dispatch_json_udpmsg(ipCli) < 0) {
		hb_print(LOG_ERR,"dispatch json udp packet error!");
		delete_ipcli(ipCli);
		return;
	}
	return;
}

