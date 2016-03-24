#include <stdlib.h>

#include "cJSON.h"

void call_ipchelper(int udpfd,struct sockaddr *cliaddr,char *msg)
{
	cJSON *pJson;	
	
	pJson = cJSON_Parse(msg);
	
	cJSON *pJsonCmdUrl = cJSON_GetObjectItem(pJson, "cmd_url");
	char *pCmdUrl = cJSON_Print(pJsonCmdUrl);

	cJSON *pJsonCmdName = cJSON_GetObjectItem(pJson, "cmd_name");
	char *pCmdName = cJSON_Print(pJsonCmdName);
	
	cJSON *pJsonNodeMac = cJSON_GetObjectItem(pJson, "node_mac");
	char *pNodeMac = cJSON_Print(pJsonNodeMac);
		
	cJSON *pJsonValue = cJSON_GetObjectItem(pJson, "value");

	cJSON *pJsonMacAddress = cJSON_GetObjectItem(pJsonValue, "MACAddress");
	char *pMacAddress = cJSON_Print(pJsonMacAddress);

	cJSON *pJsonChannels = cJSON_GetObjectItem(pJsonValue, "Channels");
	char *pChannels = cJSON_Print(pJsonChannels);
	
	cJSON *pJsonNumberChildLimit = cJSON_GetObjectItem(pJsonValue, "numberofchildlimit");
	char *pNumberChildLimit = cJSON_Print(pJsonNumberChildLimit);
	
	printf("pCmdUrl(%s) pCmdName(%s) pNodeMac(%s) pMacAddress(%s) pChannels(%s) pNumberChildLimit(%d)\n",
		pCmdUrl,pCmdName,pNodeMac,pMacAddress,pChannels,atoi(pNumberChildLimit));

	free(pCmdUrl);
	free(pCmdName);
	free(pNodeMac);
	free(pMacAddress);	
	free(pChannels);
	free(pNumberChildLimit);		
	cJSON_Delete(pJson);
}

