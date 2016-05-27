#include "hb_core.h"
#include "udpserver.h"
#include "common.h"

void call_mye_interface(ipc_udp_client_st *ipCli)
{
	u32_t vendor;
	u32_t *pVendor;
	struct heartbeat_route_client* hbrc;
	ipc_udp_server_st *ipcServ;

	ipcServ = ipCli->ipcServ;
	hbrc = (struct heartbeat_route_client*)ipcServ->priv_data;
	
	pVendor = (u32_t*)ipCli->jsonVendor; 
	vendor = *pVendor;

	cJSON *pJsonValue = cJSON_GetObjectItem(ipCli->jsonMsg, "value");

#if 1
	int iSize = cJSON_GetArraySize(pJsonValue);
	int iCnt = 0;
	
	hb_print(LOG_INFO,"%s:receive %d med commands !",__FUNCTION__,iSize);

	/* ÂÖ·¢ËÍ Êý¾Ý */
	for(iCnt = 0; iCnt < iSize; iCnt++)
	{
		cJSON *pJsonMedArray = cJSON_GetArrayItem(pJsonValue, iCnt);
		cJSON *pJsonMed = cJSON_GetObjectItem(pJsonMedArray, "med");
		char *pMed = pJsonMed->valuestring;
		
		business_report(hbrc,vendor,pMed,strlen(pMed));
	}
#elif 0
	cJSON *pJsonMedArray = cJSON_GetArrayItem(pJsonValue, iCnt);
	cJSON *pJsonMed = cJSON_GetObjectItem(pJsonMedArray, "med");
	char *pMed = pJsonMed->valuestring;
	hb_print(LOG_ERR,"$$$$$$$$$ strlen(pMed) (%d)",strlen(pMed));
	business_report(vendor,pMed,strlen(pMed));
#else
   cJSON *pJsonMed = cJSON_GetObjectItem(pJsonValue, "med");
   char *pMed = pJsonMed->valuestring;
   business_report(vendor,pMed,strlen(pMed));
#endif
}

