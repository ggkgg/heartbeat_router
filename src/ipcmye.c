#include "hb_core.h"
#include "udpserver.h"
#include "common.h"


int call_mye_interface(char *msg);

ipc_core_client_st ipc_mye = {
	"myed",
	{NULL,NULL},
	call_mye_interface
};

#if 0
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

	/* 轮发送 数据 */
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
#endif

int call_mye_interface(char *msg)
{
	cJSON *pJsonData;
	
	pJsonData = cJSON_Parse(msg);
	if(!pJsonData)
		return -1;
#if 1
	int iSize = cJSON_GetArraySize(pJsonData);
	int iCnt = 0;

	/* 轮发送 数据 */
	for(iCnt = 0; iCnt < iSize; iCnt++)
	{
		cJSON *pJsonMedArray = cJSON_GetArrayItem(pJsonData, iCnt);
		cJSON *pJsonMed = cJSON_GetObjectItem(pJsonMedArray, "med");
		char *pMed = pJsonMed->valuestring;

		hb_print(LOG_INFO,"%s:send commands :%s !",__FUNCTION__,pMed);
		business_report(ipc_mye.vendor,pMed,strlen(pMed));
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
	cJSON_Delete(pJsonData);
}


void ipc_mye_init()
{
	register_ipcore(&ipc_mye);
}

