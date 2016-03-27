#include "udpserver.h"

void call_mye_interface(ipc_udp_client_st *ipCli)
{
	u32_t vendor;
	u32_t *pVendor;
	
	pVendor = (u32_t*)ipCli->jsonVendor; 
	vendor = *pVendor;

	cJSON *pJsonValue = cJSON_GetObjectItem(ipCli->jsonMsg, "value");

	cJSON *pJsonMed = cJSON_GetObjectItem(pJsonValue, "med");
	char *pMed = pJsonMed->valuestring;

	business_report(vendor,pMed,strlen(pMed));
}

