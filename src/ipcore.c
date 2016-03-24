#include <stdlib.h>

#include "cJSON.h"

void call_ipchelper(int udpfd,struct sockaddr *cliaddr,char *msg)
{
	cJSON *pJson;	

	pJson = cJSON_Parse(msg);


	cJSON_Delete(pJson);


}

