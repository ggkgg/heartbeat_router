#ifndef _HB_IPC_H
#define _HB_IPC_H

#include "list.h"
#define HB_IPC


struct ipc_core_client_s
{
	char *vendor;
	//struct hbc_ipc* pHbcIpc;
	struct list_head ipcCoreList; 
	/* function */
	int (*handle_msg)(char* msg);	
};

typedef struct ipc_core_client_s ipc_core_client_st;

struct hbc_ipc
{
	void *priv_data;

	struct sockaddr_in cliAddr;
	char *recvMsg;
	int recvMsgLen;
	char *vendor;
	char *data;
	
	/* function */
	int (*parse_ipc_msg)(struct hbc_ipc *pHbcIpc);
	int (*dispatch_ipc_msg)(struct hbc_ipc *pHbcIpc);	
};

#endif
