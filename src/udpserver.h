#ifndef _UDPSERVER_H
#define _UDPSERVER_H

#include <sys/socket.h>	/* basic socket definitions */
#include <arpa/inet.h> /* sockaddr_in INADDR_ANY*/
#include <sys/select.h>	/* for convenience */
#include <pthread.h>
#include <errno.h>

#include "cJSON.h"


struct ipc_udp_server_s
{
	int listenfd;
	int port;
	
	void *priv_data;

	/* function */
	int (*recv_msg)(struct ipc_udp_server_s *ipcServ);
};


struct ipc_udp_client_s
{
	struct ipc_udp_server_s *ipcServ;
	struct sockaddr_in cliAddr;
	char *recvMsg;
	int recvMsgLen;
	char *sendMsg;
	int sendMsgLen;
	cJSON * jsonMsg;
	char *jsonModule;
	char *jsonCmdName;
	char *jsonVendor;
};

typedef struct ipc_udp_client_s ipc_udp_client_st;
typedef struct ipc_udp_server_s ipc_udp_server_st;

ipc_udp_server_st* get_udp_server(int port);

#endif
