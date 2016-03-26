#include <sys/socket.h>	/* basic socket definitions */
#include <arpa/inet.h> /* sockaddr_in INADDR_ANY*/
#include <sys/select.h>	/* for convenience */
#include <pthread.h>
#include <errno.h>

#include "hb_core.h"
#include "cJSON.h"

struct ipc_udp_client_s
{
	int listenfd;
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

