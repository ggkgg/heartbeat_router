#ifndef _HB_IPC_H
#define _HB_IPC_H

#define HB_IPC

struct hbc_ipc
{
	void *priv_data;

	/* function */
	int (*parse_ipc_msg)(struct ipc_udp_server_s *ipcServ);
	int (*dispatch_ipc_msg)(struct ipc_udp_server_s *ipcServ);	
};

#endif
