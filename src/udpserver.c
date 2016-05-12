#include "udpserver.h"

#if 0
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/wait.h> 
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <string.h> 
#endif

 
extern struct glob_arg G;

#define	MAXLINE	2048	/* to see datagram truncation */

int net_socket(int family, int type, int protocol)
{
	int		n;

	if ( (n = socket(family, type, protocol)) < 0)
		hb_print(LOG_ERR,"socket error");
	return(n);
}



void net_bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
	if (bind(fd, sa, salen) < 0)
		hb_print(LOG_ERR,"bind error\n");
}


int net_recvfrom(int fd, void *ptr, size_t nbytes, int flags,
		 struct sockaddr *sa, socklen_t *salenptr)
{
	ssize_t		n;

	if ( (n = recvfrom(fd, ptr, nbytes, flags, sa, salenptr)) < 0)
		hb_print(LOG_ERR,"recvfrom error\n");
	return(n);
}

void net_sendto(int fd, const void *ptr, size_t nbytes, int flags,
	   const struct sockaddr *sa, socklen_t salen)
{
	if (sendto(fd, ptr, nbytes, flags, sa, salen) != (ssize_t)nbytes)
		hb_print(LOG_ERR,"sendto error\n");
}

#if 0
void thread_recv_udpmsg(void *data)
{
	int udpfd,*pudpfd;;
	char mesg[MAXLINE];
	socklen_t	len;
	ipc_udp_client_st *ipCli;


	ipCli = (ipc_udp_client_st *)malloc(sizeof(ipc_udp_client_st));
	bzero(ipCli,sizeof(ipc_udp_client_st));
	ipCli->recvMsg = (char *)malloc(MAXLINE*sizeof(char));
	
	pudpfd = (int *)data;
	ipCli->listenfd = *pudpfd;
	len = sizeof(ipCli->cliAddr);
	ipCli->recvMsgLen = net_recvfrom(ipCli->listenfd, ipCli->recvMsg, MAXLINE, 0, (struct sockaddr*) &ipCli->cliAddr, &len);

	hb_print(LOG_INFO,"recv msg coming client (%s:%d)",inet_ntoa(ipCli->cliAddr.sin_addr),ipCli->cliAddr.sin_port);
	call_ipchelper(ipCli);


	ipCli->sendMsg = ipCli->recvMsg;
	ipCli->sendMsgLen = ipCli->recvMsgLen; 
	net_sendto(ipCli->listenfd, ipCli->sendMsg, ipCli->sendMsgLen, 0, (struct sockaddr*) &ipCli->cliAddr, len);

	if(!ipCli->recvMsg)
		free(ipCli->recvMsg);
	if(!ipCli->sendMsg)
		free(ipCli->sendMsg);
	free(ipCli);
}
#endif

void delete_ipcli(ipc_udp_client_st *ipCli)
{
	if(!ipCli)
		return;

	if(ipCli->recvMsg) {
		free(ipCli->recvMsg);
		ipCli->recvMsg = NULL;
	}

	if(ipCli->sendMsg) {
		free(ipCli->sendMsg);
		ipCli->sendMsg = NULL;
	}

	if(ipCli->jsonMsg)
		cJSON_Delete(ipCli->jsonMsg);

	if(ipCli->jsonModule)
		free(ipCli->jsonModule);
	if(ipCli->jsonCmdName)
		free(ipCli->jsonCmdName);
	if(ipCli->jsonVendor)
		free(ipCli->jsonVendor);

	free(ipCli);
}

int process_recvmsg(int udpfd)
{
	char mesg[MAXLINE];
	socklen_t	len;
	ipc_udp_client_st *ipCli;

	if(G.udpThread.pause_flag) {
		return 0;
	}


	ipCli = (ipc_udp_client_st *)malloc(sizeof(ipc_udp_client_st));
	bzero(ipCli,sizeof(ipc_udp_client_st));
	ipCli->recvMsg = (char *)malloc(MAXLINE*sizeof(char));
	memset(ipCli->recvMsg,0,MAXLINE*sizeof(char));
	
	ipCli->listenfd = udpfd;
	len = sizeof(ipCli->cliAddr);
	ipCli->recvMsgLen = net_recvfrom(ipCli->listenfd, ipCli->recvMsg, MAXLINE, 0, (struct sockaddr*)&ipCli->cliAddr, &len);

	printf("ipCli->recvMsg(%d)(%s)\n",ipCli->recvMsgLen,ipCli->recvMsg);

	/*  当前udp只处理ipc消息，调用錭all_ipchelper触发ipc消息解析  */
	if (call_ipchelper(ipCli) < 0) {
		hb_print(LOG_ERR,"parse json udp packet error!");
		delete_ipcli(ipCli);
		return -1;
	}


#if 0
	ipCli->sendMsg = strdup(ipCli->recvMsg);
	ipCli->sendMsgLen = ipCli->recvMsgLen;
	printf("ipCli->sendMsg(%d)(%s)\n",ipCli->sendMsgLen,ipCli->sendMsg);
	net_sendto(ipCli->listenfd, ipCli->sendMsg, ipCli->sendMsgLen, 0, (struct sockaddr*) &ipCli->cliAddr, len);
#endif
	delete_ipcli(ipCli);
	return 0;
}

int udp_server(int port)
{
	int				udpfd,nready, maxfdp1;
	fd_set				rset;
	struct sockaddr_in  servaddr;
	pthread_t pth_ids;
	int ret;


	udpfd = net_socket(AF_INET, SOCK_DGRAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(port);

	net_bind(udpfd, (struct sockaddr*) &servaddr, sizeof(servaddr));

	FD_ZERO(&rset);
	maxfdp1 = udpfd + 1;
	for ( ; ; ) { 
		FD_SET(udpfd, &rset);
		if ( (nready = select(maxfdp1, &rset, NULL, NULL, NULL)) < 0) {
			if (errno == EINTR)
				continue;		/* back to for() */
			else
				hb_print(LOG_ERR,"select error");
		}


		if (FD_ISSET(udpfd, &rset)) {
#if 0
			ret=pthread_create(&pth_ids,NULL,(void *)thread_recv_udpmsg,(void*)&udpfd);
			if(ret!=0)
			{
				hb_print(LOG_ERR,"Create pthread error!\n");
				exit(1);
			}
			pthread_detach(pth_ids);
#endif
			if (process_recvmsg(udpfd) < 0) {
				hb_print(LOG_ERR,"udp packet error!");
				continue;
			}

		}
	}
}

