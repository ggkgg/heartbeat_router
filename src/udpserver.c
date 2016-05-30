#include "udpserver.h"
#include "common.h"


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

#if 0
int udp_server(int port)
{
	int				udpfd,nready, maxfdp1;
	fd_set				rset;
	struct sockaddr_in  servaddr;
	int ret;
	//ipc_udp_client_st *ipServ;


	//ipServ = (ipc_udp_server_st *)malloc(sizeof(ipc_udp_server_st));
	//bzero(ipServ,sizeof(ipc_udp_client_st));

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
#else
ipc_udp_server_st* get_udp_server(int port)
{
	int	udpfd;
	struct sockaddr_in  servaddr;
	int ret;
	ipc_udp_server_st *ipServ;
	

	ipServ = (ipc_udp_server_st *)malloc(sizeof(ipc_udp_server_st));
	bzero(ipServ,sizeof(ipc_udp_server_st));

	udpfd = net_socket(AF_INET, SOCK_DGRAM, 0);
	ipServ->listenfd = udpfd;

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(port);

	net_bind(udpfd, (struct sockaddr*) &servaddr, sizeof(servaddr));

	return ipServ;
}

#if 0
void set_udp_server_private(ipc_udp_client_st* ipcServ, void *priv)
{
	ipServ->priv_data = priv;
}

void set_udp_server_recv_func(ipc_udp_client_st* ipcServ, int(*recv_func)(void*))
{
	ipServ->recv_msg = recv_func;
}
#endif

void start_recv_msg(ipc_udp_server_st* ipcServ)
{
	fd_set	rset;
	int	 lintenFd,nready, maxfdp1;

	lintenFd = ipcServ->listenfd;

	FD_ZERO(&rset);
	maxfdp1 = lintenFd + 1;
	for ( ; ; ) { 
		FD_SET(lintenFd, &rset);
		if ( (nready = select(maxfdp1, &rset, NULL, NULL, NULL)) < 0) {
			if (errno == EINTR)
				continue;		/* back to for() */
			else
				hb_print(LOG_ERR,"select error");
		}


		if (FD_ISSET(lintenFd, &rset)) {
			if (ipcServ->recv_msg(ipcServ) < 0) {
				hb_print(LOG_ERR,"udp packet error!");
				continue;
			}

		}
	}
}
#endif

