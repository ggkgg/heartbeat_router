#include <sys/socket.h>	/* basic socket definitions */
#include <arpa/inet.h> /* sockaddr_in INADDR_ANY*/
#include <sys/select.h>	/* for convenience */
#include <pthread.h>
#include <errno.h>


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

 


#define	MAXLINE	1024		/* to see datagram truncation */

int net_socket(int family, int type, int protocol)
{
	int		n;

	if ( (n = socket(family, type, protocol)) < 0)
		printf("socket error");
	return(n);
}



void
net_bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
	if (bind(fd, sa, salen) < 0)
		printf("bind error\n");
}


int net_recvfrom(int fd, void *ptr, size_t nbytes, int flags,
		 struct sockaddr *sa, socklen_t *salenptr)
{
	ssize_t		n;

	if ( (n = recvfrom(fd, ptr, nbytes, flags, sa, salenptr)) < 0)
		printf("recvfrom error\n");
	return(n);
}

void
net_sendto(int fd, const void *ptr, size_t nbytes, int flags,
	   const struct sockaddr *sa, socklen_t salen)
{
	if (sendto(fd, ptr, nbytes, flags, sa, salen) != (ssize_t)nbytes)
		printf("sendto error\n");
}

void thread_recv_udpmsg(void *data)
{
	int udpfd,*pudpfd;
	struct sockaddr_in cliaddr;
	char mesg[MAXLINE];
	int			n;
	socklen_t	len;

	pudpfd = (int *)data;
	udpfd = *pudpfd;
	len = sizeof(cliaddr);
	n = net_recvfrom(udpfd, mesg, MAXLINE, 0, (struct sockaddr*) &cliaddr, &len);

	call_ipchelper(udpfd,&cliaddr,mesg);

	net_sendto(udpfd, mesg, n, 0, (struct sockaddr*) &cliaddr, len);

}


int udp_server(int argc, int port)
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
				printf("select error");
		}


		if (FD_ISSET(udpfd, &rset)) {

			
			ret=pthread_create(&pth_ids,NULL,(void *)thread_recv_udpmsg,(void*)&udpfd);
			if(ret!=0)
			{
				printf ("Create pthread error!\n");
				exit(1);
			}
			pthread_detach(pth_ids);


		}
	}
}
/* end udpservselect02 */

