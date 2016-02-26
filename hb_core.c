#include "hb_core.h"

#if 0
int hb_connect(char *host, int port)
{
    struct sockaddr_in addr;

    int clientfd = socket(AF_INET, SOCK_STREAM, 0);

    if(clientfd <= 0)
    {
        return -1;
    }
  
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    //addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_addr.s_addr = inet_addr("115.239.210.27");
    addr.sin_port = htons(port);

    int i = connect(clientfd, (struct sockaddr *)&addr, sizeof(addr));

    if(i < 0 && errno != EINPROGRESS)
    {

        hb_print(LOG_ERR,"connect (%s) errno(%d) %s",host,errno,strerror(errno));
        close(clientfd);
        return -1;
    }
    else
    {
        return clientfd;
    }
}
#else
/*
int connect_server(struct in_addr serverIp,int timeout){
    int c_socket;
    struct sockaddr_in s_add;
    unsigned short portnum = 18000;
  
    //建立socket连接
    c_socket = socket (AF_INET, SOCK_STREAM, 0);
    if (-1 == c_socket){
      	debug(targs.debuglevel,DEBUG_DETAIL, "[connect_server] socket fail ! \r\n");
        return -1;
    }
 
    struct timeval tm;
    fd_set set;
    unsigned long ul = 1;
    int error=-1, len;
    len = sizeof(int);
    ioctl(c_socket, FIONBIO, &ul); //设置为非阻塞模式
    bool ret = false;

    bzero(&s_add, sizeof (struct sockaddr_in));
    s_add.sin_family = AF_INET;
    s_add.sin_addr.s_addr = serverIp.s_addr;
    s_add.sin_port = htons (portnum);
    debug(targs.debuglevel,DEBUG_DETAIL, "conncect serverip %s:%d", inet_ntoa(s_add.sin_addr),portnum);

    if (-1 == connect (c_socket, (struct sockaddr *) (&s_add), sizeof (struct sockaddr))){
    	tm.tv_sec = timeout;
    	tm.tv_usec = 0;
    	FD_ZERO(&set);
    	FD_SET(c_socket, &set);
    	if( select(c_socket+1, NULL, &set, NULL, &tm) > 0)
    	{
    	    getsockopt(c_socket, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
    	    if(error == 0)
            {   
    	    	ret = true;
            }
    		else 
            {         
    			ret = false;
            }
    	} 
        else 
    	{
    		ret = false;
    	}
    }else{
    	ret = true;
    }
	ul = 0;
	ioctl(c_socket, FIONBIO, &ul); //设置为阻塞模式
	if(!ret)
	{
		close(c_socket);
		debug(targs.debuglevel,DEBUG_DETAIL, "Cannot Connect the server %s:%d",inet_ntoa(s_add.sin_addr),portnum);
		return -1;
	}
  
    return c_socket;
}
*/

int hb_connect(char *host, int port)
{
    struct sockaddr_in addr;
    int error = -1, len;
    int ret = -1;	
    int err = 0;
    struct timeval tm;
    fd_set read_set;
    fd_set write_Set;


    int clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if(0 >= clientfd)
    {
        printf("socket failed\n");
        return -1;
    }

	set_noblock(clientfd);//设置为非阻塞模式
    
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    //addr.sin_addr.s_addr = inet_addr("115.239.210.27");
    addr.sin_port = htons(port);

    ret = connect(clientfd, (struct sockaddr *)&addr, sizeof(addr));
    if (0 == ret)
    {
        printf("connect to heartbeat server ok");
        return (clientfd);
    }

    tm.tv_sec = 5;
    tm.tv_usec = 0;
    FD_ZERO(&read_set);
    FD_SET(clientfd, &read_set);
    write_Set = read_set;
    ret = select(clientfd+1, &read_set, &write_Set, NULL, &tm);
    if (0 > ret)
    {
        printf("select failed\n");
        close(clientfd);
        return (-1);
    }

    if (0 == ret)
    {   
        printf("timeout, connect to server failed\n");
        close(clientfd);
        return (-1);
    }

    if (FD_ISSET(clientfd, &read_set) && FD_ISSET(clientfd,  &write_Set)) 
    {
        printf("readable and writable, Connect to server failed\n");
        close(clientfd);
        return (-1);
    }

    if (!FD_ISSET(clientfd, &read_set) && FD_ISSET(clientfd,  &write_Set)) 
    {
        printf("Unreadable but writable, connect to server OK\n");
        return (clientfd);
    }

    close(clientfd);
    return (-1);
}

#endif
