#include "hb_core.h"

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
