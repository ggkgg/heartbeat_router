#include "hb_core.h"

int hb_connect(char *host, int port)
{
    struct sockaddr_in addr;

    int clientfd = socket(AF_INET, SOCK_STREAM, 0);

    if(clientfd <= 0)
    {
        return -1;
    }

    hb_print(LOG_INFO," socket new fd %d \n", clientfd);
  
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    int i = connect(clientfd, (struct sockaddr *)&addr, sizeof(addr));

    if(i < 0 && errno != EINPROGRESS)
    {

        hb_print(LOG_ERR,"errno(%d) %s", errno,strerror(errno));
        close(clientfd);
        return -1;
    }
    else
    {
        return clientfd;
    }
}

