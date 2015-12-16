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


int do_challange(int fd)
{

    if(fd <= 0)
    {
        printf("%s error fd = %d\n", __FUNCTION__, fd);
        return -1;
    }

    THDR chal_header;
    THDR *pHdr = &chal_header;

    pHdr->flag = PKT_HDR_MAGIC;
    pHdr->pktlen = sizeof(TCHALREQ);
    pHdr->version = PKT_VERSION;
    pHdr->pktType = PKT_CHALLENGE_REQUEST;
    pHdr->sn = 10001;

    TCHALREQ chal_reqmsg;
    TCHALREQ *pReq = &chal_reqmsg;

    pReq->magic = PKT_CHALLENGE_MAGIC;
    pReq->key = (u32_t)time(NULL);
	
    memset(pReq->u8res, 0x08, sizeof(pReq->u8res));

    unsigned char deschal[64];
    memset(deschal, 0, sizeof(deschal));

    int bytes = sizeof(TCHALREQ);

    des_encode((const void *)pReq, deschal, CHANLLENGE_KEY, bytes);

    pHdr->pktlen = bytes;

    send(fd, pHdr, sizeof(THDR), 0);
    send(fd, deschal, bytes, 0);

    return 1;
}


