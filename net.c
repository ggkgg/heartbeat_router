#include "hb_core.h"

int set_noblock(int sClient)
{
    int opts;

    opts = fcntl(sClient, F_GETFL);

    if(opts < 0)
    {
        perror("fcntl(sock,GETFL)");
        exit(1);
    }

    opts = opts | O_NONBLOCK;

    if(fcntl(sClient, F_SETFL, opts) < 0)
    {
        perror("fcntl(sock, SETFL, opts)");
        exit(1);
    }

    return 0;
}

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


int ishdrValid(char *pBuff, u32_t len)
{
    THDR *pHdr;

    if(len < sizeof(THDR))
    {
        return -1;
    }

    pHdr = (THDR *)pBuff;

    unsigned int needlen = sizeof(THDR) + pHdr->pktlen;

    if(len < needlen)
    {
        return -2;
    }

    if(pHdr->flag != PKT_HDR_MAGIC)
    {
        hb_print(LOG_ERR, "recv invalid pkt, recv magic=0x%X, right=0x%X\n", pHdr->flag, PKT_HDR_MAGIC);
        return -3;
    }

    return 1;
}

void *recvMalloc(u32_t len)
{
    void *p = malloc(len);

    if(p == NULL)
    {
        return NULL;
    }
    else
    {
        memset(p, 0, len);
        return p;
    }
}


int net_recv_challage_msg(struct heartbeat_route_client* hbrc,THDR *pHdr,TCHALRESP  *pResp)
{
	fd_set read_fds;
	int maxsock;
	struct timeval tv;
	int ret;
	int chanResqLen;
	char revBuffer[128] = {0};
	int recbytes,recTolBytes = 0;
	
	chanResqLen = sizeof(THDR) + sizeof(TCHALRESP);
	while (recTolBytes < chanResqLen) {
		char revdata[128] = {0};
		maxsock = hbrc->hbrc_sockfd;
		// timeout setting
		tv.tv_sec = 5;
		tv.tv_usec = 0;
	
		// initialize file descriptor set
		FD_ZERO(&read_fds);
		FD_SET(hbrc->hbrc_sockfd, &read_fds);
		ret = select(maxsock + 1, &read_fds, NULL, NULL, &tv);
		if (ret < 0) {
			hb_print(LOG_ERR, "[Fail] create select !");
			break;
		} else if (ret == 0) {
			hb_print(LOG_INFO, "select timeout!");
			return -1;
		}			
		if (FD_ISSET(hbrc->hbrc_sockfd, &read_fds)) {
			recbytes = read(hbrc->hbrc_sockfd, revdata, 128);
			memcpy(&revBuffer[recTolBytes],revdata,recbytes);
			recTolBytes += recbytes;
		}
	}
	
	pHdr = (THDR *)revBuffer;
	memcpy(pHdr,revBuffer,sizeof(THDR));
	
	des_decode((void *)(revBuffer + sizeof(THDR)), pResp, CHANLLENGE_KEY, sizeof(*pResp));
	return 0;
}

int net_send_challage_msg(struct heartbeat_route_client *hbrc,THDR* pHdr,char* pMsg,int msgLen)
{
	int fd;
    unsigned char deschal[64];


	fd = hbrc->hbrc_sockfd;
    if(fd <= 0)
    {
        printf("%s error fd = %d\n", __FUNCTION__, fd);
        return -1;
    }

	pHdr->pktlen = msgLen;
    memset(deschal, 0, sizeof(deschal));
    des_encode((const void *)pMsg, deschal, CHANLLENGE_KEY, msgLen);
    
    send(fd, pHdr, sizeof(THDR), 0);
    send(fd, deschal, msgLen, 0);
}


int net_recv_msg(struct heartbeat_route_client* hbrc)
{
    char buff[512] = {0};

    char *oldBuff = hbrc->gbuf;
    int dataLen = hbrc->dataLen;
    int maxLen = hbrc->maxLen;

	int fd = hbrc->hbrc_sockfd;


    while(1)
    {
        int len = read(fd, buff, 256);

        if(len < 0)
        {
            buff[0] = 0;
			/* 非阻塞模式下，没有数据返回EAGAIN，跳出循环 
			hb_print(LOG_ERR, "[Fail] read < 0 bytes ,errno(%d) %s!",errno,strerror(errno));
			*/
            if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
            {
                break;
            }
			
			/* mips平台下，设置非阻塞模式，没有数据返回0，表示success，平台bug? */
			if(errno == 0)
				break;
#if 0
            else
            {
            	hb_print(LOG_ERR, "[Fail] read < 0 bytes ,set activeRecvFlag 0!");
                hbrc->activeRecvFlag = 0;
                return -1;
            }
#endif
        }
		/* 当服务器关闭，链接断开，select会立即返回可读，read后的len等于0*/
        else if(len == 0)
        {
			hb_print(LOG_ERR, "[Fail] read = 0 bytes, seesion have closed!");
            buff[len] = 0;
#if 0
            hbrc->activeRecvFlag = true;
#endif
            return -1;
        }

        int totalLen = dataLen + len;

        if(oldBuff == NULL && maxLen == 0)
        {
            oldBuff = (char *)recvMalloc(512);

            if(oldBuff == 0)
            {
#if 0
                hbrc->activeRecvFlag = 0;
#endif
				hb_print(LOG_ERR, "Fail to malloc memory for oldBuff!");
                return -1;
            }

            hbrc->gbuf = oldBuff ;
            hbrc->maxLen = 512;
            maxLen = 512;
        }

        if(totalLen <= maxLen)
        {
            memcpy(oldBuff + dataLen, buff, len);
            dataLen += len;
            hbrc->dataLen = dataLen;
        }
        else
        {
            char *newBuff = (char *)recvMalloc(totalLen);

            if(newBuff == 0)
            {
#if 0
                hbrc->activeRecvFlag = 0;
#endif
				hb_print(LOG_ERR, "Fail to malloc memory for newBuff!");
                return -1;
            }

            hbrc->gbuf = newBuff ;
            hbrc->maxLen = totalLen;
            maxLen = totalLen;

            memcpy(newBuff, oldBuff, dataLen);
            memcpy(newBuff + dataLen, buff, len);

            dataLen += len;
            hbrc->dataLen = dataLen;
            free(oldBuff);
            oldBuff = newBuff;

        }

        char *recvBuff = hbrc->gbuf;

		/* 取出数据, 分析报文 */
        while(1)
        {
            if(dataLen == 0)
            {
                break;
            }

            int invalidFlag = ishdrValid(recvBuff, dataLen);

            if(invalidFlag < 0 && invalidFlag != -3)
            {
                break;
            }

            if(invalidFlag == -3)
            {
                THDR *pHdr;
                pHdr = (THDR *)recvBuff;
                int needLen = 0;
                needLen = sizeof(THDR) + pHdr->pktlen;
                dataLen = dataLen - needLen;
                memcpy(recvBuff, recvBuff + needLen, dataLen);
                hbrc->dataLen = dataLen;
                continue;
            }

            int remainLen = proc_packet(hbrc, recvBuff, dataLen);

            if(remainLen > 0)
            {
                memcpy(recvBuff, recvBuff + dataLen - remainLen, remainLen);
            }

            dataLen = remainLen;
            hbrc->dataLen = dataLen;
        }
    }	
}


int net_send_msg(struct heartbeat_route_client *hbrc,THDR* pHdr,char* pMsg,int msgLen)
{
	int fd = hbrc->hbrc_sockfd;

    if(fd <= 0)
    {
        printf("%s error fd = %d\n", __FUNCTION__, fd);
        return -1;
    }

	char encodeMsg[256]={0};
	pHdr->pktlen = msgLen;

	XORencode(pMsg, encodeMsg, hbrc->session_server_key, pHdr->pktlen);

	send(fd, pHdr, sizeof(THDR), 0);
	send(fd, encodeMsg, pHdr->pktlen, 0);
}


