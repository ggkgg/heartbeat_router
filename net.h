#ifndef _NET_H
#define _NET_H

int set_noblock(int sClient);
int hb_connect(char *host, int port);
int net_recv_msg(struct heartbeat_route_client* hbrc);
int net_send_msg(struct heartbeat_route_client *hbrc,THDR* pHdr,char* pMsg,int msgLen);


#endif

