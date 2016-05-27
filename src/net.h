#ifndef _NET_H
#define _NET_H

#include "hb_core.h"


int set_noblock(int sClient);
int hb_connect(char *host, int port);
int net_recv_msg(struct heartbeat_route_client* hbrc);
int net_send_msg(struct heartbeat_route_client *hbrc,THDR* pHdr,char* pMsg,int msgLen);
int net_recv_challage_msg(struct heartbeat_route_client* hbrc,THDR *pHdr,TCHALRESP  *pResp);
int net_send_challage_msg(struct heartbeat_route_client *hbrc,THDR* pHdr,char* pMsg,int msgLen);
int proc_echoresp(struct heartbeat_route_client* hbrc, char *pBuff);
int proc_notifyreq(struct heartbeat_route_client* hbrc, char *pBuff);
int proc_packet(struct heartbeat_route_client* hbrc, char *pBuff, int readLen);
void print_hdr(THDR  *tHdr);
void print_chalreq(THDR  *tHdr, TCHALREQ  *chalReq);
void print_chalresp(THDR  *tHdr, TCHALRESP  *chalResp);
void print_echoreq(THDR  *tHdr, TECHOREQ  *echoReq);
void print_echoresp(THDR  *tHdr, TECHORESP *echoResp);
void print_notifyreq(THDR  *tHdr,TNOTIFYREQ  *notifyReq);
void print_notifyresp(THDR  *tHdr,TNOTIFYRESP* notifyResp);

#endif

