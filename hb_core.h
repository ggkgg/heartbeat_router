#ifndef _HB_CORE_H
#define _HB_CORE_H

#include "common.h"
#include "protype.h"


enum hbrc_sm_type {
	HBRC_INVALID = 0,
	HBRC_STRAT,
	HBRC_INIT,
	HBRC_IDLE,
	HBRC_CHANLLENGE,
	HBRC_ECHO,
	HBRC_CLEAN,
};

struct hbc_conf {
	int echo_interval;
	int retry_count;
	int retry_interval;
	int noecho_interval;
};

/* 心跳路由客户端  */
struct heartbeat_route_client {
	int hbrc_sm;
	struct hb_server **hbs_head;
	struct hb_server *current_hbs;
	struct hbc_conf hbrc_conf;
	int hbs_count;

	/* connect param*/
	char equipmentSn[6];
	int hbrc_sockfd;
	int sendsn;
	u32_t session_server_key;
	u32_t session_client_key;

	/*recv buff*/
    char* gbuf;
    int dataLen;
    int maxLen;
	int activeRecvFlag;

};

/* 心跳路由客户端的服务器列表 */
struct hb_server {
	//int hbs_sm;

	struct in_addr hbs_ip;
	int hbs_port;
	int hbs_index;
	int try_conn;
	int used;	
};

#define MAX_HB_COUNT 10
#endif
