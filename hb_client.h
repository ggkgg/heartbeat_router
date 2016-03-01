#if CVNWARE
#include "cvnware.h"
#endif

#if MTK
#include "nvram.h"
#endif

#include "common.h"
#include "profile.h"
#include "hb_core.h"



#if 0
enum hbrc_sm_type {
	HBRC_INVALID = 0,
	HBRC_STRAT,
	HBRC_INIT,
	HBRC_WORK,
};


enum hbs_sm_type {
	HBS_INVALID = 0,
	HBS_STRAT,
	HBS_INIT,
	HBS_CHANLLENGE,
	HBS_ECHO,
	HBS_WORK,
};
#endif

enum hbrc_sm_type {
	HBRC_INVALID = 0,
	HBRC_STRAT,
	HBRC_INIT,
	HBRC_IDLE,
	HBRC_CHANLLENGE,
	HBRC_ECHO,
	HBRC_CLEAN,
};


struct echo_thread {
	pthread_t echo_thpid;
	int pause_flag;
};


struct recv_thread {
	pthread_t recv_thpid;
	int pause_flag;
	int flush_flag;
};

struct dispatch_thread {
	pthread_t dispatch_thpid;
	int terminal_flag;
};



struct hbc_conf {
	int echo_interval;
	int retry_count;
	int retry_interval;
	int noecho_interval;
};


struct glob_arg {
	/*command*/
	char* configFile;
	int debuglevel;
	int log_syslog;
	//struct in_addr beforeserverip;
	
	/*hbrc*/
	struct heartbeat_route_client *hbrc;

	
	/*thread*/
	struct echo_thread echoThread;
	struct recv_thread recvThread;
	struct dispatch_thread dispatchThread;
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

#define DEFAULT_CONFIG_PATH "./hb_client.conf"
#define MAX_HB_COUNT 10

//static int init_hbrc(struct heartbeat_route_client *hbrc);
static struct hb_server* get_hbs();



