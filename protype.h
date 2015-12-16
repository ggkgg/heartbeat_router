#ifndef _PROTYPE_H
#define _PROTYPE_H

#include "mytype.h"

#define PKT_VERSION             1

#define PKT_CHALLENGE_MAGIC     0xaa
#define PKT_HDR_MAGIC           0xab

#define CHANLLENGE_KEY  ((char *)"CVNCHINA")

#define PKT_CHALLENGE_REQUEST       101
#define PKT_CHALLENGE_RESPONSE      102

#define PKT_ECHO_REQUEST            103
#define PKT_ECHO_RESPONSE           104

#define PKT_NOTIFY_REQUEST          105
#define PKT_NOTIFY_RESPONSE         106

struct header
{
    u16_t flag;
    u16_t pktlen;
    u8_t  version;
    u8_t  pktType;
    u16_t sn;
    u32_t ext;
};

struct challenge_request
{
    u32_t magic;
    u32_t key;
    u8_t  u8res[8];
};

struct challenge_response
{
    u16_t client_sn;
    u8_t magic[4];
    u8_t key[4];
    u8_t  u8res[6];
};

struct echo_request
{
    i8_t equipmentSn[6];

};

struct echo_response
{
    u16_t client_sn;
};

struct notify_request
{
    i8_t equipmentSn[6];
    u16_t command;
    u32_t sendTime;
};

struct notify_response
{
    u16_t  returnSn;
    u16_t returnCode;
};

enum resp_code
{
    OK = 1,
    AUTH_FAIILED,
    SEND_FAILED,
    USER_NOT_EXISTED,
    UN_AUTHED,
    CONNECT_FAILED,
    USER_TYPE_ERROR
};


struct client_info
{
    u32_t client_key;
    u32_t server_key;
    i32_t client_fd;
    i32_t echo_flag;
    i8_t name[16];
    i8_t password[16];
}; 


typedef struct header THDR;
typedef struct challenge_request TCHALREQ;
typedef struct challenge_response TCHALRESP;
typedef struct echo_request  TECHOREQ;
typedef struct echo_response  TECHORESP;
typedef struct notify_request  TNOTIFYREQ;
typedef struct notify_response  TNOTIFYRESP;


#endif
