#ifndef _NVRAM_H
#define _NVRAM_H 	1

#include <linux/autoconf.h>

/*BEGIN: Modified by huangcd for adding-default-cfg-area, 2013.09.17*/
#if 0
#ifdef CONFIG_DUAL_IMAGE
#define UBOOT_NVRAM	0
#define RT2860_NVRAM    1
#define RTDEV_NVRAM    	2
#define CERT_NVRAM    	3
#define WAPI_NVRAM    	4
#else
#define RT2860_NVRAM    0
#define RTDEV_NVRAM    	1
#define CERT_NVRAM    	2
#define WAPI_NVRAM    	3
#endif
#else
#ifdef CONFIG_DUAL_IMAGE
#define UBOOT_NVRAM     0
#define RT2860_NVRAM    1
#define DEFAULT_NVRAM   2
#define NOUSE_NVRAM     3
#else
#define RT2860_NVRAM    0
#define DEFAULT_NVRAM   1
#define NOUSE_NVRAM     2
#endif
#endif
/*END:   Modified by huangcd for adding-default-cfg-area, 2013.09.17*/

#define NV_DEV "/dev/nvram"
#define RALINK_NVRAM_IOCTL_GET		0x01
#define RALINK_NVRAM_IOCTL_GETALL	0x02
#define RALINK_NVRAM_IOCTL_SET		0x03
#define RALINK_NVRAM_IOCTL_COMMIT	0x04
#define RALINK_NVRAM_IOCTL_CLEAR	0x05

/*BEGIN:Added by huangcd for cfg-bugfix,2013.10.08*/
#define WITHOUT_THIS_CFG "WithoutThisCfg"
/*END:  Added by huangcd for cfg-bugfix,2013.10.08*/

typedef struct environment_s {
	unsigned long crc;		//CRC32 over data bytes
	char *data;
} env_t;

typedef struct cache_environment_s {
	char *name;
	char *value;
} cache_t;

/*BEGIN: Modified by huangcd for adding-default-cfg-area, 2013.09.17*/
//#define MAX_CACHE_ENTRY 500
#define MAX_CACHE_ENTRY 1000
/*END:   Modified by huangcd for adding-default-cfg-area, 2013.09.17*/

typedef struct block_s {
	char *name;
	env_t env;			//env block
	cache_t	cache[MAX_CACHE_ENTRY];	//env cache entry by entry
	unsigned long flash_offset;
	unsigned long flash_max_len;	//ENV_BLK_SIZE

	char valid;
	char dirty;
} block_t;

#define MAX_NAME_LEN 128
#define MAX_VALUE_LEN 1024
typedef struct nvram_ioctl_s {
	int index;
	int ret;
	char *name;
	char *value;
} nvram_ioctl_t;


/*BEGIN: Modified by huangcd for adding-default-cfg-area, 2013.09.17*/
#if 0 
#ifdef CONFIG_DUAL_IMAGE
#define FLASH_BLOCK_NUM	5
#else
#define FLASH_BLOCK_NUM	4
#endif
#else
#ifdef CONFIG_DUAL_IMAGE
#define FLASH_BLOCK_NUM	4
#else
#define FLASH_BLOCK_NUM	3
#endif
#endif
/*END:   Modified by huangcd for adding-default-cfg-area, 2013.09.17*/

void nvram_init(int idx);
void nvram_close(int idx);

int nvram_set(int idx, char *name, char *value);
const char *nvram_get(int idx, char *name);
int nvram_bufset(int idx, char *name, char *value);
char const *nvram_bufget(int idx, char *name);
void loadDefault(int chip_id);

/*BEGIN: Added by huangcd for adding-default-cfg-area, 2013.09.17*/
const char *nvram_get_nodef(int idx, char *name);
char const *nvram_bufget_nodef(int idx, char *name);
/*END:   Added by huangcd for adding-default-cfg-area, 2013.09.17*/

/*BEGIN:Added by huangcd for cfg-bugfix,2013.10.23*/
char const *nvram_bufget_nullstr(int index, char *name);
/*END:  Added by huangcd for cfg-bugfix,2013.10.23*/

void nvram_buflist(int idx);
int nvram_commit(int idx);
int nvram_clear(int idx);
int nvram_erase(int idx);

int getNvramNum(void);
unsigned int getNvramOffset(int idx);
unsigned int getNvramBlockSize(int idx);
char *getNvramName(int idx);
unsigned int getNvramIndex(char *name);
void toggleNvramDebug(void);
void loadDefault(int chip_id);

#endif
