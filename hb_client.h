#if CVNWARE
#include "cvnware.h"
#endif

#if MTK
#include "nvram.h"
#endif

#include "profile.h"
#include "hb_core.h"
#include "net.h"


#define DEFAULT_CONFIG_PATH "./hb_client.conf"

//static int init_hbrc(struct heartbeat_route_client *hbrc);
static struct hb_server* get_hbs();
