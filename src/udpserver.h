

/* ����·�ɿͻ��˵ķ������б� */
struct hb_server {
	//int hbs_sm;

	struct in_addr hbs_ip;
	int hbs_port;
	int hbs_index;
	int try_conn;
	int used;	
};

struct ipc_udp_client_s
{
};
