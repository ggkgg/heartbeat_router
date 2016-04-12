#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "cJSON.h"



int main(int argc, char **argv)
{
    printf("This is a UDP client\n");
    struct sockaddr_in addr;
    int sock;

    if ( (sock=socket(AF_INET, SOCK_DGRAM, 0)) <0)
    {
        perror("socket");
        exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(10400);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (addr.sin_addr.s_addr == INADDR_NONE)
    {
        printf("Incorrect ip address!");
        close(sock);
        exit(1);
    }

    char buff[512];
    int len = sizeof(addr);
    while (1)
    {
//        gets(buff);
        int n;

		cJSON *root,*value;
		
		char *out;

		root=cJSON_CreateObject();


		cJSON_AddStringToObject(root,"cmd_url","/heartbeatclient/business");

		cJSON_AddStringToObject(root,"cmd_name","report");

		cJSON_AddStringToObject(root,"vendor","myed");
		
		cJSON_AddItemToObject(root,"value",value=cJSON_CreateObject());

		cJSON_AddStringToObject(value,"med","xxxxxxxxccccccccccccccccccccccccccccccccccccccccc");		

		out = cJSON_Print(root);
		int outLen = strlen(out);
		
		printf("root(%d) = %s\n",outLen,out);
		strncpy(buff,out,outLen);
		buff[outLen] = '\0';

        n = sendto(sock, buff, strlen(buff), 0, (struct sockaddr *)&addr, sizeof(addr));
        if (n < 0)
        {
            perror("sendto");
            close(sock);
            break;
        }
		
        n = recvfrom(sock, buff, 512, 0, (struct sockaddr *)&addr, &len);
        if (n>0)
        {
            buff[n] = 0;
            printf("received:");
            puts(buff);
        }
        else if (n==0)
        {
            printf("server closed\n");
            close(sock);
            break;
        }
        else if (n == -1)
        {
            perror("recvfrom");
            close(sock);
            break;
        }

		cJSON_Delete(root);
		free(out);

		sleep(5);
		break;
    }
    
    return 0;
}

