#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <sys/types.h> 
#include <arpa/inet.h>
#include "mbus.h"
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/resource.h>
#include <limits.h>
#define pr() printf("%s %s %d\n", __FILE__, __func__, __LINE__)
extern struct mbus_tcp_func tcp_func;

int _check_para(struct send_info *info)
{
	if (info->sbuf[6] == (char)0xf1){
		return 0;
	}	
	if (info->sbuf[7] > 6 && info->sbuf[7] < 1){
			printf("Function code :\n");
			printf("1        Read Coil Status\n");
			printf("2        Read Input Status\n");
			printf("3        Read Holding Registers\n");
			printf("4        Read Input Registers\n");
			printf("5        Force Single Coil\n");
			printf("6        Preset Single Register\n");
			return -1;
	}
	
	if(info->sbuf[7] == 5){
		if(info->sbuf[10] && info->sbuf[11]){
			info->sbuf[10] = 0xff;
			info->sbuf[11] = 0x0;
		}
	}	
	return 0;
}

int _create_sk_cli(char *addr, char *port)
{
	int skfd;
	int ret;
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *p;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;

	ret = getaddrinfo(addr, port, &hints, &res);
	if(ret != 0){
		printf("<Modbus Tcp Master> getaddrinfo : %s\n", gai_strerror(ret));
		return -1;
	}

	for(p = res; p != NULL; p = p->ai_next){
		skfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(skfd == -1){
			continue;
		}

		ret = connect(skfd, p->ai_addr, p->ai_addrlen);
		if(ret == -1){
			close(skfd);
			continue;
		}
		break;
	}

	if(p == NULL){
		if (skfd > 0)
			close(skfd);
		printf("<Modbus Tcp Master> Fail to connect\n");
 		return -1;
	}

	freeaddrinfo(res);
	
	return skfd;
}


struct send_info *create_connect(char *ip, char *port)
{
	struct send_info *info = malloc(sizeof(struct send_info));
	if (!info){
		return NULL;
	}
	info->ip = ip;
	info->port = port;
	info->skfd = _create_sk_cli(ip, port);
	if(info->skfd < 0){
		free(info);
		return NULL;
	}
	return info;
}

void del_connect(struct send_info *info)
{
	close(info->skfd);
	free(info);
}

void set_data(struct send_info *info, char *buf, int len)
{
	info->sbuf[0] = INITTCPTRANSID >> 8;
	info->sbuf[1] = INITTCPTRANSID & 0xFF;
	info->sbuf[2] = TCPMBUSPROTOCOL >> 8;;
	info->sbuf[3] = TCPMBUSPROTOCOL & 0XFF;;
	info->sbuf[4] = (len >> 8) & 0xFF;
	info->sbuf[5] = len & 0xFF;
	memcpy(&(info->sbuf[6]), buf, len);
	info->len = len + 6;
}

int send_date(struct send_info *info, char *rbuf, int len)
{
	int ret;
	int wlen;
	int rlen;
	struct tcp_frm_para pa;

	ret = _check_para(info);
	if(ret == -1){
		return ret;
	}

         wlen = send(info->skfd, info->sbuf, info->len, MSG_NOSIGNAL);
	 if(wlen != info->len){
		return -1;
	 }

	 if (info->sbuf[6] == (char)0xF1){
		 return 0;
	 }	

	 rlen = recv(info->skfd, rbuf, len, 0);
	 if(rlen < 1){
		return -1;
	 }

	pa.transID = (info->sbuf[0] << 8) + info->sbuf[1];  
	pa.potoID = (info->sbuf[2] << 8) + info->sbuf[3];  
	pa.msglen = (info->sbuf[4] << 8) + info->sbuf[5];  
	pa.unitID = info->sbuf[6];
	pa.fc = info->sbuf[7];
	pa.straddr = (info->sbuf[8] << 8) + info->sbuf[9];
	pa.act = (info->sbuf[10] << 8) + info->sbuf[11];
	pa.len = (info->sbuf[10] << 8) + info->sbuf[11];

	 ret = tcp_func.chk_dest((struct tcp_frm *)rbuf, &pa);
	 if(ret == -1){
		return -1;
	 }
	
	 ret = tcp_func.resp_parser((unsigned char *)rbuf, &pa, rlen);
	 if(ret == -1){
		return -1;
	 }
	
	return ret == -1 ? -1 : rlen;
}	



int main_2(int argc, char **argv, char *rbuf)
{
	struct send_info *info;
	char obuf[] = {0xf1, 0x01, 0x04, 0x09,0x06, 0xfe};
	char sbuf[] = {0x01, 0x03, 0x00, 0x00,0x00, 0x01};
	char buf[32];
	int tem;
	int len;
	
	if ((info = create_connect(argv[1], argv[2])) == NULL){
		printf("Can't create a connect to %s:%s\n", argv[1], argv[2]);
		return 0;
	}
	

	set_data(info, sbuf, sizeof(sbuf));

	len = send_date(info, rbuf, 32);
       	if (len < 0){
		printf("send error\n");
		return 0;
	}
int i;
for(i = 0 ; i < len; i++){
	printf("%d ", rbuf[i]);
		
}
printf("\n");
	tem = (rbuf[9] << 8) + rbuf[10];	
	obuf[2] = (tem % 1000) / 100;
	obuf[3] = ((tem % 100) / 10) | 0x80;
	obuf[4] = (tem % 10);

	set_data(info, obuf, sizeof(obuf));
	len = send_date(info, buf, 32);
       	if (len < 0){
		printf("send error\n");
		return 0;
	}
	printf("%d\n", tem);
	del_connect(info);
	return tem;
	
}

#define LOCKFILE "/var/run/mbtd.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

static int already_running()
{
	int fd;
	char buf[16];
	struct flock flock;	

	fd = open (LOCKFILE, O_RDWR | O_CREAT, LOCKMODE);
	if (fd < 0){
		printf("Can't open %s: %s\n", LOCKFILE, strerror(errno));
		return -1;
	}
	
	flock.l_type = F_WRLCK;
	flock.l_start = 0;
	flock.l_whence = SEEK_SET;
	flock.l_len = 0;

	if (fcntl(fd, F_SETLK, &flock) < 0){
		if (errno == EACCES || errno == EAGAIN){
			close(fd);
			printf("mbtd has been running\n");
			return 1;
		}
		printf("Can't open %s: %s\n", LOCKFILE, strerror(errno));
		return -1;
	}
	
	ftruncate(fd, 0);
	sprintf(buf, "%ld", (long)getpid());
	write(fd, buf, strlen(buf));
	return 0;
}

int prepare_for_daemon()
{
	int fd0, fd1, fd2;
	pid_t pid;
	int i;
	struct rlimit rl;
	struct sigaction sa;
	umask(0);

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0){
		perror("Can't get file limit\n");
		return -1;
	}
	
	if ((pid = fork()) < 0){
		perror("Can't fork\n");
		return -1;
	}
	else if (pid != 0){
		exit(0);
	}

	setsid();

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	
	if (sigaction(SIGHUP, &sa, NULL) < 0){
		perror("Can't ignore SIGHUP\n");
		return -1;
	}

	if ((pid = fork()) < 0){
		perror("Can't fork\n");
		return -1;
	}
	else if (pid != 0){
		exit(0);
	}

	if (chdir("/") < 0){
		perror("Can't chdir to \n");
		return -1;
	}

	if (rl.rlim_max == RLIM_INFINITY)
		rl.rlim_max = 1024;

	for (i = 0; i < rl.rlim_max; i++)
		close(i);

	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);

	if (fd0 != 0 || fd1 != 1 || fd2 != 2){
		perror("Unexpected file descriptors\n");
		return -1;
	}
	return 0;

}

int main(int argc, char **argv)
{
	int sock;
	int cli;
	struct sockaddr_in self;
 	char buf[2][32];

	if (prepare_for_daemon() < 0)
		return 0;

	if (already_running())
		return 0;
	

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("Can't create a socket\n");
		return 0;
	}

	bzero(&self, sizeof(self));
	self.sin_family = AF_INET;
	self.sin_port = htons(502); 
	self.sin_addr.s_addr = htonl(INADDR_ANY); //inet_addr("127.0.0.1");

	if (bind(sock, (struct sockaddr*)&self, sizeof(self)) != 0 ){
		printf("Can't bind %s\n", strerror(errno));
		close(sock);
		return 0;
	}

		pr();
	if (listen(sock, 5) < 0){
		printf("listen failed\n");
		close(sock);
		return 0;
	}
		pr();
	int len;
	while(1){
		pr();
		cli = accept(sock, NULL, NULL);
		if (cli < 0){
		pr();
			break;
		}
		pr();
		len = recv(cli, buf[0], 32, 0);
		pr();
		main_2(argc, argv, buf[1]);
		pr();
		memcpy(&buf[1][0], &buf[0][0], 6);
		pr();
		send(cli, buf[1], len, 0);
		pr();
		close(cli);
	}
	close(sock);
	return 0;
}
