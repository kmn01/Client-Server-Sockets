#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pthread.h>
#include <dirent.h>
#include <ctype.h>
#include <queue>
#include <fcntl.h>
using namespace std;

struct sockaddr_in servaddr;
int addrlen;
char procdata[10000];

struct proc{
	int pid;
	char pname[100];
	unsigned long ucpu;
	unsigned long kcpu;
    unsigned long totcpu;
    proc(int pid1, char pname1[], int ucpu1, int kcpu1){
        pid = pid1;
        strcpy(pname, pname1);
        ucpu = ucpu1;
        kcpu = kcpu1;
        totcpu = ucpu1 + kcpu1;
    }
};
struct comparator {
    bool operator()(proc const& p1, proc const& p2) {
        return p1.totcpu < p2.totcpu;
    }
};
char* findTop(int n){
    priority_queue<proc, vector<proc>, comparator> q;
	DIR *procdir;
    procdir = opendir("/proc");
    if(procdir == NULL) {
        printf("%s\n", "Proc directory open failed.\n");
        return NULL;
    }
    struct dirent *entry;
    while((entry = readdir(procdir)) != NULL) {
    	int flag = 0;
        char *ptr;
	    for (ptr = entry->d_name; *ptr; ptr++) {
	        if(!isdigit(*ptr)){
	            flag = 1;
	        }
	    }
        if(flag == 1){
            continue;
        }
        char path[267];
        snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
        int fd = open(path, O_RDONLY);
        if(fd == -1) {
            printf("%s\n", "Stat file open failed.");
            continue;
        }
        int pid;
        char pname[100];
		unsigned long ucpu;
		unsigned long kcpu;
        int ctr = 0;
        char buf[1];
        char data[100];
        FILE* fp = fdopen(fd, "r");
        fscanf(fp, "%d %s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu ", &pid, pname, &ucpu, &kcpu);
        q.push(proc(pid, pname, ucpu, kcpu));
        close(fd);
    }
    closedir(procdir);
    bzero(procdata, sizeof(procdata));
    for (int i = 0; i < n; i++) {
        proc p = q.top();
        q.pop();
        char buf[500];
        snprintf(buf, sizeof(buf), "PID: %5d PName: %-20s CPU Usage(User, Kernel, Total): %lu %lu %lu\n", p.pid, p.pname, p.ucpu, p.kcpu, p.totcpu);
        strcat(procdata, buf);
    }
    return procdata;
}
int createSocket(){
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	return sockfd;
}
int connectSocket(int sockfd){
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(3490);
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addrlen = sizeof(servaddr);

	int ret = connect(sockfd, (struct sockaddr*)&servaddr, (socklen_t)addrlen);
	return ret;
}
int sendRequest(int sockfd){
	char buf1[6000];
	printf("Enter n: \n");
	int n;
	scanf("%d", &n);
	int* nptr = &n;
	ssize_t ret = send(sockfd, (void*)nptr, sizeof(int), 0);
	if(ret != -1){
		printf("Request sent.\n");
		return 0;
	}
	return -1;
}
int receiveFile(int sockfd){
	char buf[6000];
	int buflen = sizeof(buf);
	ssize_t ret = recv(sockfd, buf, buflen, 0);
	//ssize_t ret = read(sockfd, buf, buflen);
	if(ret != -1){
		printf("Receiving file...\n");
		printf("%s\n",buf);
		FILE *fp ;
		fp = fopen("serverdata.txt", "w");
		if (fp != NULL) {
	        fputs(buf, fp);
	        fclose(fp);
	        printf("File received successfully.\n");
	    }
	}
	return ret;
}
int sendData(int sockfd){
	char data[10000];
	strcpy(data, findTop(1));
	if(data != NULL) {
		printf("%s\n", "Sending data...\n");
		printf("%s\n", data);
        ssize_t ret = send(sockfd, (void*)data, sizeof(data), 0);
		if(ret != -1){
        	printf("Data sent successfully.\n");
			return 0;
		}
    }
	return -1;
}
int closeSocket(int sockfd){
	int ret = close(sockfd);
	return ret;
}
int main(){
	int sockfd = createSocket();
	if(sockfd == -1){
		printf("%s\n", "Error! Socket could not be created.");
		return 0;
	}
	if(connectSocket(sockfd) == -1 ){
		printf("%s\n", "Error in connecting!");
		return 0;
	}
	if(sendRequest(sockfd) == -1){
		printf("%s\n", "Error! Request could not be sent.");
		return 0;
	}
	if(receiveFile(sockfd) == -1){
		printf("%s\n", "Error! File could not be received.");
		return 0;
	}
	if(sendData(sockfd) == -1){
		printf("%s\n", "Error! Data could not be sent.");
		return 0;
	}	
	sleep(30);
	if(closeSocket(sockfd) == -1){
		printf("%s\n", "Error in closing!");
		return 0;
	}
	pthread_exit(NULL);
	printf("%s\n", "--Client program ends here--");
	return 0;
}