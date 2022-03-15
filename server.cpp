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
pthread_mutex_t lock;

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
int bindSocket(int sockfd){
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(3490);
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addrlen = sizeof(servaddr);

	int ret = bind(sockfd, (struct sockaddr*)&servaddr, (socklen_t)addrlen);
	return ret;
}
int listenSocket(int sockfd){
	int ret = listen(sockfd, 50);
	return ret;
}
int acceptSocket(int sockfd){
	int ret = accept(sockfd, (struct sockaddr*)&servaddr, (socklen_t*)&addrlen);
	return ret;
}
int receiveData(int sockfd){
	int n;
	int* buf = (int*)malloc(sizeof(int));
	ssize_t ret = recv(sockfd, (void*)buf, sizeof(int), 0);
	if(ret != -1 && buf != NULL){
		n = *buf;
		free(buf);
		printf("%d\n", n);
		return n;
	}
	return ret;
}
FILE* writeFile(int n){
	FILE *fp ;
	fp = fopen("sfile.txt", "w");
	char data[10000];
	strcpy(data, findTop(n));
	if (fp != NULL) {
        fputs(data, fp);
		printf("%s\n", data);
        fclose(fp);
        printf("Data written to file successfully.\n");
        return fp;
    }  
    return NULL; 
}
int sendFile(int sockfd){
	FILE *fp ;
	fp = fopen("sfile.txt", "r");
	if(fp != NULL) {
	    char data[6000];
	    char buf[6000];
	    bzero(buf, sizeof(buf));
		int buflen = sizeof(buf);
		printf("%s\n", "Sending file...\n");
        while(fgets(data, 6000, fp) != NULL) {
            strcat(buf, data);
            bzero(data, sizeof(data));
        }
        fclose(fp);
        printf("%s\n", buf);
        ssize_t ret = send(sockfd, (void*)buf, buflen, 0);
		if(ret != -1){
        	printf("File sent successfully.\n");
			return 0;
		}
    }
	return -1;
}
int receiveFile(int sockfd){
	char buf[6000];
	int buflen = sizeof(buf);
	ssize_t ret = recv(sockfd, buf, buflen, 0);
	if(ret != -1 && buf != NULL){
		printf("\nReceiving file...\n");
		printf("%s\n", buf);
		FILE *fp ;
		fp = fopen("clientdata.txt", "w");
		if(fp != NULL) {
	        fputs(buf, fp);
	        fclose(fp) ;
	        printf("File received successfully.\n");
	        return 0;
	    }
	}
	return -1;
}
int closeSocket(int sockfd){
	int ret = close(sockfd);
	return ret;
}
void* manageClient(void* pcliSockfd){
	pthread_mutex_lock(&lock);
	int cliSockfd = *((int*)pcliSockfd);
	int rcvret = receiveData(cliSockfd);
	if(rcvret == -1){
		printf("%s\n", "Error! Data could not be received.");
		return NULL;
	}
	if(writeFile(rcvret) == NULL){
		printf("File write failed.") ;
		return NULL;
	}
	if(sendFile(cliSockfd) == -1){
		printf("%s\n", "Error! File could not be sent.");
		return NULL;
	}
	if(receiveFile(cliSockfd) == -1){
		printf("%s\n", "Error! File could not be received.");
		return NULL;
	}
	pthread_mutex_unlock(&lock);
	return NULL;
}

int main(){
	int serSockfd = createSocket();
	if(serSockfd == -1){
		printf("%s\n", "Error! Socket could not be created.");
		return 0;
	}
	if(bindSocket(serSockfd) == -1){
		printf("%s\n", "Error in binding!");
		return 0;
	}
	if(listenSocket(serSockfd) == -1){
		printf("%s\n", "Error in listening!");
		return 0;
	}
	pthread_mutex_init(&lock, NULL);
	while(1){
		int cliSockfd = acceptSocket(serSockfd);
		if(cliSockfd == -1){
			printf("%s\n", "Error in accepting!");
			return 0;
		}
		pthread_t tid;
		int* pclient = (int*)malloc(sizeof(int));
		*pclient = cliSockfd;
		pthread_create(&tid, NULL, manageClient, pclient);
		sleep(30);
		pthread_join(tid, NULL);
	}
	pthread_mutex_destroy(&lock);
	if(closeSocket(serSockfd) == -1){
		printf("%s\n", "Error in closing!");
		return 0;
	}
	return 0;
}