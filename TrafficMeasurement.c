/*
	> Need to the PacketAnalysisService file

	> compile
	gcc -o TrafficMeasurement TrafficMeasurement.c

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

void NetworkTrafficMeasurement();

/*
	main 함수는 데몬 프로세스 생성에 관여
*/
int main(void)
{
	int pid;
	int ret;

	pid = fork();

	if(pid < 0){
		printf("fork Error ... : return is [%d]\n", pid);
		perror("fork Error : ");
		exit(0);
	} else if(pid > 0){
		exit(0);
	}

	signal(SIGHUP, SIG_IGN);
	close(0);
	close(1);
	close(2);

	chdir("/");
	
	setsid();

	while(1){
		if((pid = fork()) < 0){
			printf("fork error : restart daemon\n");
		} else if(pid == 0){
			break;
		} else if(pid > 0){
			wait(&ret);
		}
		
		// 300초 주기마다 NetworkTrafficMeasurement 함수를 실행한다.
		NetworkTrafficMeasurement();
		sleep(300); // Set interval 5 Min == 300 sec
	}
}

void NetworkTrafficMeasurement()
{
	FILE *fp = NULL;
	double trafficDoubleValue;
	/*
		vnStat 네트워크 모니터링 프로그램 쉘 실행 구문
		-i : 인터페이스를 의미
		-tr : 트래픽 계산
		| grep "rx" : 나가는 트래픽이 아닌 들어오는 트래픽 양만을 표시
	*/
	char command[100] = "vnstat -i p4p1 -tr | grep \"rx\""; // Set rx
	char trafficCharValue[20];
	char bps[20];

	// execute command
	fp = popen(command, "r");
	if(!fp){
		printf("error [%d:%s]\n", errno, strerror(errno));
	}

	// Parsing result
	// form : rx   1.60 kbit/s   1 packets/s
	fscanf(fp, "%s", trafficCharValue); // rx, 파싱 과정에서 필요없는 부분 
	fscanf(fp, "%s", trafficCharValue); // ex : 2.59, 1.61
	fscanf(fp, "%s", bps); // ex : kbit/s, Mbit/s
	
	// Change data type Char -> Double
	trafficDoubleValue = atof(trafficCharValue);

	// Case : Over 8.0 Mbit/s
	if((bps[0] == 'M') && (trafficDoubleValue > 2.0)){ // Set 8.0
		/* warning : File is located on '/' */
		system("./PacketAnalysisService");
	}
	pclose(fp);
}
