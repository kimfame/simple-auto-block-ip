/**
	@Month of the last update : 2015/11
*/

/*
	> Need to the PacketAnalysisService file

	> how to compile
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
	main function is making an daemon process
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
		
		// execute NetworkTrafficMeasurement function at 300 seconds interval.
		NetworkTrafficMeasurement();
		sleep(300); // Set interval 5 Min == 300 sec
	}
}

void NetworkTrafficMeasurement()
{
	FILE *fp = NULL;
	double trafficDoubleValue;
	/*
		shell execution syntax of vnStat network monitering program
		-i : interface
		-tr : traffic calculation
		| grep "rx" : only display inbound traffic not outbound
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
	fscanf(fp, "%s", trafficCharValue); // rx, not need this part in parsing processing
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
