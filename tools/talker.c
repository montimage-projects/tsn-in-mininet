/*
 * talker.c - A simple UDP connection-based client
 * usage: talker <host> <port> <sleep ms> <nic>
 *
 *
 *  Created on: Oct 25, 2024
 *      Author: nhnghia
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>

#define PORT 5000
#define MAXLINE 1000

/*
 * error - wrapper for perror
 */
void error(char *msg) {
	perror(msg);
	exit(0);
}

int main(int argc, char **argv) {
	char buffer[100];
	int sockfd;
	struct sockaddr_in servaddr;

	char *iface_name = NULL;
	char *server_ip;
	int server_port;
	int sleep_ms = 10;

	/* check command line arguments */
	if (argc < 3 || argc > 5) {
		fprintf(stderr, "usage: %s <server-ip> <server-port> <sleep ms = 10> <bind-nic>\n", argv[0]);
		exit(0);
	}
	server_ip = argv[1];
	server_port  = atoi(argv[2]);

	if( argc == 4 )
		sleep_ms = atoi(argv[3]);

	if( argc == 5 )
		iface_name = argv[4];


	// clear servaddr
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_addr.s_addr = inet_addr( server_ip );
	servaddr.sin_port = htons( server_port );
	servaddr.sin_family = AF_INET;

	// create datagram socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if( iface_name != NULL ){
		if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, strlen(iface_name)) )
			error("Cannot bind to nic");
	}

	// connect to server
	if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
		error("Connect Failed \n");

	// request to send datagram
	while( 1 ){
		bzero(buffer, sizeof(buffer));
		gettimeofday((struct timeval *) buffer, NULL);

		sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)NULL, sizeof(servaddr));
		usleep(sleep_ms * 1000);
	}

	// close the descriptor
	close(sockfd);
}
