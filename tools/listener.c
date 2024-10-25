/*
 * listener.c - A simple UDP connection-based server
 * usage: listener <port>
 *
 *
 *  Created on: Oct 25, 2024
 *      Author: nhnghia
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>

/**
 * Number of microseconds per second
 */
#define MICRO 1000000
size_t get_latency(int i, const struct timeval *start){
	struct timeval now;
	gettimeofday( &now, NULL );
	size_t latency = (now.tv_sec * MICRO + now.tv_usec) - (start->tv_sec*MICRO + start->tv_usec);

	printf("%3d, %ld.%.10ld, %ld.%.6ld, %4ld us\n", i, start->tv_sec, start->tv_usec, now.tv_sec, now.tv_usec, latency);
	fflush(stdout);
	return latency;
}

int main(int argc, char **argv) {
	char buffer[100];
	int server_port;
	int listenfd;
	socklen_t len;
	size_t latencies = 0, i;
	struct sockaddr_in servaddr, cliaddr;
	bzero(&servaddr, sizeof(servaddr));

	/* check command line args */
	if (argc != 2) {
		fprintf(stderr, "usage: %s <port> <nb>\n", argv[0]);
		exit(1);
	}
	server_port = atoi(argv[1]);

	// Create a UDP Socket
	listenfd = socket(AF_INET, SOCK_DGRAM, 0);
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(server_port);
	servaddr.sin_family = AF_INET;

	// bind server address to socket descriptor
	bind(listenfd, (struct sockaddr*) &servaddr, sizeof(servaddr));
	printf("Listing on port %d ...\n", server_port );
	i = 0;
	while(1) {
		//receive the datagram
		len = sizeof(cliaddr);

		bzero(buffer, sizeof(buffer));

		recvfrom(listenfd, buffer, sizeof(buffer), 0,
				(struct sockaddr*) &cliaddr, &len); //receive message from server

		latencies += get_latency( ++i,  (struct timeval *) buffer );

		if( i % 100 == 0 )
			printf(" avg = %ld\n\n", (latencies / i ));
	}
}
