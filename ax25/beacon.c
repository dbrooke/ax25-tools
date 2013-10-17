#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netax25/ax25.h>

#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/daemon.h>

static int logging = FALSE;
static int single = FALSE;

static void terminate(int sig)
{
	if (logging) {
		syslog(LOG_INFO, "terminating on SIGTERM\n");
		closelog();
	}
	
	exit(0);
}

int main(int argc, char *argv[])
{
	struct full_sockaddr_ax25 dest;
	struct full_sockaddr_ax25 src;
	int s, n, dlen, len, interval = 30;
	char *addr, *port, *message, *portcall;
	char *srccall = NULL, *destcall = NULL;

	char test_message[]="Test";
	
	while ((n = getopt(argc, argv, "c:d:lst:v")) != -1) {
		switch (n) {
			case 'c':
				srccall = optarg;
				break;
			case 'd':
				destcall = optarg;
				break;
			case 'l':
				logging = TRUE;
				break;
			case 's':
				single = TRUE;
				break;
			case 't':
				interval = atoi(optarg);
				if (interval < 1) {
					fprintf(stderr, "wsaprs: interval must be greater than one minute\n");
					return 1;
				}
				break;
			case 'v':
				printf("wsaprs: %s\n", VERSION);
				return 0;
			case '?':
			case ':':
				fprintf(stderr, "usage: wsaprs [-c <src_call>] [-d <dest_call>] [-l] [-s] [-t interval] [-v] <port>\n");
				return 1;
		}
	}

	signal(SIGTERM, terminate);

	if (optind != argc - 1) {
		fprintf(stderr, "usage: wsaprs [-c <src_call>] [-d <dest_call>] [-l] [-s] [-t interval] [-v] <port>\n");
		return 1;
	}

	port    = argv[optind];
	message = test_message;
	
	if (ax25_config_load_ports() == 0) {
		fprintf(stderr, "wsaprs: no AX.25 ports defined\n");
		return 1;
	}

	if ((portcall = ax25_config_get_addr(port)) == NULL) {
		fprintf(stderr, "wsaprs: invalid AX.25 port setting - %s\n", port);
		return 1;
	}

	addr = NULL;
	if (destcall != NULL)
		addr = strdup(destcall);
	else
		addr = strdup("APZGZH");
	if (addr == NULL)
	  return 1;

	if ((dlen = ax25_aton(addr, &dest)) == -1) {
		fprintf(stderr, "wsaprs: unable to convert callsign '%s'\n", addr);
		return 1;
	}
	if (addr != NULL) free(addr); addr = NULL;

	if (srccall != NULL && strcmp(srccall, portcall) != 0) {
		if ((addr = (char *) malloc(strlen(srccall) + 1 + strlen(portcall) + 1)) == NULL)
			return 1;
		sprintf(addr, "%s %s", srccall, portcall);
	} else {
		if ((addr = strdup(portcall)) == NULL)
			return 1;
	}

	if ((len = ax25_aton(addr, &src)) == -1) {
		fprintf(stderr, "wsaprs: unable to convert callsign '%s'\n", addr);
		return 1;
	}
	if (addr != NULL) free(addr); addr = NULL;

	if (!single) {
		if (!daemon_start(FALSE)) {
			fprintf(stderr, "wsaprs: cannot become a daemon\n");
			return 1;
		}
	}

	if (logging) {
		openlog("wsaprs", LOG_PID, LOG_DAEMON);
		syslog(LOG_INFO, "starting");
	}

	for (;;) {
		if ((s = socket(AF_AX25, SOCK_DGRAM, 0)) == -1) {
			if (logging) {
				syslog(LOG_ERR, "socket: %m");
				closelog();
			}
			return 1;
		}

		if (bind(s, (struct sockaddr *)&src, len) == -1) {
			if (logging) {
				syslog(LOG_ERR, "bind: %m");
				closelog();
			}
			return 1;
		}
		
		if (sendto(s, message, strlen(message), 0, (struct sockaddr *)&dest, dlen) == -1) {
			if (logging) {
				syslog(LOG_ERR, "sendto: %m");
				closelog();
			}
			return 1;
		}

		close(s);

		if (!single)
			sleep(interval * 60);
		else
			break;
	}

	return 0;
}
