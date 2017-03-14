#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "arp_get.h"

static void usage() {
	printf("\n");
}

int main(int argc, char **argv) {
	if (argc != 4) {
		usage();
		exit(0);
	}
	
	char *type 	= argv[1];
	char *value = argv[2];
	char *dev 	= argv[3];
    
	printf("type %s value %s dev %s\n", type, value, dev);
    
	if (strcmp(type, "mac") == 0) {
		char mac[MAC_LENGTH] = {0};
		if (arp_get_mac(dev, value, mac)) {
			printf("mac is %s\n", mac);
		} else 
			printf("error %s\n", strerror(errno));
	} else if (strcmp(type, "ip") == 0) {
        char ip[IP_LENGTH] = {0};
        if (arp_get_ip(dev, value, ip)) {
            printf("ip is %s\n", ip);
        }
	} else if (strcmp(type, "vendor") == 0) {
        get_mac_vendor(value);
    } else 
		usage();
	
  	return 0;
}
