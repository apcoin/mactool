#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
/* libevent */
#include <event-config.h>
#include <event.h>
/* openssl */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "arp_get.h"
#include "http_client.h"

static int get_mac_vendor_url(const char *mac, char *o_url, int length) {
	if (!mac || !o_url)
		return 0;
	
	int nret = snprintf(o_url, length, "%s/%s", MAC_VENDOR_LOOKUP_URL, mac);
	return nret<0?0:1;
}

static void mac_2_vendor(struct http_client *api, struct http_request *req, struct http_response *response, void *baton) {
	struct s_vendor *vendor = (struct s_vendor *)baton;
	printf("%.*s", response->body_len, response->body);
}

#define LOOKUP_URL_LENGTH	128
#define VENDOR_LENGTH		128

int get_mac_vendor(const char *mac) {
	char lookup_url[LOOKUP_URL_LENGTH] = {0};
	if (!get_mac_vendor_url(mac, lookup_url, LOOKUP_URL_LENGHT))
		return 0;
	
	struct s_vendor *vendor = malloc(sizeof(struct s_vendor));
	memset(vendor, 0, sizeof(struct s_vendor));
	make_http_get_request(lookup_url, mac_2_vendor, vendor);
}

void make_http_get_request(const char *url,  cb_http_response callback, void *baton) {
	
	
	struct evhttp_uri *http_uri = evhttp_uri_parse(url);
	const char *host = evhttp_uri_get_host(http_uri);
	const int  port = evhttp_uri_get_port(http_uri);
	
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	event_init();
	
	struct http_client   *client = http_client_new(host, port, NULL);
  	struct http_request  *req = http_client_request(client, HTTP_METHOD_GET, strlen(url), url);

  	http_client_request_dispatch(req, callback, baton);
	
	event_loop(0);
	
	return 0;
}

int arp_get_mac(const char *dev_name, const char *i_ip, char *o_mac) {
	int s;
    struct arpreq arpreq;
    struct sockaddr_in *sin;
	
	if (!dev_name || !i_ip || !o_mac)
		return 0;
	
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s <= 0) {
		return 0;
	}
	
	memset(&arpreq, 0, sizeof(arpreq));

    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr(i_ip);

	strcpy(arpreq.arp_dev, dev_name);
	if (ioctl(s, SIOCGARP, &arpreq) < 0) {
		return 0;
	}
	
	if (arpreq.arp_flags & ATF_COM) {
        unsigned char *eap = (unsigned char *) &arpreq.arp_ha.sa_data[0];
        snprintf(o_mac, MAC_LENGTH, "%02X:%02X:%02X:%02X:%02X:%02X",
                eap[0], eap[1], eap[2], eap[3], eap[4], eap[5]);
        return 1;
    } 
	
	return 0;
}

int arp_get_ip(const char *dev_name, const char *i_mac, char *o_ip) {
    return 0;
}
