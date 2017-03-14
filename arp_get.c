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

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

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

#define LOOKUP_URL_LENGTH	256
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
    struct evhttp_uri *http_uri = NULL;
	const char *scheme, *host, *path, *query;
	char uri[LOOKUP_URL_LENGTH];
	int port;

	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct bufferevent *bev;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req;
	struct evkeyvalq *output_headers;
	struct evbuffer *output_buffer;

	int i;
	int ret = 0;
	enum { HTTP, HTTPS } type = HTTP;
    
    http_uri = evhttp_uri_parse(url);
	if (http_uri == NULL) {
		err("malformed url");
		goto error;
	}

	scheme = evhttp_uri_get_scheme(http_uri);
	host = evhttp_uri_get_host(http_uri);
	port = evhttp_uri_get_port(http_uri);
	if (port == -1) {
		port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;
	}
	path = evhttp_uri_get_path(http_uri);
	if (strlen(path) == 0) {
		path = "/";
	}
	query = evhttp_uri_get_query(http_uri);
	if (query == NULL) {
		snprintf(uri, sizeof(uri) - 1, "%s", path);
	} else {
		snprintf(uri, sizeof(uri) - 1, "%s?%s", path, query);
	}
	uri[sizeof(uri) - 1] = '\0';
    
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
	// Initialize OpenSSL
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif
    
    r = RAND_poll();
	if (r == 0) {
		err_openssl("RAND_poll");
		goto error;
	}

	/* Create a new OpenSSL context */
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		err_openssl("SSL_CTX_new");
		goto error;
	}
    
    base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		goto error;
	}

	// Create OpenSSL bufferevent and stack evhttp on top of it
	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		err_openssl("SSL_new()");
		goto error;
	}
    
    if (strcasecmp(scheme, "http") == 0) {
		bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	} else {
		type = HTTPS;
		bev = bufferevent_openssl_socket_new(base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	}
    
    if (bev == NULL) {
		fprintf(stderr, "bufferevent_openssl_socket_new() failed\n");
		goto error;
	}

	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

	// For simplicity, we let DNS resolution block. Everything else should be
	// asynchronous though.
	evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
		host, port);
	if (evcon == NULL) {
		fprintf(stderr, "evhttp_connection_base_bufferevent_new() failed\n");
		goto error;
	}
    
    evhttp_connection_set_timeout(evcon, 1);
    
    req = evhttp_request_new(http_request_done, bev);
	if (req == NULL) {
		fprintf(stderr, "evhttp_request_new() failed\n");
		goto error;
	}

	output_headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Host", host);
	evhttp_add_header(output_headers, "Connection", "close");
    
    r = evhttp_make_request(evcon, req, data_file ? EVHTTP_REQ_POST : EVHTTP_REQ_GET, uri);
	if (r != 0) {
		fprintf(stderr, "evhttp_make_request() failed\n");
		goto error;
	}

	event_base_dispatch(base);
	goto cleanup;

error:
	ret = 1;
cleanup:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http_uri)
		evhttp_uri_free(http_uri);
	event_base_free(base);

	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	if (type == HTTP && ssl)
		SSL_free(ssl);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
	EVP_cleanup();
	ERR_free_strings();

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	ERR_remove_state(0);
#else
	ERR_remove_thread_state(NULL);
#endif

	CRYPTO_cleanup_all_ex_data();

	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER) */
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
