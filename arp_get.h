#ifdef	_ARP_GET_
#define	_ARP_GET_
int arp_get_mac(const char *i_ip, char *o_mac);
int arp_get_ip(const char *i_mac, char *o_ip);
#endif
