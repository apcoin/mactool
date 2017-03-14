#ifdef	_ARP_GET_
#define	_ARP_GET_

/*  arp_flags and at_flags field values */
#define ATF_INUSE   0x01    /* entry in use */
#define ATF_COM     0x02    /* completed entry (enaddr valid) */
#define ATF_PERM    0x04    /* permanent entry */
#define ATF_PUBL    0x08    /* publish entry (respond for other host) */
#define ATF_USETRAILERS 0x10    /* has requested trailers */
#define ATF_PROXY   0x20    /* Do PROXY arp */

#define MAC_LENGTH  18
#define IP_LENGTH   16

char *mac_2_vendor(const char *mac);
int arp_get_mac(const char *dev_name, const char *i_ip, char *o_mac);
int arp_get_ip(const char *dev_name, const char *i_mac, char *o_ip);

#endif
