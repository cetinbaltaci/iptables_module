#ifndef _LINUX_NETFILTER_XT_DETECTTLS_H
#define _LINUX_NETFILTER_XT_DETECTTLS_H

struct xt_detectTls {
	int type ;
	int handshake;
	int cipherSuite;
};


#endif /* _LINUX_NETFILTER_XT_DETECTTLS_H */
