#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include "../module/xt_detecttls.h"

static const struct option detectTls_mt_opts[] = {
	{.name = "type", .has_arg = true, .val = '1'},
	{.name = "handshake", .has_arg = true, .val = '2'},
	{.name = "cipher", .has_arg = true, .val = '3'},
	{NULL}
};

static void detectTls_mt_help(void)
{
	printf("detectTls match options:\n"
			"[!] --type value  Match Type of packet\n"
			"[!] --handshake value  Match Handshake of packet\n"
			"[!] --cipher value  Match CipherSuite of packet\n"
	);
}

static void detectTls_mt_init(struct xt_entry_match *match)
{
	struct xt_detectTls *info = (void *)match->data;
	info->type = 0 ;
	info->handshake = 0 ;
}

static int detectTls_mt_parse(int c, char **argv, int invert,
    unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
	struct xt_detectTls *info = (void *)(*match)->data;
	switch (c) {
		case '1':
			info->type = strtol(optarg, NULL, 16);
			return true;
		case '2':
			info->handshake = atoi(optarg);
			return true;
		case '3':
			info->cipherSuite = atoi(optarg);
			return true ;
	}
	return false;
}


static void detectTls_mt_print(const void *entry,
    const struct xt_entry_match *match, int numeric)
{
	const struct xt_detectTls *info = (const void *)match->data;
	printf(" detectTls Type:%04x Handshake: %s Cipher: %04x" , info->type, 
		(info->handshake == 1) ? "ClientHello":  (info->handshake == 2) ? "ServerHello" : "UnKnown", 
		info->cipherSuite );
}


static struct xtables_match detectTls_mt_reg = {
	.version       = XTABLES_VERSION,
	.name          = "detectTls",
	.revision      = 0,
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_detectTls)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_detectTls)),
	.help          = detectTls_mt_help,
	.init          = detectTls_mt_init,
	.parse         = detectTls_mt_parse,
	.print         = detectTls_mt_print,
	.extra_opts    = detectTls_mt_opts,
};

void __attribute((constructor)) my_init(void)
{
	xtables_register_match(&detectTls_mt_reg);
}



