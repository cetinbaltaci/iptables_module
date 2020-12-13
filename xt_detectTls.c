#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_detecttls.h>

static bool detectTls_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_detectTls *matchinfo = par->matchinfo;
	struct tcphdr *tcp_header;
	char *data, *tail;
	size_t data_len;
	u_int16_t tls_header_len = 0 ;
	u_int16_t tls_version = 0 , tls_handshake_version = 0 , cipherSuite = 0 , index = 0;
	u_int8_t handshake_type = 0, sessionID_len = 0;
	u_int16_t client_cipher_list_len = 0 , client_cipher_indis = 0, tmp_cipher = 0 ;
	char str[256] = {0};
	
	tcp_header = (struct tcphdr *)skb_transport_header(skb);
	data = (char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
	tail = skb_tail_pointer(skb);
	data_len = (uintptr_t)tail - (uintptr_t)data;
	
	if (data[0] == 0x16) {
		tls_version = (data[1] << 8) +  data[2];
		tls_header_len = (data[3] << 8) + data[4];
		handshake_type = data[5];
		tls_handshake_version = (data[9] << 8) +  data[10];

		sessionID_len = data[43] ;
		index = 43 + sessionID_len +1 ;
		
		sprintf(str, "matchinfo->type: %04x matchinfo->handshake: %d matchinfo->cipherSuite: %02x", 
				matchinfo->type, matchinfo->handshake, matchinfo->cipherSuite);
		printk(KERN_INFO"xt_detectTLS RULES: %s\n", str);
		
		if (handshake_type == 0x02) // Server Hello
		{
			cipherSuite = (data[index] << 8) +  data[index + 1 ];
			sprintf(str, "Server Hello -> tls_version: %04x tls_header_len: %d handshake_type: %02x tls_handshake_version: %04x tls_header_len: %d cihperSuite: %02x", 
					tls_version, tls_header_len, handshake_type, tls_handshake_version, tls_header_len, cipherSuite);
			printk(KERN_INFO "xt_detectTLS Data: %s\n", str);		
			
		}
		else if (handshake_type == 0x01)  // Client Hello
		{	
			if (matchinfo->cipherSuite != 0  ) {
				client_cipher_list_len = (data[index ] << 8) +  data[index + 1];
				client_cipher_list_len /= 2 ;
				index += 2 ;
				for(client_cipher_indis = 0 ; client_cipher_indis < client_cipher_list_len; client_cipher_indis++) {
					tmp_cipher = (data[index + 2 * client_cipher_indis ] << 8) ;
					tmp_cipher += data[index + 2 * client_cipher_indis + 1 ];
					sprintf(str, "Client Hello -> Cipher[%d]: %04x", client_cipher_indis, tmp_cipher);
					printk(KERN_INFO"xt_detectTLS Data: %s\n", str);					
					if (matchinfo->cipherSuite == tmp_cipher) {
						cipherSuite = tmp_cipher;
						break ;
					}
				}
			}
		}

		if ( (matchinfo->type == tls_handshake_version) && (matchinfo->handshake == handshake_type) && (matchinfo->cipherSuite == 0 || cipherSuite == matchinfo->cipherSuite) ) {
			sprintf(str, "tls_version: %04x tls_header_len: %d handshake_type: %02x tls_handshake_version: %04x tls_header_len: %d cipherSuite: %02x", 
				tls_version, tls_header_len, handshake_type, tls_handshake_version, tls_header_len, cipherSuite);
			printk(KERN_INFO"xt_detectTLS Rule Matched: %s\n", str);
			return 1 ;
		}

		
	}
	
	return 0;
}

static struct xt_match detectTls_reg __read_mostly = {
		.name       = "detectTls",
		.revision   = 0,
		.family     = NFPROTO_UNSPEC,
		.match      = detectTls_mt,
		.matchsize  = sizeof(struct xt_detectTls),
		.me         = THIS_MODULE
};

static int __init detectTls_init(void)
{
	printk(KERN_INFO "xt_detectTls module initialized.\n");
	return xt_register_match(&detectTls_reg);
}

static void __exit detectTls_exit(void)
{
	printk(KERN_INFO "xt_detectTls module exit.\n");
	xt_unregister_match(&detectTls_reg);
}

module_init(detectTls_init);
module_exit(detectTls_exit);
MODULE_DESCRIPTION("Xtables: Detect TLS Protocol By Cetin BALTACI");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_detectTls");

