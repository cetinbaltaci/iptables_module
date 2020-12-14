iptables module for TLS conneciton.

Usage :
Drop Rule: Client Hello, TLS v1.1 and Cipher Suite 0xCCA8 (ECDHE-RSA-CHACHA20-POLY1305). 

iptables -I OUTPUT 1 -m state --state NEW,ESTABLISHED,RELATED -m detectTls --type 302 --handshake 1 --cipher $((16#CCA8)) -j DROP

Drop Rule: Client Hello, TLS v1.0

iptables -I OUTPUT 1 -m state --state NEW,ESTABLISHED,RELATED -m detectTls --type 301 --handshake 1 --cipher 0 -j DROP

Cipher Suites List:
openssl ciphers -V
