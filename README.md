This is a Kernle IPTABLES module for TLS / SSL connections.

## **Install :**

> Module:

    cd module
    make
    sudo insmod ./xt_detectTls.ko
    sudo grep detectTls /proc/net/ip_tables_matches 

> Extension:

    cd extensions
    make
    sudo cp libxt_detectTls.so /usr/lib/x86_64-linux-gnu/xtables/
    iptables -m detectTls --help

## **Usage :**

> Drop Rule: Client Hello, TLS v1.1 and Cipher Suite 0xCCA8
> (ECDHE-RSA-CHACHA20-POLY1305).

    sudo iptables -I OUTPUT 1 -m state --state NEW,ESTABLISHED,RELATED -m detectTls --type 302 --handshake 1 --cipher $((16#CCA8)) -j DROP

> Drop Rule: Client Hello, TLS v1.0

    sudo iptables -I OUTPUT 1 -m state --state NEW,ESTABLISHED,RELATED -m detectTls --type 301 --handshake 1 --cipher 0 -j DROP

> Check iptables:

    sudo iptables -L OUTPUT
    Output:
    DROP       all  --  anywhere             anywhere             state NEW,RELATED,ESTABLISHED detectTls Type:0302 Handshake: ClientHello Cipher: cca8


> Cipher Suites List:

    openssl ciphers -V

