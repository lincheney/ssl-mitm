# ssl-mitm

Usually I use [mitmproxy](https://mitmproxy.org/) for my SSL mitm needs,
but sometimes there are
[stubborn programs that resist](https://docs.mitmproxy.org/stable/concepts-certificates/#certificate-pinning).

If these programs use openssl, then we can work around this with some `LD_PRELOAD` hacks.

## Usage

`make` the library and then do `LD_PRELOAD=/path/to/ssl-mitm.so curl https://google.com`

This will probably do nothing much by default, but you can change behaviour with some environment variables:
* `MITM_CA_BUNDLE`: path to a CA file to use
    * e.g. `MITM_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca.pem`
* `MITM_PEER_CERTS`: a string of `host1:file1:host2:file2:...`
    * if `SSL_get_peer_cert_chain()` is called and the host matches one in `MITM_PEER_CERTS`,
        then the cert chain is loaded from the corresponding file (instead of whatever is actually presented by the server)
    * this may be useful in some cert pinning scenarios
    * you can obtain cert chains with: `openssl s_client -showcerts -connect google.com:443 </dev/null | sed '/^-----BEGIN CERT/,/^-----END CERT/!d'`
* `MITM_OUTPUT_FILE`: output file to dump information
    * information is printed to the file in newline delimited json
    * it's probably not threadsafe, so if using threads, expect messages to be potentially mixed up
    * *decrypted* input/output buffers for `SSL_write`, `SSL_write_ex`, `SSL_read`, `SSL_read_ex` are also displayed
    * example: `MITM_OUTPUT_FILE=/dev/stderr LD_PRELOAD=./ssl-mitm.so curl https://google.com --http1.1`

## Forcing the program through a proxy

This is out of scope of this repo, but you can use one of these:
* [proxychains-ng](https://github.com/rofl0r/proxychains-ng/)
* [graftcp](https://github.com/hmgle/graftcp)
* [socko](https://github.com/lincheney/socko)
* or do some iptables stuff
