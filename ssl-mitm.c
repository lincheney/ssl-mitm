#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ts.h>
#include <sys/socket.h>
#include <netinet/in.h>

// dlopen / dlsym stuff
#define DLVSYM_VERSION "GLIBC_2.2.5"
void* libssl = RTLD_NEXT;

void* real_dlsym(void *handle, const char *name) {
    static void* (*_real_dlsym)(void*, const char*) = NULL;
    if (!_real_dlsym) _real_dlsym = dlvsym(RTLD_NEXT, "dlsym", DLVSYM_VERSION);
    return _real_dlsym(handle, name);
}

#define LOOKUP(return_type, name, args, body) \
    return_type name args { \
        static return_type (*super) args = NULL; \
        if (!super) super = real_dlsym(libssl, #name); \
        body \
    }

#define OVERRIDE(return_type, name, args, body) \
    extern LOOKUP(return_type, name, args, body)

// options
#define MITM_CA_BUNDLE "MITM_CA_BUNDLE"
#define MITM_PEER_CERTS "MITM_PEER_CERTS"
#define MITM_OUTPUT_FILE "MITM_OUTPUT_FILE"

#define write_to_output_file(...) { FILE* f; if (f = get_output_file()) fprintf(f, __VA_ARGS__); }
FILE* get_output_file() {
    static FILE* file = NULL;
    if (!file) {
        file = fopen(getenv(MITM_OUTPUT_FILE), "wb");
    }
    return file;
}

// json stuff
void json_dump_string(const unsigned char *buf, const int size) {
    if (!get_output_file()) {
        return;
    }
    write_to_output_file("\"");

    int start = 0;
    int i;
    for (i = start; i < size; i++) {
        if (buf[i] != '"' && ' ' <= buf[i] && buf[i] <= '~') {
            continue;
        }

        if (i > start) {
            write_to_output_file("%.*s", i-start, buf+start);
        }
        start = i+1;

        switch (buf[i]) {
            case '"':   write_to_output_file("\\\""); break;
            case '\n':  write_to_output_file("\\n"); break;
            case '\t':  write_to_output_file("\\t"); break;
            case '\r':  write_to_output_file("\\r"); break;
            default:    write_to_output_file("\\u00%02x", buf[i]);
        }
    }

    if (i > start) {
        write_to_output_file("%.*s", i-start, buf+start);
    }
    write_to_output_file("\"");
}
void print_json_info(const SSL* ssl, const char* fn, int print_end) {
    if (!get_output_file()) {
        return;
    }
    const char* server = SSL_get_servername(ssl, SSL_get_servername_type(ssl));

    int port = -1;
    int ssl_fd = SSL_get_fd(ssl);
    // Get the peer address information
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (ssl_fd >= 0 && getsockname(ssl_fd, (struct sockaddr *)&addr, &addrlen) == 0) {
        port = ntohs(addr.sin_port);
    }

    write_to_output_file("{\"fn\": %s, \"local_port\": %i, \"remote_host\": ", fn, port);
    if (server) {
        json_dump_string(server, strlen(server));
    } else {
        write_to_output_file("null");
    }
    if (print_end) {
        write_to_output_file("}\n");
    }
}

LOOKUP(int, SSL_get_servername_type, (const SSL* ssl), { return super(ssl); })
LOOKUP(const char*, SSL_get_servername, (const SSL* ssl, const int type), { return super(ssl, type); })
LOOKUP(int, SSL_get_fd, (const SSL *ssl), { return super(ssl); });
LOOKUP(int, SSL_CTX_load_verify_file, (SSL_CTX *ctx, const char *CAfile), { return super(ctx, CAfile); })
LOOKUP(SSL_CTX*, SSL_get_SSL_CTX, (const SSL *ssl), { return super(ssl); })
LOOKUP(STACK_OF(X509)*, TS_CONF_load_certs, (const char *file), { return super(file); })
LOOKUP(void, ERR_print_errors_fp, (FILE *fp), { return super(fp); })

// symbol exports

OVERRIDE(int, SSL_write, (SSL* ssl, const void* buf, int len), {
    int rc = super(ssl, buf, len);
    print_json_info(ssl, "\"SSL_write\"", 0);
    write_to_output_file(", \"data\": ");
    json_dump_string(buf, rc);
    write_to_output_file("}\n");
    return rc;
})

OVERRIDE(int, SSL_write_ex, (SSL* ssl, const void* buf, size_t num, size_t *written), {
    int rc = super(ssl, buf, num, written);
    print_json_info(ssl, "\"SSL_write_ex\"", 0);
    write_to_output_file(", \"data\": ");
    json_dump_string(buf, *written);
    write_to_output_file("}\n");
    return rc;
})

OVERRIDE(int, SSL_read, (SSL* ssl, void* buf, int len), {
    int rc = super(ssl, buf, len);
    print_json_info(ssl, "\"SSL_read\"", 0);
    write_to_output_file(", \"data\": ");
    json_dump_string(buf, rc);
    write_to_output_file("}\n");
    return rc;
})

OVERRIDE(int, SSL_read_ex, (SSL* ssl, void* buf, size_t num, size_t *read_bytes), {
    int rc = super(ssl, buf, num, read_bytes);
    print_json_info(ssl, "\"SSL_read_ex\"", 0);
    write_to_output_file(", \"data\": ");
    json_dump_string(buf, *read_bytes);
    write_to_output_file("}\n");
    return rc;
})

void load_verify_file(SSL* ssl) {
    static const char* cafile = NULL;
    if (!cafile) {
        cafile = getenv(MITM_CA_BUNDLE);
    }

    SSL_CTX* ctx;
    if (cafile && (ctx = SSL_get_SSL_CTX(ssl)) && SSL_CTX_load_verify_file(ctx, cafile) != 1) {
        fprintf(stderr, "Error loading CA certificate file: %s\n", cafile);
        ERR_print_errors_fp(stderr);
    }
}

OVERRIDE(int, SSL_connect, (SSL* ssl), {
    load_verify_file(ssl);
    int rc = super(ssl);
    if (rc > 0) {
        print_json_info(ssl, "\"SSL_connect\"", 1);
    }
    return rc;
})

OVERRIDE(int, SSL_do_handshake, (SSL* ssl), {
    print_json_info(ssl, "\"SSL_do_handshake\"", 1);
    load_verify_file(ssl);
    return super(ssl);
})

struct peer_cert_spec {
    char* host;
    char* path;
};

struct peer_cert_spec* load_peer_cert_specs(const char* spec) {
    struct peer_cert_spec* peer_certs = NULL;
    int num = 0;
    const char* start = getenv(MITM_PEER_CERTS);
    while (start) {
        char* end = strchr(start, ':');
        if (!end) {
            break;
        }
        char* path = strchr(end+1, ':');

        num ++;
        peer_certs = realloc(peer_certs, sizeof(struct peer_cert_spec) * num);
        peer_certs[num-1] = (struct peer_cert_spec){ strndup(start, end-start), path ? strndup(end+1, path-end-1) : strdup(end+1) };
        start = path ? path+1 : NULL;
    }
    num ++;
    peer_certs = realloc(peer_certs, sizeof(struct peer_cert_spec) * num);
    peer_certs[num-1] = (struct peer_cert_spec){ NULL, NULL };
    return peer_certs;
}

OVERRIDE(STACK_OF(X509)*, SSL_get_peer_cert_chain, (const SSL* ssl), {
    static struct peer_cert_spec* peer_certs = NULL;
    if (!peer_certs) {
        peer_certs = load_peer_cert_specs(getenv(MITM_PEER_CERTS));
    }
    print_json_info(ssl, "\"SSL_get_peer_cert_chain\"", 1);

    const char* server;
    if (peer_certs && (server = SSL_get_servername(ssl, SSL_get_servername_type(ssl)))) {
        for (struct peer_cert_spec* spec = peer_certs; spec->host != NULL; spec ++) {
            if (strcmp(spec->host, server) == 0) {
                STACK_OF(X509)* stack = TS_CONF_load_certs(spec->path);
                if (stack) {
                    return stack;
                }

                fprintf(stderr, "Error loading certificate file: %s\n", spec->path);
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }

    return super(ssl);
})

extern void* dlsym(void *handle, const char *name) {
#define DLSYM_OVERRIDE(func) if (strcmp(name, #func) == 0) { libssl = handle; return (void*) func; }
    DLSYM_OVERRIDE(SSL_read);
    DLSYM_OVERRIDE(SSL_write);
    DLSYM_OVERRIDE(SSL_read_ex);
    DLSYM_OVERRIDE(SSL_write_ex);
    DLSYM_OVERRIDE(SSL_get_peer_cert_chain);
    DLSYM_OVERRIDE(SSL_connect);
    DLSYM_OVERRIDE(SSL_do_handshake);

    return real_dlsym(handle, name);
}
