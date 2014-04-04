#ifndef __EASY_SSL_H
#define __EASY_SSL_H

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ssl23.h>
#include <openssl/ssl2.h>

#define EASYSSL_PATH_LEN   128
#define EASYSSL_PASS_LEN   128
#define EASYSSL_DEPTH      1

#define EASYSSL_SEND_TIMEO  5
#define EASYSSL_RECV_TIMEO  5

enum{
    SSL_ERR_SUCCESS,
    SSL_ERR_INIT,
    SSL_ERR_TLS,
    SSL_ERR_CERT,
    SSL_ERR_PKEY,
    SSL_ERR_NEW,
    SSL_ERR_CONN,
    SSL_ERR_PARAM,
    SSL_ERR_SOCK,
    SSL_ERR_BIND,
    SSL_ERR_LISTEN,
    SSL_ERR_SEND,
    SSL_ERR_RECV
};

typedef struct easyssl_ctx{
    struct sockaddr_in  srv_addr;
    struct sockaddr_in  addr;
    int                 fd;
    int                 cert_auth;
    char                cert_path[EASYSSL_PATH_LEN];
    char                pkey_path[EASYSSL_PATH_LEN];
    char                passwd[EASYSSL_PASS_LEN];
    BIO                 *bio;
    SSL_CTX             *ctx;
    SSL                 *ssl;
    SSL_METHOD          *method;
}EASYSSL;

EASYSSL *easyssl_new();

EASYSSL *easyssl_accept(EASYSSL *ctx);
int easyssl_set_cert(EASYSSL *ctx, char *cert, char *pkey, char *passwd);
int easyssl_connect(EASYSSL *ctx, char *url, int port);
int easyssl_bind(EASYSSL *ctx, char *ip, int port, int max_cli);
void easyssl_print_cert(SSL* ssl);
int easyssl_send(EASYSSL *ctx, const void *data, size_t len, int timeout);
int easyssl_recv(EASYSSL *ctx, void *data, size_t len, int timeout);
void easyssl_free(EASYSSL *ctx);
void easyssl_destroy(EASYSSL *ctx);

#endif
