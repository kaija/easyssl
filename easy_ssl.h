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
    SSL_ERR_NO_CERT,
    SSL_ERR_NEW,
    SSL_ERR_CONN,
    SSL_ERR_PARAM,
    SSL_ERR_SOCK
};

typedef struct easyssl_ctx{
    struct sockaddr_in  srv_addr;
    int                 sk;
    int                 cert_auth;
    char                cert_path[EASYSSL_PATH_LEN];
    char                pkey_path[EASYSSL_PATH_LEN];
    char                passwd[EASYSSL_PASS_LEN];
    BIO                 *bio;
    SSL_CTX             *ctx;
    SSL                 *ssl;
}EASYSSL;


EASYSSL *easyssl_new();

#endif
