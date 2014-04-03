#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <openssl/md5.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ssl23.h>
#include <openssl/ssl2.h>


#include "easy_ssl.h"

int easyssl_socket_reuseaddr(int sk)
{
	int on = 1;
    return setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(on));
}

void easyssl_socket_sendtimeout(int sk, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if(setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv))!=0){
        printf("setsockopt SO_SNDTIMEO failure %s\n", strerror(errno));
    }
}

void easyssl_socket_recvtimeout(int sk, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if(setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv))!=0){
        printf("setsockopt SO_RCVTIMEO failure %s\n", strerror(errno));
    }
}

static void easyssl_set_tcp_nodelay(int fd)
{
    int enable = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&enable, sizeof(enable));
}

static void easyssl_nonblock_socket(int sk)
{
    unsigned long fc = 1;
    ioctl(sk, FIONBIO, &fc);
}

static void easyssl_block_socket(int sk)
{
    unsigned long fc = 0;
    ioctl(sk, FIONBIO, &fc);
}

static int easyssl_ca_verify_cb(int ok, X509_STORE_CTX *store)
{
    int depth, err;
    X509 *cert = NULL;
    char data[256];
    if(!ok) {
        cert = X509_STORE_CTX_get_current_cert(store);
        depth = X509_STORE_CTX_get_error_depth(store);
        err = X509_STORE_CTX_get_error(store);
        printf("Error with certificate at depth: %i", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        printf(" issuer = %s", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        printf(" subject = %s", data);
        printf(" err %i:%s", err, X509_verify_cert_error_string(err));
        return 0;
    }
    return ok;
}

EASYSSL *easyssl_new()
{
    EASYSSL *ctx = malloc(sizeof(EASYSSL));
    if(ctx){
        memset(ctx, 0, sizeof(EASYSSL));
        ctx->ssl = NULL;
        ctx->bio = NULL;
        ctx->ctx = NULL;
    }
    return ctx;
}

int easyssl_setup(EASYSSL *ctx) {
    SSL_load_error_strings();
    if(SSL_library_init() != 1) {
        printf("Error: SSL lib init failure\n");
        return -SSL_ERR_INIT;
    }
    if((ctx->ctx = SSL_CTX_new(SSLv3_method())) == NULL) {
        printf("Create SSLv3 failure\n");
        if((ctx->ctx = SSL_CTX_new(TLSv1_method())) == NULL) {
            printf("Create TLSv1 failure\n");
            return -SSL_ERR_TLS;
        }
    }
    if(ctx->cert_auth == 0){
        SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_NONE, NULL);
    }else{
        SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_PEER, easyssl_ca_verify_cb);
        SSL_CTX_set_verify_depth(ctx->ctx, EASYSSL_DEPTH);
        if(SSL_CTX_load_verify_locations(ctx->ctx, ctx->cert_path, NULL) != 1) {
            return -SSL_ERR_NO_CERT;
        }
    }
    SSL_CTX_set_default_passwd_cb_userdata(ctx->ctx, ctx->passwd);
    if(SSL_CTX_use_certificate_chain_file(ctx->ctx, ctx->cert_path) == 1){
        printf("Load certificate success\n");
    }
    if(SSL_CTX_use_PrivateKey_file(ctx->ctx, ctx->pkey_path, SSL_FILETYPE_PEM) == 1) {
        printf("Load private key success\n");
    }
    if(SSL_CTX_check_private_key(ctx->ctx) == 1) {
        printf("Check private key success\n");
    }
    if((ctx->ssl = SSL_new(ctx->ctx)) == NULL) {
        printf("Error: create SSL failure\n");
        return -SSL_ERR_NEW;
    }
    if(SSL_set_fd(ctx->ssl, ctx->sk) != 1) {
        printf("Error: set SSL fd failure\n");
    }
    if(SSL_connect(ctx->ssl) != 1) {
        return -SSL_ERR_CONN;
    }
    printf("Connected to SSL success\n");
    return SSL_ERR_SUCCESS;
}

void easyssl_destroy(EASYSSL *ctx) {
    if (!ctx) return;
    if(ctx->ssl) {
        SSL_set_shutdown(ctx->ssl, 2);
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
    }
    if(ctx->ctx) SSL_CTX_free(ctx->ctx);
    ctx->ssl = NULL;
    ctx->ctx = NULL;
    if(ctx->sk > 0)
    {
        close(ctx->sk);
    }
    free(ctx);
}

int easyssl_connect(EASYSSL *ctx, char *url, int port)
{
    struct addrinfo hints;
    struct addrinfo *server;
    int status = 0;
    if(!url || port < 0 || port > 65535) return -SSL_ERR_PARAM;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;

    if((status = getaddrinfo(url, NULL, &hints, &server)) != 0){
        printf("getaddrinfo error %s\n", gai_strerror(status));
        return -SSL_ERR_CONN;
    }
    ctx->srv_addr.sin_addr = ((struct sockaddr_in *) (server->ai_addr))->sin_addr;
    ctx->srv_addr.sin_family = AF_INET;
    ctx->srv_addr.sin_port = htons(port);
    ctx->sk = socket(AF_INET, SOCK_STREAM, 0);
    if(ctx->sk < 0) {
        printf("socket connect error %d (%s)",errno, strerror(errno) );
        return -SSL_ERR_SOCK;
    }
    freeaddrinfo(server);
    easyssl_socket_reuseaddr(ctx->sk);
    //http_nonblock_socket(hd->sk);
    easyssl_socket_sendtimeout(ctx->sk, EASYSSL_SEND_TIMEO);
    easyssl_socket_recvtimeout(ctx->sk, EASYSSL_RECV_TIMEO);
    if(connect(ctx->sk, (struct sockaddr *)&(ctx->srv_addr), sizeof(struct sockaddr)) == -1 && errno != EINPROGRESS) {
        printf("connect error %d (%s)\n", errno, strerror(errno));
        return -SSL_ERR_CONN;
    }
    if((status = easyssl_setup(ctx)) != SSL_ERR_SUCCESS){
        return status;
    }
    return 0;
}
