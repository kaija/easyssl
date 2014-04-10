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
#include <openssl/err.h>

#include "easyssl.h"

char *easyssl_get_version()
{
    return EASYSSL_VERSION;
}

int easyssl_send(EASYSSL *ctx, const void *data, size_t len, int timeout)
{
    if(!ctx) return -SSL_ERR_PARAM;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    size_t sent = 0;
    int ret = -1;
    int retry = 3;
    if(ctx->fd < 1) return -SSL_ERR_PARAM;
    fd_set fs;
    do{
        FD_ZERO(&fs);
        FD_SET(ctx->fd, &fs);
        ret = select(ctx->fd + 1, NULL, &fs, NULL, &tv);
        char *ptr = (char *)data + sent;
        ret = SSL_write(ctx->ssl, (void *) ptr, len -sent);
        if(ret > 0){
        }else{
            if(errno != -EAGAIN){
                printf("Send data failure %d(%s)\n", errno , strerror(errno));
                ret = -SSL_ERR_SEND;
                break;
            }else{
                retry --;
                if(retry == 0) {
                    ret = -SSL_ERR_SEND;
                    break;
                }
            }
        }
    }while(sent < len);
    if(ret >= 0) return sent;
    return ret;
}

int easyssl_recv(EASYSSL *ctx, void *data, size_t len, int timeout)
{
    if(!ctx) return -SSL_ERR_PARAM;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    int ret = -1;
    if(ctx->fd < 1) return -SSL_ERR_PARAM;

    if(SSL_pending(ctx->ssl) > 0){
        ret = SSL_read(ctx->ssl, data, len);
    }else{
        fd_set fs;
        FD_ZERO(&fs);
        FD_SET(ctx->fd, &fs);
        ret = select(ctx->fd + 1, &fs, NULL, NULL, &tv);
        if(ret >= 0){
            ret = SSL_read(ctx->ssl, data, len);
        }
    }
    return ret;
}

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
#if 0
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
#endif

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
        ctx->method = NULL;
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
            return -SSL_ERR_CERT;
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
    if(SSL_set_fd(ctx->ssl, ctx->fd) != 1) {
        printf("Error: set SSL fd failure\n");
    }
    if(SSL_connect(ctx->ssl) != 1) {
        return -SSL_ERR_CONN;
    }
    printf("Connected to SSL success\n");
    return SSL_ERR_SUCCESS;
}

//void easyssl

void easyssl_destroy(EASYSSL *ctx)
{
    if (!ctx) return;
    if(ctx->ssl) {
        SSL_set_shutdown(ctx->ssl, 2);
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
    }
    if(ctx->ctx) SSL_CTX_free(ctx->ctx);
    ctx->ssl = NULL;
    ctx->ctx = NULL;
    if(ctx->fd > 0)
    {
        close(ctx->fd);
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
    ctx->fd = socket(AF_INET, SOCK_STREAM, 0);
    if(ctx->fd < 0) {
        printf("socket connect error %d (%s)",errno, strerror(errno) );
        return -SSL_ERR_SOCK;
    }
    freeaddrinfo(server);
    easyssl_socket_reuseaddr(ctx->fd);
    //easyssl_nonblock_socket(hd->fd);
    easyssl_socket_sendtimeout(ctx->fd, EASYSSL_SEND_TIMEO);
    easyssl_socket_recvtimeout(ctx->fd, EASYSSL_RECV_TIMEO);
    if(connect(ctx->fd, (struct sockaddr *)&(ctx->srv_addr), sizeof(struct sockaddr)) == -1 && errno != EINPROGRESS) {
        printf("connect error %d (%s)\n", errno, strerror(errno));
        return -SSL_ERR_CONN;
    }
    if((status = easyssl_setup(ctx)) != SSL_ERR_SUCCESS){
        return status;
    }
    return 0;
}

int easyssl_set_cert(EASYSSL *ctx, char *cert, char *pkey, char *passwd)
{
    if(cert) strncpy(ctx->cert_path, cert, EASYSSL_PATH_LEN);
    if(pkey) strncpy(ctx->pkey_path, pkey, EASYSSL_PATH_LEN);
    if(passwd) strncpy(ctx->passwd, passwd, EASYSSL_PASS_LEN);
    return 0;
}

int easyssl_bind(EASYSSL *ctx, char *ip, int port, int max_cli)
{
    if(port < 0 || port > 65535) return -SSL_ERR_PARAM;
    struct sockaddr_in addr;

    ctx->fd = socket(AF_INET, SOCK_STREAM, 0);
    if(ctx->fd < 0)
    {
        printf("create socket error %d(%s)\n", errno, strerror(errno));
        return -SSL_ERR_SOCK;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    //FIXME bind on specified IP address
    if ( bind(ctx->fd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        printf("bind socket error %d(%s)\n", errno, strerror(errno));
        return -SSL_ERR_BIND;
    }
    if ( listen(ctx->fd, max_cli) != 0 )
    {
        printf("listen socket error %d(%s)\n", errno, strerror(errno));
        return -SSL_ERR_LISTEN;
    }
    if(SSL_library_init() != 1) {
        printf("Error: SSL lib init failure\n");
        return -SSL_ERR_INIT;
    }

    const SSL_METHOD          *method;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv3_server_method();
    ctx->ctx = SSL_CTX_new(method);
    if ( ctx->ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        return -SSL_ERR_NEW;
    }

    if ( SSL_CTX_use_certificate_file(ctx->ctx, ctx->cert_path, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return -SSL_ERR_CERT;
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx->ctx, ctx->pkey_path, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return -SSL_ERR_PKEY;
    }
    if ( !SSL_CTX_check_private_key(ctx->ctx) )
    {
        printf("Private key does not match the public certificate\n");
        return -SSL_ERR_PKEY;
    }
    return SSL_ERR_SUCCESS;
}

EASYSSL *easyssl_accept(EASYSSL *ctx)
{
    EASYSSL *cli = easyssl_new();
    if(!cli) return NULL;

    socklen_t len = sizeof(cli->addr);

    int fd = accept(ctx->fd, (struct sockaddr*)&cli->addr, &len);
    if(fd >= 0){
        cli->fd = fd;
        cli->ssl = SSL_new(ctx->ctx);
        easyssl_print_cert(cli->ssl);
        //printf("Connect with cipher %s\n",SSL_get_cipher(cli->ssl));
        SSL_set_fd(cli->ssl, fd);
    }
    if ( SSL_accept(cli->ssl) == -1 ){
        printf("ssl accept error %d(%s)\n", errno, strerror(errno));
        easyssl_destroy(cli);
        cli = NULL;
    }
    return cli;
}

void easyssl_print_cert(SSL* ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }else{
        printf("No certificates.\n");
    }
}
