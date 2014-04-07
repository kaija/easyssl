/**
 * @file    easyssl.h
 * @brief   easyssl library header. Use this library easy setup a SSL client / server
 * @author  Kaija kaija.chang@gmail.com
 * @date    2014/04/06
 */

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

/*! library error code enum */
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

/**
 * @name    easyssl_new
 * @brief   create a new EASYSSL structure
 * @retval          the EASYSSL structure
 */
EASYSSL *easyssl_new();

/**
 * @name    easyssl_accept
 * @brief   accept a new connection from ssl server
 * @param   ctx     the EASYSSL context structure
 * @retval          the EASYSSL client context
 */
EASYSSL *easyssl_accept(EASYSSL *ctx);

/**
 * @name    easyssl_set_cert
 * @brief   set the easyssl structure certificate and private key info
 * @param   ctx     the EASYSSL context
 * @param   cert    the certificate path
 * @param   pkey    the private key path
 * @param   passwd  the private key password/passphrase
 * @retval  =0      success
 * @retval  <0      failure with error code
 */
int easyssl_set_cert(EASYSSL *ctx, char *cert, char *pkey, char *passwd);

/**
 * @name    easyssl_connect
 * @brief   connect to the ssl server
 * @param   ctx     the EASYSSL context
 * @param   url     the ssl server url
 * @param   port    the ssl server port
 * @retval  =0      success
 * @retval  <0      failure with error code
 */
int easyssl_connect(EASYSSL *ctx, char *url, int port);

/**
 * @name    easyssl_bind
 * @brief   bind ssl server socket
 * @param   ctx     the EASYSSL context
 * @param   ip      bind on specified IP or NULL bind all
 * @param   port    the ssl server port
 * @param   max_cli the max client number
 * @retval  =0      success
 * @retval  <0      failure with error code
 */
int easyssl_bind(EASYSSL *ctx, char *ip, int port, int max_cli);

/**
 * @name    easyssl_print_cert
 * @brief   print the client certificate
 * @param   ssl     the client ssl
 * @retval  =0      success
 * @retval  <0      failure with error code
 */
void easyssl_print_cert(SSL* ssl);

/**
 * @name    easyssl_send
 * @brief   send the data by ssl function
 * @param   ctx     the EASYSSL context
 * @param   data    the data want to be send
 * @param   len     the data length
 * @param   timeout the send data timeout
 * @retval  =0      success
 * @retval  <0      failure with error code
 */
int easyssl_send(EASYSSL *ctx, const void *data, size_t len, int timeout);

/**
 * @name    easyssl_recv
 * @brief   receive the data from ssl socket
 * @param   ctx     the EASYSSL context
 * @param   data    the data buffer for receive
 * @param   len     the data length
 * @param   timeout the receive data timeout
 * @retval  =0      success
 * @retval  <0      failure with error code
 */
int easyssl_recv(EASYSSL *ctx, void *data, size_t len, int timeout);

/**
 * @name    easyssl_destroy
 * @brief   free the EASYSSL structure
 * @param   ctx     the EASYSSL context
 */
void easyssl_destroy(EASYSSL *ctx);

#endif
