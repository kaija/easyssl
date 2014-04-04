#include <stdio.h>
#include <stdlib.h>
#include "easy_ssl.h"
#if 0
void serv(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
 
    if ( SSL_accept(ssl) == -1 )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        easyssl_print_cert(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf);   /* construct reply */
            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}
#endif

int echo(EASYSSL *ctx)
{
    if(!ctx) return -1;
    char buf[4096];
    size_t size = 0;
    size = easyssl_recv(ctx, buf, 4096, 3);
    if(size > 0){
        easyssl_send(ctx, buf, size, 3);
    }
    easyssl_destroy(ctx);
    return 0;
}


int main()
{
    int stat = 0;
    EASYSSL *ctx = easyssl_new();
    if(ctx){
        easyssl_set_cert(ctx, "ssl.cert", "ssl.key", NULL);
        if((stat = easyssl_bind(ctx, NULL, 8443, 10)) != 0 ){
            printf("Bind error %d\n", stat);
            return 0;
        }
        while (1)
        {
            EASYSSL *cli = easyssl_accept(ctx);
            if(cli){
                echo(cli);
            }
        }
    }
    
    return 0;
}
