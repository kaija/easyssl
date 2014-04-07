#include <stdio.h>
#include <stdlib.h>
#include "easyssl.h"

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
