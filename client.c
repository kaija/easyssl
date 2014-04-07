#include <stdio.h>
#include <stdlib.h>

#include "easyssl.h"
int main()
{
    EASYSSL *ctx = easyssl_new();
    if(ctx){
        easyssl_connect(ctx, "localhost", 8443);
    }
    return 0;
}
