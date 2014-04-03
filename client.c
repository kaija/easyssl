#include <stdio.h>
#include <stdlib.h>

#include <easy_ssl.h>
int main()
{
    EASYSSL *ctx = easyssl_new();
    if(ctx){
        easyssl_connect(ctx, "s5.securepilot.com", 443);
    }
    return 0;
}
