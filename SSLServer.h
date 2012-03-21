#ifndef SSLSERVER_H
#define SSLSERVER_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>

class SSLServer
{
public:
    SSLServer();

    void run();

protected:
    SSL_CTX* ctx;
    char *cert;
    char *key;
    BIO *abio;
    BIO *client;
    SSL *ssl;
    char *host;

    void handleClient();
};

#endif
