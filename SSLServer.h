#ifndef SSLSERVER_H
#define SSLSERVER_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <errno.h>
#include <sstream>


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
    std::string createAnswer401();
    std::string createAnswer200();
    bool parseReq( std::string req );
    std::string decodeDigest( std::string digest );

};

#endif
