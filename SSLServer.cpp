#include "SSLServer.h"

SSLServer::SSLServer()
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();
    cert = "/home/roa/programming/examples/ssl_conn/ssl_example/servercert.pem";
    key  = "/home/roa/programming/examples/ssl_conn/ssl_example/private.key";
    host = "localhost:9037";

    ctx = SSL_CTX_new(SSLv3_server_method());
    SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    abio = BIO_new_accept(host);
    if(abio == NULL)
    {
        abort();
    }
}

void SSLServer::run()
{
    if(BIO_do_accept(abio) <= 0)
    {
        abort();
    }

    fd_set fds;

    int afd = BIO_get_fd(abio,NULL);

    while(true)
    {
        FD_ZERO(&fds);
        FD_SET(afd,&fds);

        select(afd+1,&fds,NULL,NULL,NULL);
        if(FD_ISSET(afd,&fds) && BIO_do_accept(abio) > 0)
        {
            int r;
            char rbuf[4096];
            client = BIO_pop(abio);
            ssl = SSL_new(ctx);
            SSL_set_accept_state(ssl);
            SSL_set_bio(ssl, client, client);

            handleClient();
        }
    }
}
void SSLServer::handleClient()
{
    fd_set rfds, wfds;
    int cfd = BIO_get_fd(client, NULL);
    int r;
    char rbuf[4096];
    std::string tempstr;

    for(;;)
    {
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(cfd, &rfds);

        r = select(cfd+1, &rfds, &wfds, NULL, NULL);

        if(FD_ISSET(cfd, &rfds))
        {
            r = SSL_read(ssl, rbuf, sizeof(rbuf)-1);
            if( r <= 0 )
            {
                break;
            }
            rbuf[r] = '\0';
            tempstr.append(rbuf);
        }
    }
    std::cout << "huch" << std::endl;
    std::cout << tempstr << std::endl;
}

