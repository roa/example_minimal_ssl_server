#include "SSLServer.h"

SSLServer::SSLServer()
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();
    cert = "/home/roa/programming/examples/ssl_conn/ssl_example/servercert.pem";
    key  = "/home/roa/programming/examples/ssl_conn/ssl_example/private.key";
    host = "localhost:443";

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
            SSL_accept(ssl);
            handleClient();
        }
    }
}
void SSLServer::handleClient()
{
    int cfd = BIO_get_fd(client, NULL);
    int r;
    char rbuf[4096];
    std::string tempstr;

    r = SSL_read(ssl, rbuf, sizeof(rbuf)-1);
    rbuf[r] = '\0';
    tempstr.append(rbuf);
    do
    {
        r = SSL_read(ssl, rbuf, sizeof(rbuf)-1);
        if( r < 0 )
        {
            switch(SSL_get_error(ssl,r))
            {
                case SSL_ERROR_ZERO_RETURN:
                {
                    std::cout << "zeroreturn" << std::endl;
                    break;
                }
                case SSL_ERROR_WANT_READ:
                {
                    std::cout << "wantread" << std::endl;
                    break;
                }
                case SSL_ERROR_WANT_WRITE:
                {
                    std::cout << "want write" << std::endl;
                    break;
                }
                case SSL_ERROR_WANT_CONNECT:
                {
                    std::cout << "want connect" << std::endl;
                    break;
                }
                case SSL_ERROR_WANT_ACCEPT:
                {
                    std::cout << "want accept" << std::endl;
                    break;
                }
                case SSL_ERROR_WANT_X509_LOOKUP:
                {
                    std::cout << "want x509" << std::endl;
                    break;
                }
                case SSL_ERROR_SYSCALL:
                {
                    std::cout << "syscall" << std::endl;
                    std::cout << strerror(errno) << std::endl;
                    break;
                }
                default:
                {
                }
            }
            break;
        }
        if( r == 0)
        {
            break;
        }
        else
        {
            rbuf[r] = '\0';
            tempstr.append(rbuf);
        }
    }while(SSL_pending(ssl));

    std::string write = createAnswer();
    int numbytes = SSL_write(ssl, write.c_str(), write.size() );
    if(numbytes > 0)
    {
        std::cout << tempstr << std::endl;
        close(cfd);
    }
}

std::string SSLServer::createAnswer()
{
    std::string answer;
    answer.append( "HTTP/1.1 200 OK\r\n" );
    answer.append( "Server: TestServer/0.01\r\n" );
    answer.append( "Content-Type: text/xml\r\n" );
    answer.append( "Connection: close\r\n");
    answer.append( "\r\n" );
    answer.append( "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n" );
    answer.append( "<body>\r\n" );

    answer.append( "<p id=\"1\" problem=\"test\"/>\r\n" );
    answer.append( "</body>" );

    return answer;
}

