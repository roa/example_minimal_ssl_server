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
    if( abio == NULL )
    {
        abort();
    }
}

void SSLServer::run()
{
    if( BIO_do_accept( abio ) <= 0 )
    {
        abort();
    }

    dropRights();

    fd_set fds;

    int afd = BIO_get_fd( abio,NULL );

    while( true )
    {
        FD_ZERO( &fds );
        FD_SET( afd, &fds );

        select( afd+1, &fds, NULL, NULL, NULL );

        if( FD_ISSET( afd, &fds ) && BIO_do_accept( abio ) > 0 )
        {
            int r;
            char rbuf[4096];
            client = BIO_pop( abio );
            ssl = SSL_new( ctx );
            SSL_set_accept_state( ssl );
            SSL_set_bio( ssl, client, client );
            SSL_accept( ssl );
            handleClient();
        }
    }
}

void SSLServer::handleClient()
{
    int cfd = BIO_get_fd( client, NULL );
    int r;
    char rbuf[4096];
    std::string tempstr;
    bool answer = false;

    r = SSL_read( ssl, rbuf, sizeof( rbuf ) - 1 );
    rbuf[r] = '\0';
    tempstr.append( rbuf );

    do
    {
        r = SSL_read( ssl, rbuf, sizeof( rbuf ) - 1 );
        if( r < 0 )
        {
            switch( SSL_get_error( ssl, r ) )
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
        if( r == 0 )
        {
            break;
        }
        else
        {
            rbuf[r] = '\0';
            tempstr.append( rbuf );
        }
    } while( SSL_pending( ssl ) );

    if( !tempstr.empty() )
    {
        answer = parseReq( tempstr );

    }
    std::string write;
    if ( answer )
        write = createAnswer200();
    else
        write = createAnswer401();
    int numbytes = SSL_write( ssl, write.c_str(), write.size() );
    if( numbytes > 0 )
    {
        close( cfd );
    }
}

std::string SSLServer::createAnswer401()
{

    std::string answer;
    answer.append( "HTTP/1.1 401 Unauthorized\r\n" );
    answer.append( "WWW-Authenticate: Basic realm=\"Secure Area\"" );
    answer.append( "Connection: close\r\n" );
    answer.append( "\r\n" );
    return answer;
}

std::string SSLServer::createAnswer200()
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

bool SSLServer::parseReq( std::string req )
{
    std::stringstream reqStream;
    std::string line;
    reqStream << req;
    while( getline( reqStream, line ) )
    {
        size_t found = line.find( "Authorization" );
        if( found == 0 )
        {
            std::string digest = line.substr( line.find_last_of( " " ) + 1, line.npos - 1 );
            std::string ok = "test123:test123";

            if( decodeDigest( digest ).compare( 0, ok.length(), ok ) == 0 )
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}

std::string SSLServer::decodeDigest( std::string digest )
{
    int length = digest.size() + 1;
    char *cdigest = ( char* ) malloc( length );
    cdigest = ( char* ) digest.c_str();
    char * buffer = ( char * ) malloc( length );
    BIO *b64, *bmem;
    b64 = BIO_new( BIO_f_base64() );
    BIO_set_flags( b64, BIO_FLAGS_BASE64_NO_NL );
    bmem = BIO_new_mem_buf( cdigest, length );
    bmem = BIO_push( b64, bmem );
    int r = BIO_read( bmem, buffer, length );
    BIO_free_all( bmem );
    std::string decoded = buffer;

    return decoded;
}

void SSLServer::dropRights()
{
    if (getuid() == 0) {
    if (setgid( 1000 ) != 0)
        printf("setgid: Unable to drop group privileges: %s", strerror(errno));
    if (setuid( 1000 ) != 0)
        printf("setuid: Unable to drop user privileges: %S", strerror(errno));
    }
}
