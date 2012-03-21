#include "SSLServer.h"

int main()
{
    SSLServer *s;
    s = new SSLServer;
    s->run();
    return 0;
}
