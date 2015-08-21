/*
 *  Sets up a TLS server and a TLS client instance and lets the instances
 *  talk to each other.
 *  The purpose of this program is to allow for fuzzing the mbed TLS
 *  library using afl.
 *
 *  Copyright (C) 2015, Fabian Foerg, Gotham Digital Science, All Rights Reserved
 *
 *  Based on code by:
 *
 *  Copyright (C) 2006-2013, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdio.h>
#define polarssl_fprintf    fprintf
#define polarssl_printf     printf
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

#if defined(POLARSSL_BIGNUM_C) && defined(POLARSSL_CERTS_C) && \
    defined(POLARSSL_ENTROPY_C) && defined(POLARSSL_SSL_TLS_C) && \
    defined(POLARSSL_SSL_SRV_C) && defined(POLARSSL_NET_C) && \
    defined(POLARSSL_RSA_C) && defined(POLARSSL_CTR_DRBG_C) && \
    defined(POLARSSL_X509_CRT_PARSE_C) && defined(POLARSSL_FS_IO)
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/ssl.h"
#include "polarssl/net.h"
#include "polarssl/error.h"
#include "polarssl/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#if defined(POLARSSL_SSL_CACHE_C)
#include "polarssl/ssl_cache.h"
#endif

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_CERTS_C) ||    \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_SSL_TLS_C) || \
    !defined(POLARSSL_SSL_SRV_C) || !defined(POLARSSL_NET_C) ||     \
    !defined(POLARSSL_RSA_C) || !defined(POLARSSL_CTR_DRBG_C) ||    \
    !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_FS_IO)
int main( void )
{
    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_CERTS_C and/or POLARSSL_ENTROPY_C "
           "and/or POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_SRV_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_CTR_DRBG_C and/or POLARSSL_X509_CRT_PARSE_C "
           "not defined.\n");
    return( 0 );
}
#else
static void my_debug( void *ctx, int level, const char *str )
{
    ((void) level);

    polarssl_fprintf( (FILE *) ctx, "%s", str );
    fflush(  (FILE *) ctx  );
}

#if defined(_MSC_VER)
#if defined(_WIN32_WCE)
#pragma comment( lib, "ws2.lib" )
#else
#pragma comment( lib, "ws2_32.lib" )
#endif
#endif /* _MSC_VER */

#ifdef _WIN32
#define read(fd,buf,len)        recv(fd,(char*)buf,(int) len,0 )
#define write(fd,buf,len)       send(fd,(char*)buf,(int) len,0 )
#define close(fd)               closesocket(fd)

static int wsa_init_done = 0;

#else /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#endif /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

/*
 * Highly recommended to set the following value to 0.
 * If the value is 0, a buffer in memory will be used for communication between
 * the client and server. Otherwise, communication occurs over network sockets.
 */
#define SOCKET_COMMUNICATION 0

#if SOCKET_COMMUNICATION
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
/*
 * Check if the requested operation would be blocking on a non-blocking socket
 * and thus 'failed' with a negative return value.
 */
static int net_would_block( int fd )
{
    ((void) fd);
    return( WSAGetLastError() == WSAEWOULDBLOCK );
}
#else
/*
 * Check if the requested operation would be blocking on a non-blocking socket
 * and thus 'failed' with a negative return value.
 *
 * Note: on a blocking socket this function always returns 0!
 */
static int net_would_block( int fd )
{
    /*
     * Never return 'WOULD BLOCK' on a non-blocking socket
     */
    if( ( fcntl( fd, F_GETFL ) & O_NONBLOCK ) != O_NONBLOCK )
        return( 0 );

    switch( errno )
    {
#if defined EAGAIN
        case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return( 1 );
    }
    return( 0 );
}
#endif /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

#define SERVER_PORT 44433
#define SERVER_NAME "localhost"
#endif

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define MAX_HANDSHAKE_STEPS (sizeof(client_steps)/sizeof(client_steps[0]))

/* Store sent messages in files for fuzzing. */
#if !defined(PACKET_FILE_PREFIX)
#define PACKET_FILE_PREFIX "./packet-"
#endif
static size_t packet_count = 1;
static size_t packet_in_num = 0;
static const char *packet_in_file = NULL;

#if !SOCKET_COMMUNICATION
#define BUF_SIZE 4096

static unsigned char server_send_buf[BUF_SIZE];
static size_t server_send_off = 0;
static size_t server_recv_off = 0;

static unsigned char client_send_buf[BUF_SIZE];
static size_t client_send_off = 0;
static size_t client_recv_off = 0;

static unsigned char *shared_buf = NULL;
static size_t *send_off = NULL;
static size_t *recv_off = NULL;

#else
static int recv_would_block = 0;
#endif

#define DEBUG_LEVEL 0

/*
 * Write at most 'len' characters to shared buffer or file.
 * Multiple sends can occur before a receive; therefore, maintain an
 * offset.
 * Also, write content of file to shared buffer, if desired (determined
 * by command-line options).
 */
static int send_custom( void *ctx, const unsigned char *buf,
        size_t len )
{
    int ret;
#if SOCKET_COMMUNICATION
    int fd = *((int *) ctx);

    if( fd < 0 )
        return( POLARSSL_ERR_NET_SOCKET_FAILED );
#else
    ((void) ctx);
#endif

    /* Read packet from file or write packet to file */
    if( packet_count == packet_in_num )
    {
        FILE *in_file;
#if !SOCKET_COMMUNICATION
        size_t rlen;
#endif

        if( !packet_in_file )
        {
            polarssl_fprintf( stderr, "Packet input file not specified!\n" );
            exit(1);
        }

        /* Read packet from file, ignoring buf */
        in_file = fopen( packet_in_file, "rb" );

        if( !in_file )
        {
            perror( "Unable to open packet input file" );
            exit( 1 );
        }

        /* Write packet to socket/buffer. */
#if SOCKET_COMMUNICATION
        ret = (int) write( fd, buf, len );
#else
        rlen = fread( shared_buf, sizeof(shared_buf[0]), BUF_SIZE,
                in_file );
#endif
        if ( ferror( in_file ) )
        {
            perror( "Unable to read packet input file" );
            exit( 1 );
        }
#if !SOCKET_COMMUNICATION
        else {
            *send_off += rlen;
            ret = rlen;
        }
#endif
        fclose( in_file );
    }
    else
    {
        /* Write packet to socket/buffer. */
#if SOCKET_COMMUNICATION
        ret = (int) write( fd, buf, len );
#else
        if ( (len <= BUF_SIZE) && memcpy( shared_buf, buf, len ) )
        {
            *send_off += len;
            ret = len;
        }
        else
        {
            ret = -1;
        }
#endif

        if( packet_in_num == 0 )
        {
            char out_filename[100];
            FILE *out_file;

            /* Write packet to file. */
            snprintf( out_filename, sizeof(out_filename), "%s%zd",
                    PACKET_FILE_PREFIX, packet_count );
            out_file = fopen( out_filename, "wb" );
            fwrite( buf, sizeof(char), len, out_file );
            fclose( out_file );
        }
    }
    packet_count++;

#if SOCKET_COMMUNICATION
    if( ret < 0 )
    {
        if( net_would_block( fd ) != 0 )
            return( POLARSSL_ERR_NET_WANT_WRITE );

#if(  defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( POLARSSL_ERR_NET_WANT_WRITE );
#endif

        return( POLARSSL_ERR_NET_SEND_FAILED );
    }
#endif

    return( ret );
}

/*
 * Read at most 'len' characters and write to buf.
 */
static int recv_custom( void *ctx, unsigned char *buf, size_t len )
{
    int ret;
#if SOCKET_COMMUNICATION
    int fd = *((int *) ctx);

    if( fd < 0 )
        return( POLARSSL_ERR_NET_SOCKET_FAILED );
    ret = (int) read( fd, buf, len );
#else
    ((void) ctx);
    ((void) len);

    if ( ((*recv_off + len) <= BUF_SIZE) && memcpy( buf, &shared_buf[*recv_off], len ) )
    {
        *recv_off += len;
        if( *recv_off == *send_off )
        {
            /*
             * Done copying buffer.
             * Reset offsets for next calls of send and rcv functions.
             */
            *recv_off = 0;
            *send_off = 0;
        }
        /* Imitate the return value of read(2). */
        ret = len;
    }
    else
    {
        ret = -1;
    }
#endif

#if SOCKET_COMMUNICATION
    if( ret < 0 )
    {
        if( net_would_block( fd ) != 0 )
            return( POLARSSL_ERR_NET_WANT_READ );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( POLARSSL_ERR_NET_WANT_READ );
#endif

        return( POLARSSL_ERR_NET_RECV_FAILED );
    }
#endif

    return( ret );
}

/*
 * Make the program deterministic for fuzzing: always generate 1 bytes
 * instead of random numbers.
 */
static int ctr_drbg_deterministic( void *p_rng, unsigned char *output, size_t output_len )
{
    ((void) p_rng);

    /* Note that key generation would fail with 0 bytes. */
    memset( output, 1, output_len );

    return 0;
}

#if !SOCKET_COMMUNICATION
static int func_server_send_buf( void *ctx, const unsigned char *buf,
        size_t len )
{
    shared_buf = server_send_buf;
    send_off = &server_send_off;

    return send_custom(ctx, buf, len);
}

static int func_client_send_buf( void *ctx, const unsigned char *buf,
        size_t len )
{
    shared_buf = client_send_buf;
    send_off = &client_send_off;

    return send_custom(ctx, buf, len);
}

static int func_server_recv_buf( void *ctx, unsigned char *buf,
        size_t len )
{
    shared_buf = client_send_buf;
    send_off = &client_send_off;
    recv_off = &server_recv_off;

    return recv_custom(ctx, buf, len);
}

static int func_client_recv_buf( void *ctx, unsigned char *buf,
        size_t len )
{
    shared_buf = server_send_buf;
    send_off = &server_send_off;
    recv_off = &client_recv_off;

    return recv_custom(ctx, buf, len);
}
#endif

static void usage( const char *prog )
{
    polarssl_fprintf( stderr, "Usage: %s [packet number] [packet file]\n", prog );
}

int main( int argc, const char *argv[] )
{
    /* Client and server declarations. */
    int ret;
    int len;
#if SOCKET_COMMUNICATION
    int listen_fd = -1;
    int client_fd = -1;
    int server_fd = -1;
#endif
    unsigned char buf[1024];
    /* Handshake step counter */
    size_t step = 1;
    int flags;

    ssl_context s_ssl, c_ssl;
    x509_crt srvcert;
    pk_context pkey;
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_context cache;
#endif

    if( argc == 3)
    {
        packet_in_num = atoi(argv[1]);
        packet_in_file = argv[2];
    }
    else if( argc != 1)
    {
        usage(argv[0]);
        exit(1);
    }

    /* Server init */
    memset( &s_ssl, 0, sizeof( ssl_context ) );
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_init( &cache );
#endif
    x509_crt_init( &srvcert );
    pk_init( &pkey );

    /* Client init */
    memset( &c_ssl, 0, sizeof( ssl_context ) );
    /*x509_crt_init( &cacert );*/

#if defined(POLARSSL_DEBUG_C)
    debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * Server:
     * Load the certificates and private RSA key
     */
    if( packet_in_num == 0 )
    {
        printf( "  . Loading the server cert. and key..." );
        fflush( stdout );
    }

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use x509_crt_parse_file() to read the
     * server and CA certificates, as well as pk_parse_keyfile().
     */
    ret = x509_crt_parse( &srvcert, (const unsigned char *) test_srv_crt,
            strlen( test_srv_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = x509_crt_parse( &srvcert, (const unsigned char *) test_ca_list,
                          strlen( test_ca_list ) );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret =  pk_parse_key( &pkey, (const unsigned char *) test_srv_key,
            strlen( test_srv_key ), NULL, 0 );
    if( ret != 0 )
    {
        printf( " failed\n  !  pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        printf( " ok\n" );
    }

    /*
     * Server:
     * Setup stuff
     */
    if( packet_in_num == 0 )
    {
        printf( "  . Server: Setting up the SSL data...." );
        fflush( stdout );
    }

    if( ( ret = ssl_init( &s_ssl ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_init returned %d\n\n", ret );
        goto exit;
    }

    ssl_set_endpoint( &s_ssl, SSL_IS_SERVER );
    ssl_set_authmode( &s_ssl, SSL_VERIFY_NONE );

    /* SSLv3 is deprecated, set minimum to TLS 1.0 */
    ssl_set_min_version( &s_ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1 );
    /* RC4 is deprecated, disable it */
    ssl_set_arc4_support( &s_ssl, SSL_ARC4_DISABLED );

    ssl_set_rng( &s_ssl, ctr_drbg_deterministic, NULL );
    ssl_set_dbg( &s_ssl, my_debug, stdout );

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_set_session_cache( &s_ssl, ssl_cache_get, &cache,
                                   ssl_cache_set, &cache );
#endif

    ssl_set_ca_chain( &s_ssl, srvcert.next, NULL, NULL );
    if( ( ret = ssl_set_own_cert( &s_ssl, &srvcert, &pkey ) ) != 0 )
    {
        printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        printf( " ok\n" );
    }

    ssl_session_reset( &s_ssl );

#if SOCKET_COMMUNICATION
    /*
     * Server:
     * Setup the listening TCP socket
     */
    if( packet_in_num == 0 )
    {
        printf( "  . Bind on https://localhost:%d/ ...", SERVER_PORT );
        fflush( stdout );
    }

    if( ( ret = net_bind( &listen_fd, NULL, SERVER_PORT ) ) != 0 )
    {
        printf( " failed\n  ! net_bind returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        printf( " ok\n" );
    }

    /*
     * Client:
     * Start the connection
     */
    if( packet_in_num == 0 )
    {
        printf( "  . Connecting to tcp/%s/%d...", SERVER_NAME, SERVER_PORT );
        fflush( stdout );
    }

    if( ( ret = net_connect( &server_fd, SERVER_NAME,
                    SERVER_PORT ) ) != 0 )
    {
        printf( " failed\n  ! net_connect returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        printf( " ok\n" );
    }

    /*
     * Server:
     * Start listening for client connections
     */
    if( packet_in_num == 0 )
    {
        printf( "  . Waiting for a remote connection ..." );
        fflush( stdout );
    }

    /*
     * Server:
     * Accept client connection (socket is set non-blocking in
     * library/net.c)
     */
    if( ( ret = net_accept( listen_fd, &client_fd,
                    NULL ) ) != 0 )
    {
        printf( " failed\n  ! net_accept returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        printf( " ok\n" );
    }

    ssl_set_bio( &s_ssl, recv_custom, &client_fd, send_custom, &client_fd );
#else
    ssl_set_bio( &s_ssl, func_server_recv_buf, NULL, func_server_send_buf, NULL );
#endif

    /*
     * Client:
     * Setup stuff
     */
    if( packet_in_num == 0 )
    {
        printf( "  . Client: Setting up the SSL/TLS structure..." );
        fflush( stdout );
    }

    if( ( ret = ssl_init( &c_ssl ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_init returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        polarssl_printf( " ok\n" );
    }

    ssl_set_endpoint( &c_ssl, SSL_IS_CLIENT );
    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    ssl_set_authmode( &c_ssl, SSL_VERIFY_OPTIONAL );
    /* NONE permits man-in-the-middle attacks. */
    /*ssl_set_authmode( &c_ssl, VERIFY_NONE );*/
    /*ssl_set_authmode( &c_ssl, SSL_VERIFY_REQUIRED );*/
    ssl_set_ca_chain( &c_ssl, &srvcert, NULL, "PolarSSL Server 1" );

    /* SSLv3 is deprecated, set minimum to TLS 1.0 */
    ssl_set_min_version( &c_ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1 );
    /* RC4 is deprecated, disable it */
    ssl_set_arc4_support( &c_ssl, SSL_ARC4_DISABLED );

    ssl_set_rng( &c_ssl, ctr_drbg_deterministic, NULL );
    ssl_set_dbg( &c_ssl, my_debug, stdout );

    if( ( ret = ssl_set_hostname( &c_ssl, "mbed TLS Server 1" ) ) != 0 )
    {
        printf( " failed\n  ! ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

#if SOCKET_COMMUNICATION
    ssl_set_bio( &c_ssl, recv_custom, &server_fd, send_custom, &server_fd );
#else
    ssl_set_bio( &c_ssl, func_client_recv_buf, NULL, func_client_send_buf,  NULL );
#endif

    if( packet_in_num == 0 )
    {
        printf( "  . Performing the SSL/TLS handshake...\n" );
        fflush( stdout );
    }

    /*
     * The following number of steps are hardcoded to ensure
     * that the client and server complete the handshake without
     * waiting infinitely for the other side to send data.
     *
     *                     1  2  3  4  5  6  7  8  9
     */
    int client_steps[] = { 2, 1, 1, 1, 4, 2, 1, 1, 3 };
    int server_steps[] = { 3, 1, 1, 3, 2, 1, 2, 1, 2 };

    do {
        /*
         * Client:
         * Handshake step
         */
        int i;
        int no_steps;

        if( c_ssl.state == SSL_HANDSHAKE_OVER ) {
            no_steps = 0;
        } else {
            no_steps = client_steps[step - 1];
        }

        for (i = 0; i < no_steps; i++) {
            if(  ( ret = ssl_handshake_step( &c_ssl ) ) != 0 )
            {
                if(  ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
                {
                    printf( " failed\n  ! ssl_handshake returned -0x%x\n\n", -ret );
                    /*goto exit;*/
                    break;
                }
            }
        }

        if( packet_in_num == 0 )
        {
            printf( "--- client handshake step %zd ok\n", step );
        }

        /*
         * Server:
         * Handshake step
         */
        if( s_ssl.state == SSL_HANDSHAKE_OVER ) {
            printf("over\n");
            no_steps = 0;
        } else {
            no_steps = server_steps[step - 1];
        }

        for (i = 0; i < no_steps; i++) {
            if(  ( ret = ssl_handshake_step( &s_ssl ) ) != 0 )
            {
                if(  ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
                {
                    printf( " failed\n  ! ssl_handshake returned %d\n\n", ret );
                    /*goto exit;*/
                    break;
                }
            }
        }

        if( packet_in_num == 0 )
        {
            printf( "--- server handshake step %zd ok\n", step );
        }

        step++;
    } while( ((c_ssl.state != SSL_HANDSHAKE_OVER)
                || (s_ssl.state != SSL_HANDSHAKE_OVER))
            && (step <= MAX_HANDSHAKE_STEPS) );

    if( packet_in_num == 0 )
    {
        printf( "c_ssl.state: %d\n", c_ssl.state != SSL_HANDSHAKE_OVER );
        printf( "s_ssl.state: %d\n", s_ssl.state != SSL_HANDSHAKE_OVER );
    }

    /*
     * Client:
     * Verify the server certificate
     */
    if( packet_in_num == 0 )
    {
        printf( "  . Verifying peer X.509 certificate..." );
    }

    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = ssl_get_verify_result( &c_ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        printf( " failed\n" );

        x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        printf( "%s\n", vrfy_buf );
    }
    else if( packet_in_num == 0 )
    {
        printf( " ok\n" );
    }

    /*
     * Client:
     * Write the GET request
     */
    if( packet_in_num == 0 )
    {
        printf( "  > Write to server:" );
        fflush( stdout );
    }

    len = sprintf( (char *) buf, GET_REQUEST );

    while( ( ret = ssl_write( &c_ssl, buf, len ) ) <= 0 )
    {
        if( ret !=POLARSSL_ERR_NET_WANT_READ && ret !=POLARSSL_ERR_NET_WANT_WRITE )
        {
            printf( " failed\n  ! ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    if( packet_in_num == 0 )
    {
        printf( " %d bytes written\n\n%s", len, (char *) buf );
    }

    /*
     * Server:
     * Read the HTTP Request
     */
    if( packet_in_num == 0 )
    {
        printf( "  < Read from client:" );
        fflush( stdout );
    }

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = ssl_read( &s_ssl, buf, len );

        if( ret ==POLARSSL_ERR_NET_WANT_READ || ret ==POLARSSL_ERR_NET_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
                    printf( " connection was closed gracefully\n" );
                    break;

                case POLARSSL_ERR_NET_CONN_RESET:
                    printf( " connection was reset by peer\n" );
                    break;

                default:
                    printf( " ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        len = ret;
        if( packet_in_num == 0 )
        {
            printf( " %d bytes read\n\n%s", len, (char *) buf );
        }

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * Server:
     * Write the 200 Response
     */
    if( packet_in_num == 0 )
    {
        printf( "  > Write to client:" );
        fflush( stdout );
    }

    len = sprintf( (char *) buf, HTTP_RESPONSE,
            ssl_get_ciphersuite( &s_ssl ) );

    while( ( ret = ssl_write( &s_ssl, buf, len ) ) <= 0 )
    {
        if( ret == POLARSSL_ERR_NET_CONN_RESET )
        {
            printf( " failed\n  ! peer closed the connection\n\n" );
            goto exit;
        }

        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            printf( " failed\n  ! ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    if( packet_in_num == 0 )
    {
        printf( " %d bytes written\n\n%s\n", len, (char *) buf );
    }

    /*
     * Client:
     * Read the HTTP response
     */
    if( packet_in_num == 0 )
    {
        printf( "  < Read from server:" );
        fflush( stdout );
    }

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = ssl_read( &c_ssl, buf, len );

        if( ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE )
            continue;

        if( ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY )
        {
            ret = 0;
            break;
        }

        if( ret < 0 )
        {
            printf( "failed\n  ! ssl_read returned %d\n\n", ret );
            break;
        }

        if( ret == 0 )
        {
            printf( "\n\nEOF\n\n" );
            break;
        }

        len = ret;
        if( packet_in_num == 0 )
        {
            printf( " %d bytes read\n\n%s", len, (char *) buf );
        }

        /*
         * Server:
         * Client read response. Close connection.
         */
        if ( packet_in_num == 0 )
        {
            printf( "  . Closing the connection..." );
            fflush( stdout );
        }

        while( ( ret = ssl_close_notify( &s_ssl ) ) < 0 )
        {
            if( ret != POLARSSL_ERR_NET_WANT_READ &&
                    ret != POLARSSL_ERR_NET_WANT_WRITE )
            {
                printf( " failed\n  ! ssl_close_notify returned %d\n\n", ret );
                goto exit;
            }
        }

        if( packet_in_num == 0 )
        {
            printf( " ok\n" );
        }
    }
    while( 1 );

    /*
     * Client:
     * Close connection.
     */
    if( packet_in_num == 0 )
    {
        printf( "  . Closing the connection..." );
        fflush( stdout );
    }

    ssl_close_notify( &c_ssl );

    if( packet_in_num == 0 )
    {
        printf( " ok\n" );
    }

    /*
     * Server:
     * We do not have multiple clients and therefore do not goto reset.
     */
    /*ret = 0;*/
    /*goto reset;*/

exit:

#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

#if SOCKET_COMMUNICATION
    if ( client_fd != 1 )
        net_close( client_fd );
    if( server_fd != -1 )
        net_close( server_fd );
    if ( listen_fd != 1 )
        net_close( listen_fd );
#endif

    x509_crt_free( &srvcert );
    pk_free( &pkey );
    ssl_free( &s_ssl );
    ssl_free( &c_ssl );
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_free( &cache );
#endif

#if defined(_WIN32)
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_CERTS_C && POLARSSL_ENTROPY_C &&
          POLARSSL_SSL_TLS_C && POLARSSL_SSL_SRV_C && POLARSSL_NET_C &&
          POLARSSL_RSA_C && POLARSSL_CTR_DRBG_C && POLARSSL_X509_CRT_PARSE_C
          && POLARSSL_FS_IO && POLARSSL_PEM_PARSE_C */
