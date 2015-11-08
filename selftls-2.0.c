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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) ||    \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) || \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||     \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||    \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
            "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
            "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
            "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
            "and/or MBEDTLS_PEM_PARSE_C not defined.\n");
    return( 0 );
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

/*#if defined(MBEDTLS_NET_C)*/

#include "mbedtls/net.h"

#include <string.h>

#if( defined(_WIN32) || defined(_WIN32_WCE)) && !defined(EFIX64) && \
    !defined(EFI32)

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
/* Enables getaddrinfo() & Co */
#define _WIN32_WINNT 0x0501
#include <ws2tcpip.h>

#include <winsock2.h>
#include <windows.h>

#if defined(_MSC_VER)
#if defined(_WIN32_WCE)
#pragma comment( lib, "ws2.lib" )
#else
#pragma comment( lib, "ws2_32.lib" )
#endif
#endif /* _MSC_VER */

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

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/net.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

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
static int net_would_block( const mbedtls_net_context *ctx )
{
    ((void) ctx);
    return( WSAGetLastError() == WSAEWOULDBLOCK );
}
#else
/*
 * Check if the requested operation would be blocking on a non-blocking socket
 * and thus 'failed' with a negative return value.
 *
 * Note: on a blocking socket this function always returns 0!
 */
static int net_would_block( const mbedtls_net_context *ctx )
{
    /*
     * Never return 'WOULD BLOCK' on a non-blocking socket
     */
    if( ( fcntl( ctx->fd, F_GETFL ) & O_NONBLOCK ) != O_NONBLOCK )
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

#define SERVER_PORT "44433"
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
#define BUF_SIZE (4096)

static unsigned char server_send_buf[BUF_SIZE];
static size_t server_send_off = 0;
static size_t server_recv_off = 0;

static unsigned char client_send_buf[BUF_SIZE];
static size_t client_send_off = 0;
static size_t client_recv_off = 0;

static unsigned char *shared_buf = NULL;
static size_t *send_off = NULL;
static size_t *recv_off = NULL;
#endif

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level,
        const char *file, int line,
        const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

/*
 * Write at most 'len' characters to shared buffer or file.
 * Multiple sends can occur before a receive; therefore, maintain an
 * offset.
 * Also, write content of file to shared buffer, if desired (determined
 * by command-line options).
 */
static int mbedtls_send_custom( void *ctx, const unsigned char *buf,
        size_t len )
{
    int ret;
#if SOCKET_COMMUNICATION
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );
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
            mbedtls_fprintf( stderr, "Packet input file not specified!\n" );
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
        if( net_would_block( ctx ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_WRITE );

#if(  defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( MBEDTLS_ERR_SSL_WANT_WRITE );
#endif

        return( MBEDTLS_ERR_NET_SEND_FAILED );
    }
#endif

    return( ret );
}

/*
 * Read at most 'len' characters and write to buf.
 */
static int mbedtls_recv_custom( void *ctx, unsigned char *buf, size_t len )
{
    int ret;
#if SOCKET_COMMUNICATION
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );
    ret = (int) read( fd, buf, len );
#else
    ((void) ctx);
    ((void) len);

    if ( ((*recv_off + len) <= BUF_SIZE) && memcpy( buf, &shared_buf[*recv_off], len ) )
    {
        *recv_off += len;
        if (*recv_off == *send_off)
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
        if( net_would_block( ctx ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_READ );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( MBEDTLS_ERR_SSL_WANT_READ );
#endif

        return( MBEDTLS_ERR_NET_RECV_FAILED );
    }
#endif

    return( ret );
}

/*
 * Make the program deterministic for fuzzing: always generate 1 bytes
 * instead of random numbers.
 */
static int mbedtls_ctr_drbg_deterministic( void *p_rng, unsigned char *output, size_t output_len )
{
    ((void) p_rng);

    /* Note that key generation would fail with 0 bytes. */
    memset( output, 1, output_len );

    return 0;
}

#if !SOCKET_COMMUNICATION
static int mbedtls_server_send_buf( void *ctx, const unsigned char *buf,
        size_t len )
{
    shared_buf = server_send_buf;
    send_off = &server_send_off;

    return mbedtls_send_custom(ctx, buf, len);
}

static int mbedtls_client_send_buf( void *ctx, const unsigned char *buf,
        size_t len )
{
    shared_buf = client_send_buf;
    send_off = &client_send_off;

    return mbedtls_send_custom(ctx, buf, len);
}

static int mbedtls_server_recv_buf( void *ctx, unsigned char *buf,
        size_t len )
{
    shared_buf = client_send_buf;
    send_off = &client_send_off;
    recv_off = &server_recv_off;

    return mbedtls_recv_custom(ctx, buf, len);
}

static int mbedtls_client_recv_buf( void *ctx, unsigned char *buf,
        size_t len )
{
    shared_buf = server_send_buf;
    send_off = &server_send_off;
    recv_off = &client_recv_off;

    return mbedtls_recv_custom(ctx, buf, len);
}
#endif

static void usage( const char *prog )
{
    fprintf( stderr, "Usage: %s [packet number] [packet file]\n", prog );
}

int main( int argc, const char *argv[] )
{
    /* Client and server declarations. */
    int ret;
    int len;
#if SOCKET_COMMUNICATION
    mbedtls_net_context listen_fd, client_fd, server_fd;
#endif
    unsigned char buf[1024];
    /* Handshake step counter */
    size_t step = 1;
    int flags;

    mbedtls_ssl_context s_ssl, c_ssl;
    mbedtls_ssl_config s_conf, c_conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
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
#if SOCKET_COMMUNICATION
    mbedtls_net_init( &listen_fd );
    mbedtls_net_init( &client_fd );
#endif
    mbedtls_ssl_init( &s_ssl );
    mbedtls_ssl_config_init( &s_conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );

    /* Client init */
#if SOCKET_COMMUNICATION
    mbedtls_net_init( &server_fd );
#endif
    mbedtls_ssl_init( &c_ssl );
    mbedtls_ssl_config_init( &c_conf );
    /*mbedtls_x509_crt_init( &cacert );*/

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * Server:
     * Load the certificates and private RSA key
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Loading the server cert. and key..." );
        fflush( stdout );
    }

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt,
            mbedtls_test_srv_crt_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
            mbedtls_test_cas_pem_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key,
            mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        mbedtls_printf( " ok\n" );
    }

    /*
     * Server:
     * Setup stuff
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Server: Setting up the SSL data...." );
        fflush( stdout );
    }

    if( ( ret = mbedtls_ssl_config_defaults( &s_conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng( &s_conf, mbedtls_ctr_drbg_deterministic, NULL );
    mbedtls_ssl_conf_dbg( &s_conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &s_conf, &cache,
            mbedtls_ssl_cache_get,
            mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ca_chain( &s_conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &s_conf, &srvcert, &pkey ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_setup( &s_ssl, &s_conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        mbedtls_printf( " ok\n" );
    }

    mbedtls_ssl_session_reset( &s_ssl );

#if SOCKET_COMMUNICATION
    /*
     * Server:
     * Setup the listening TCP socket
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Bind on https://localhost:%s/ ...", SERVER_PORT );
        fflush( stdout );
    }

    if( ( ret = mbedtls_net_bind( &listen_fd, NULL, SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        mbedtls_printf( " ok\n" );
    }

    /*
     * Client:
     * Start the connection
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT );
        fflush( stdout );
    }

    if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
                    SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        mbedtls_printf( " ok\n" );
    }

    /*
     * Server:
     * Start listening for client connections
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Waiting for a remote connection ..." );
        fflush( stdout );
    }

    /*
     * Server:
     * Accept client connection (socket is set non-blocking in
     * library/net.c)
     */
    if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
                    NULL, 0, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        mbedtls_printf( " ok\n" );
    }

    mbedtls_ssl_set_bio( &s_ssl, &client_fd, mbedtls_send_custom, mbedtls_recv_custom, NULL );
#else
    mbedtls_ssl_set_bio( &s_ssl, NULL, mbedtls_server_send_buf, mbedtls_server_recv_buf, NULL );
#endif

    /*
     * Client:
     * Setup stuff
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Client: Setting up the SSL/TLS structure..." );
        fflush( stdout );
    }

    if( ( ret = mbedtls_ssl_config_defaults( &c_conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    if( packet_in_num == 0 )
    {
        mbedtls_printf( " ok\n" );
    }

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &c_conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    /* NONE permits man-in-the-middle attacks. */
    /*mbedtls_ssl_conf_authmode( &c_conf, MBEDTLS_SSL_VERIFY_NONE );*/
    /*mbedtls_ssl_conf_authmode( &c_conf, MBEDTLS_SSL_VERIFY_REQUIRED );*/
    mbedtls_ssl_conf_ca_chain( &c_conf, &srvcert, NULL );
    mbedtls_ssl_conf_rng( &c_conf, mbedtls_ctr_drbg_deterministic, NULL );
    mbedtls_ssl_conf_dbg( &c_conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &c_ssl, &c_conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &c_ssl, "mbed TLS Server 1" ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

#if SOCKET_COMMUNICATION
    mbedtls_ssl_set_bio( &c_ssl, &server_fd, mbedtls_send_custom, mbedtls_recv_custom, NULL );
#else
    mbedtls_ssl_set_bio( &c_ssl, NULL, mbedtls_client_send_buf, mbedtls_client_recv_buf, NULL );
#endif

    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Performing the SSL/TLS handshake...\n" );
        fflush( stdout );
    }

    /*
     * The following number of steps are hardcoded to ensure
     * that the client and server complete the handshake without
     * waiting infinitely for the other side to send data.
     *
     *                     1  2  3  4  5  6  7  8  9  10
     */
    int client_steps[] = { 2, 1, 1, 1, 4, 2, 1, 1, 2, 1 };
    int server_steps[] = { 3, 1, 1, 2, 3, 1, 2, 1, 1, 1 };

    do {
        /*
         * Client:
         * Handshake step
         */
        int i;
        int no_steps;

        if( c_ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
            no_steps = 0;
        } else {
            no_steps = client_steps[step - 1];
        }

        for (i = 0; i < no_steps; i++) {
            if(  ( ret = mbedtls_ssl_handshake_step( &c_ssl ) ) != 0 )
            {
                if(  ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
                {
                    mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
                    goto exit;
                }
            }
        }

        if( packet_in_num == 0 )
        {
            mbedtls_printf( "--- client handshake step %zd ok\n", step );
        }

        /*
         * Server:
         * Handshake step
         */
        if( s_ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
            no_steps = 0;
        } else {
            no_steps = server_steps[step - 1];
        }

        for (i = 0; i < no_steps; i++) {
            if(  ( ret = mbedtls_ssl_handshake_step( &s_ssl ) ) != 0 )
            {
                if(  ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
                {
                    mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
                    goto exit;
                }
            }
        }

        if( packet_in_num == 0 )
        {
            mbedtls_printf( "--- server handshake step %zd ok\n", step );
        }

        step++;
    } while( ((c_ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
                || (s_ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER))
            && (step <= MAX_HANDSHAKE_STEPS) );

    if( packet_in_num == 0 )
    {
        mbedtls_printf( "c_ssl.state: %d\n", c_ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER );
        mbedtls_printf( "s_ssl.state: %d\n", s_ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER );
    }

    /*
     * Client:
     * Verify the server certificate
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Verifying peer X.509 certificate..." );
    }

    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &c_ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        mbedtls_printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        mbedtls_printf( "%s\n", vrfy_buf );
    }
    else if( packet_in_num == 0 )
    {
        mbedtls_printf( " ok\n" );
    }

    /*
     * Client:
     * Write the GET request
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  > Write to server:" );
        fflush( stdout );
    }

    len = sprintf( (char *) buf, GET_REQUEST );

    while( ( ret = mbedtls_ssl_write( &c_ssl, buf, len ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    if( packet_in_num == 0 )
    {
        mbedtls_printf( " %d bytes written\n\n%s", len, (char *) buf );
    }

    /*
     * Server:
     * Read the HTTP Request
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  < Read from client:" );
        fflush( stdout );
    }

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &s_ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( " connection was closed gracefully\n" );
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf( " connection was reset by peer\n" );
                    break;

                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        len = ret;
        if( packet_in_num == 0 )
        {
            mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );
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
        mbedtls_printf( "  > Write to client:" );
        fflush( stdout );
    }

    len = sprintf( (char *) buf, HTTP_RESPONSE,
            mbedtls_ssl_get_ciphersuite( &s_ssl ) );

    while( ( ret = mbedtls_ssl_write( &s_ssl, buf, len ) ) <= 0 )
    {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
            mbedtls_printf( " failed\n  ! peer closed the connection\n\n" );
            goto exit;
        }

        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    if( packet_in_num == 0 )
    {
        mbedtls_printf( " %d bytes written\n\n%s\n", len, (char *) buf );
    }

    /*
     * Client:
     * Read the HTTP response
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  < Read from server:" );
        fflush( stdout );
    }

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &c_ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
        {
            ret = 0;
            break;
        }

        if( ret < 0 )
        {
            mbedtls_printf( "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
            break;
        }

        if( ret == 0 )
        {
            mbedtls_printf( "\n\nEOF\n\n" );
            break;
        }

        len = ret;
        if( packet_in_num == 0 )
        {
            mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );
        }

        /*
         * Server:
         * Client read response. Close connection.
         */
        if ( packet_in_num == 0 )
        {
            mbedtls_printf( "  . Closing the connection..." );
            fflush( stdout );
        }

        while( ( ret = mbedtls_ssl_close_notify( &s_ssl ) ) < 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                    ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret );
                goto exit;
            }
        }

        if( packet_in_num == 0 )
        {
            mbedtls_printf( " ok\n" );
        }
    }
    while( 1 );

    /*
     * Client:
     * Close connection.
     */
    if( packet_in_num == 0 )
    {
        mbedtls_printf( "  . Closing the connection..." );
        fflush( stdout );
    }

    mbedtls_ssl_close_notify( &c_ssl );

    if( packet_in_num == 0 )
    {
        mbedtls_printf( " ok\n" );
    }

    /*
     * Server:
     * We do not have multiple clients and therefore do not goto reset.
     */
    /*ret = 0;*/
    /*goto reset;*/

exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

#if SOCKET_COMMUNICATION
    mbedtls_net_free( &client_fd );
    mbedtls_net_free( &listen_fd );
    mbedtls_net_free( &server_fd );
#endif

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_free( &s_ssl );
    mbedtls_ssl_free( &c_ssl );
    mbedtls_ssl_config_free( &s_conf );
    mbedtls_ssl_config_free( &c_conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C
          && MBEDTLS_FS_IO && MBEDTLS_PEM_PARSE_C */
