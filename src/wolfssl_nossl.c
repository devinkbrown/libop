/*
 * wolfssl_nossl.c — no-op stubs for the wolfSSL TLS backend.
 *
 * Compiled in place of wolfssl.c when TLS is disabled (wolfSSL not found).
 * Satisfies all link-time references from commio.c, op_lib.c, ssld, ircd.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <commio-ssl.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

int  op_init_ssl(void)                                         { return 0; }
bool op_ssl_is_ktls(op_fde_t *F)                              { (void)F; return false; }
void op_fde_mark_ktls(op_fde_t *F)                            { (void)F; }
int  op_init_prng(const char *path, prng_seed_t seed_type)     { (void)path; (void)seed_type; return 0; }
int  op_get_random(void *buf, size_t len)                      { memset(buf, 0, len); return 0; }
int  op_supports_ssl(void)                                     { return 0; }

int  op_setup_ssl_server(const char *cert, const char *key,
                         const char *dh, const char *ciphers,
                         bool verify, const char *ca_cert,
                         const char *min_tls_version)
     { (void)cert; (void)key; (void)dh; (void)ciphers; (void)verify;
       (void)ca_cert; (void)min_tls_version; return -1; }

int  op_setup_ssl_server_sni(const char *hostname, const char *cert,
                              const char *key, const char *dh,
                              const char *ciphers, bool verify,
                              const char *ca_cert, const char *min_tls_version)
     { (void)hostname; (void)cert; (void)key; (void)dh; (void)ciphers; (void)verify;
       (void)ca_cert; (void)min_tls_version; return 0; }

void op_get_ssl_info(char *buf, size_t len)
{
	strncpy(buf, "TLS: disabled", len);
	if (len > 0) buf[len - 1] = '\0';
}

const char *op_get_ssl_strerror(op_fde_t *F) { (void)F; return ""; }
int  op_get_ssl_certfp(op_fde_t *F, uint8_t certfp[OP_SSL_CERTFP_LEN], int method)
     { (void)F; (void)certfp; (void)method; return -1; }
int  op_get_ssl_certfp_file(const char *filename, uint8_t certfp[OP_SSL_CERTFP_LEN], int method)
     { (void)filename; (void)certfp; (void)method; return -1; }

/* Functions declared in commio-ssl.h */

int
op_ssl_listen(op_fde_t *F, int backlog, int defer_accept)
{
	(void)F; (void)backlog; (void)defer_accept;
	return -1;
}

void
op_ssl_accept_setup(op_fde_t *F, op_fde_t *new_F, struct sockaddr *st, int addrlen, bool wsock)
{
	(void)F; (void)new_F; (void)st; (void)addrlen; (void)wsock;
}

void
op_ssl_start_accepted(op_fde_t *F, ACCB *cb, void *data, int timeout, bool wsock)
{
	(void)timeout; (void)wsock;
	if (cb)
		cb(F, OP_ERROR_SSL, NULL, 0, data);
}

void
op_ssl_start_connected(op_fde_t *F, CNCB *callback, void *data, int timeout)
{
	(void)timeout;
	if (callback)
		callback(F, OP_ERROR_SSL, data);
}

void
op_ssl_shutdown(op_fde_t *F)
{
	(void)F;
}

ssize_t
op_ssl_read(op_fde_t *F, void *buf, size_t count)
{
	(void)F; (void)buf; (void)count;
	errno = ENOTCONN;
	return OP_RW_IO_ERROR;
}

ssize_t
op_ssl_write(op_fde_t *F, const void *buf, size_t count)
{
	(void)F; (void)buf; (void)count;
	errno = ENOTCONN;
	return OP_RW_IO_ERROR;
}

/* Functions declared in op_commio.h */

void
op_connect_tcp_ssl(op_fde_t *F, struct sockaddr *dest, struct sockaddr *clocal,
                   CNCB *callback, void *data, int timeout, const char *sni_hostname)
{
	(void)dest; (void)clocal; (void)timeout; (void)sni_hostname;
	if (callback)
		callback(F, OP_ERROR_SSL, data);
}

unsigned int
op_ssl_handshake_count(op_fde_t *F)
{
	(void)F;
	return 0;
}

void
op_ssl_clear_handshake_count(op_fde_t *F)
{
	(void)F;
}

const char *
op_ssl_get_cipher(op_fde_t *F)
{
	(void)F;
	return NULL;
}

int
op_ssl_export(op_fde_t *F, uint8_t *buf, size_t buflen)
{
	(void)F; (void)buf; (void)buflen;
	return -1;
}

int
op_ssl_adopt_exported(op_fde_t *F, const uint8_t *buf, size_t len)
{
	(void)F; (void)buf; (void)len;
	return -1;
}

int
op_ssl_adopt_exported_outgoing(op_fde_t *F, const uint8_t *buf, size_t len)
{
	(void)F; (void)buf; (void)len;
	return -1;
}

bool
op_ssl_is_outgoing_connection(const op_fde_t *F)
{
	(void)F;
	return false;
}
