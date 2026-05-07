/*
 * ssl_stubs.c — no-op stubs for SSL functions when opssl is unavailable.
 *
 * Compiled only when the build has no TLS library.  Every op_ssl_*
 * function returns an error or no-op so the rest of libop links cleanly.
 */

#include <op_lib.h>
#include <commio-int.h>
#include <commio-ssl.h>
#include <stddef.h>
#include <errno.h>

int op_setup_ssl_server(const char *cert, const char *keyfile,
                        const char *dhfile, const char *cipher_list,
                        bool verify, const char *ca_cert,
                        const char *min_tls_version)
{
    (void)cert; (void)keyfile; (void)dhfile; (void)cipher_list;
    (void)verify; (void)ca_cert; (void)min_tls_version;
    return -1;
}

int op_init_ssl(void) { return -1; }
int op_ssl_listen(op_fde_t *F, int bl, int da) { (void)F; (void)bl; (void)da; return -1; }
int op_init_prng(const char *p, prng_seed_t s) { (void)p; (void)s; return -1; }

int op_get_random(void *buf, size_t length)
{
    (void)buf; (void)length;
    return -1;
}

const char *op_get_ssl_strerror(op_fde_t *F) { (void)F; return "TLS not available"; }

void op_ssl_start_accepted(op_fde_t *F, ACCB *cb, void *data, int timeout, bool wsock)
{ (void)F; (void)cb; (void)data; (void)timeout; (void)wsock; }

void op_ssl_start_connected(op_fde_t *F, CNCB *cb, void *data, int timeout)
{ (void)F; (void)cb; (void)data; (void)timeout; }

void op_connect_tcp_ssl(op_fde_t *F, struct sockaddr *dest, struct sockaddr *clocal,
                        CNCB *cb, void *data, int timeout, const char *sni)
{ (void)F; (void)dest; (void)clocal; (void)cb; (void)data; (void)timeout; (void)sni; }

void op_ssl_accept_setup(op_fde_t *F, op_fde_t *new_F, struct sockaddr *st, int addrlen, bool wsock)
{ (void)F; (void)new_F; (void)st; (void)addrlen; (void)wsock; }

void op_ssl_shutdown(op_fde_t *F) { (void)F; }

ssize_t op_ssl_read(op_fde_t *F, void *buf, size_t count)
{ (void)F; (void)buf; (void)count; errno = ENOTSUP; return -1; }

ssize_t op_ssl_write(op_fde_t *F, const void *buf, size_t count)
{ (void)F; (void)buf; (void)count; errno = ENOTSUP; return -1; }

int op_ssl_pending(op_fde_t *F) { (void)F; return 0; }

void op_get_ssl_info(char *buf, size_t length)
{ if (length > 0) buf[0] = '\0'; }

bool op_ssl_is_ktls(op_fde_t *F) { (void)F; return false; }
void op_fde_mark_ktls(op_fde_t *F) { (void)F; }
int op_ssl_promote_ktls(op_fde_t *F) { (void)F; return 0; }

int op_ssl_export(op_fde_t *F, uint8_t *buf, size_t buflen)
{ (void)F; (void)buf; (void)buflen; return -1; }

int op_ssl_adopt_exported(op_fde_t *F, const uint8_t *buf, size_t len)
{ (void)F; (void)buf; (void)len; return -1; }

bool op_ssl_is_outgoing_connection(const op_fde_t *F) { (void)F; return false; }

int op_ssl_adopt_exported_outgoing(op_fde_t *F, const uint8_t *buf, size_t len)
{ (void)F; (void)buf; (void)len; return -1; }

int op_ssl_export_keying_material(op_fde_t *F, uint8_t *out, size_t outlen,
                                  const char *label,
                                  const uint8_t *context, size_t context_len)
{ (void)F; (void)out; (void)outlen; (void)label; (void)context; (void)context_len; return 0; }
