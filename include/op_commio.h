/*
 *  libop: ophion support library.
 *  op_commio.h: Network I/O subsystem.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2025-2026 ophion development team
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_commio.h directly; include op_lib.h"
#endif

#ifndef LIBOP_COMMIO_H
#define LIBOP_COMMIO_H


struct sockaddr;
struct _fde;
typedef struct _fde op_fde_t;

/* Callback for completed IO events */
typedef void PF(op_fde_t *, void *);

/* Callback for completed connections */
/* int fd, int status, void * */
typedef void CNCB(op_fde_t *, int, void *);
/* callback for fd table dumps */
typedef void DUMPCB(int, const char *desc, void *);
/* callback for accept callbacks */
typedef void ACCB(op_fde_t *, int status, struct sockaddr *addr, op_socklen_t len, void *);
/* callback for pre-accept callback */
typedef int ACPRE(op_fde_t *, struct sockaddr *addr, op_socklen_t len, void *);

enum
{
	OP_OK,
	OP_ERR_BIND,
	OP_ERR_DNS,
	OP_ERR_TIMEOUT,
	OP_ERR_CONNECT,
	OP_ERROR,
	OP_ERROR_SSL,
	OP_ERR_MAX
};

#define OP_FD_NONE		0x01
#define OP_FD_FILE		0x02
#define OP_FD_SOCKET		0x04
#ifndef _WIN32
#define OP_FD_PIPE		0x08
#else
#define OP_FD_PIPE		OP_FD_SOCKET
#endif
#define	OP_FD_LISTEN		0x10
#define OP_FD_SSL		0x20
#define OP_FD_UNKNOWN		0x40
#define OP_FD_SCTP		0x80
#define OP_FD_WEBSOCKET		0x100

#define OP_FD_INHERIT_TYPES	(OP_FD_SCTP)

#define OP_RW_IO_ERROR		-1	/* System call error */
#define OP_RW_SSL_ERROR		-2	/* SSL Error */
#define OP_RW_SSL_NEED_READ	-3	/* SSL Needs read */
#define OP_RW_SSL_NEED_WRITE	-4	/* SSL Needs write */


struct op_iovec
{
	void *iov_base;
	size_t iov_len;
};


void op_fdlist_init(int closeall, int maxfds, size_t heapsize);

op_fde_t *op_open(op_platform_fd_t, uint16_t, const char *);
void op_close(op_fde_t *);
void op_dump_fd(DUMPCB *, void *xdata);
void op_note(op_fde_t *, const char *);
void op_close_pending_fds(void);

/* Type of IO */
#define	OP_SELECT_READ		0x1
#define	OP_SELECT_WRITE		0x2

#define OP_SELECT_ACCEPT	OP_SELECT_READ
#define OP_SELECT_CONNECT	OP_SELECT_WRITE

#define OP_SSL_CERTFP_LEN	64
/* Byte length of the fixed header preceding the fingerprint payload in the
 * certfp IPC message: 1 opcode + 8 fd + 4 certfp_method + 4 len = 17 */
#define OP_SSL_CERTFP_HDR_LEN	17

/* Methods for certfp */
/* Digest of full X.509 certificate */
#define OP_SSL_CERTFP_METH_CERT_SHA1	0x0000
#define OP_SSL_CERTFP_METH_CERT_SHA256	0x0001
#define OP_SSL_CERTFP_METH_CERT_SHA512	0x0002
/* Digest of SubjectPublicKeyInfo (RFC 5280), used by DANE (RFC 6698) */
#define OP_SSL_CERTFP_METH_SPKI_SHA256	0x1001
#define OP_SSL_CERTFP_METH_SPKI_SHA512	0x1002
/* SHA-3 variants */
#define OP_SSL_CERTFP_METH_CERT_SHA3_256	0x0003
#define OP_SSL_CERTFP_METH_CERT_SHA3_512	0x0004
#define OP_SSL_CERTFP_METH_SPKI_SHA3_256	0x1003
#define OP_SSL_CERTFP_METH_SPKI_SHA3_512	0x1004

#define OP_SSL_CERTFP_LEN_SHA1		20
#define OP_SSL_CERTFP_LEN_SHA256	32
#define OP_SSL_CERTFP_LEN_SHA512	64
#define OP_SSL_CERTFP_LEN_SHA3_256	32
#define OP_SSL_CERTFP_LEN_SHA3_512	64

int op_set_nb(op_fde_t *);
int op_set_buffers(const op_fde_t *, int);

int op_get_sockerr(const op_fde_t *);

void op_settimeout(op_fde_t *, time_t, PF *, void *);
void op_checktimeouts(void *);
void op_connect_tcp(op_fde_t *, struct sockaddr *, struct sockaddr *, CNCB *, void *, int);
void op_connect_tcp_ssl(op_fde_t *, struct sockaddr *, struct sockaddr *, CNCB *, void *, int, const char *);
void op_connect_sctp(op_fde_t *, struct sockaddr_storage *connect_addrs, size_t connect_len, struct sockaddr_storage *bind_addrs, size_t bind_len, CNCB *, void *, int);
int op_connect_sockaddr(const op_fde_t *, struct sockaddr *addr, int len);

const char *op_errstr(int status);
op_fde_t *op_socket(int family, int sock_type, int proto, const char *note);
int op_socketpair(int family, int sock_type, int proto, op_fde_t **F1, op_fde_t **F2,
		  const char *note);

int op_setsockopt_reuseport(const op_fde_t *F);
int op_bind(const op_fde_t *F, const struct sockaddr *addr);
int op_sctp_bindx(const op_fde_t *F, const struct sockaddr_storage *addrs, size_t len);
int op_inet_get_proto(const op_fde_t *F);

void op_accept_tcp(op_fde_t *, ACPRE * precb, ACCB * callback, void *data);
void    op_fd_cork(op_fde_t *, int on);
void    op_zerocopy_drain(op_fde_t *);
ssize_t op_write(op_fde_t *, const void *buf, size_t count);
ssize_t op_writev(op_fde_t *, struct op_iovec *vector, int count);

ssize_t op_read(op_fde_t *, void *buf, size_t count);
int op_pending(op_fde_t *);
int op_pipe(op_fde_t **, op_fde_t **, const char *desc);

int op_setup_ssl_server(const char *cert, const char *keyfile, const char *dhfile,
                        const char *cipher_list, bool verify,
                        const char *ca_cert, const char *min_tls_version);
int op_setup_ssl_server_sni(const char *hostname, const char *cert, const char *keyfile,
                             const char *dhfile, const char *cipher_list, bool verify,
                             const char *ca_cert, const char *min_tls_version);
int op_ssl_listen(op_fde_t *, int backlog, int defer_accept);
int op_listen(op_fde_t *, int backlog, int defer_accept);

const char *op_inet_ntop(int af, const void *src, char *dst, size_t size);
int op_inet_pton(int af, const char *src, void *dst);
const char *op_inet_ntop_sock(const struct sockaddr *src, char *dst, size_t size);
int op_inet_pton_sock(const char *src, struct sockaddr_storage *dst);
int op_getmaxconnect(void);
int op_get_open_fd_count(void);
int op_ignore_errno(int);

/* Generic wrappers */
void op_setselect(op_fde_t *, unsigned int type, PF * handler, void *client_data);
void op_init_netio(void);
int op_select(long);
int op_fd_ssl(const op_fde_t *F);
op_platform_fd_t op_get_fd(const op_fde_t *F);
const char *op_get_ssl_strerror(op_fde_t *F);
int op_get_ssl_certfp(op_fde_t *F, uint8_t certfp[OP_SSL_CERTFP_LEN], int method);
int op_get_ssl_certfp_file(const char *filename, uint8_t certfp[OP_SSL_CERTFP_LEN], int method);

op_fde_t *op_get_fde(op_platform_fd_t fd);

int op_send_fd_buf(op_fde_t *xF, op_fde_t **F, int count, void *data, size_t datasize, pid_t pid);
int op_recv_fd_buf(op_fde_t *F, void *data, size_t datasize, op_fde_t **xF, int count);

void op_set_type(op_fde_t *F, uint16_t type);
uint16_t op_get_type(const op_fde_t *F);

const char *op_get_iotype(void);

typedef enum
{
	OP_PRNG_FILE,
#ifdef _WIN32
	OP_PRNGWIN32,
#endif
	OP_PRNG_DEFAULT,
} prng_seed_t;

int op_init_prng(const char *path, prng_seed_t seed_type);
int op_get_random(void *buf, size_t len);
void op_ssl_start_accepted(op_fde_t *new_F, ACCB * cb, void *data, int timeout, bool wsock);
void op_ssl_start_connected(op_fde_t *F, CNCB * callback, void *data, int timeout);

/* In-process WebSocket (RFC 6455) */
void    op_ws_start_accepted(op_fde_t *F, ACCB *cb, void *data, int timeout);
ssize_t op_ws_read(op_fde_t *F, void *buf, size_t count);
ssize_t op_ws_write(op_fde_t *F, const void *buf, size_t count);
void    op_ws_shutdown(op_fde_t *F);
int     op_fd_ws(const op_fde_t *F);
void    op_ws_attach_transferred(op_fde_t *F);
int op_supports_ssl(void);

unsigned int op_ssl_handshake_count(op_fde_t *F);
void op_ssl_clear_handshake_count(op_fde_t *F);

int op_pass_fd_to_process(op_fde_t *, pid_t, op_fde_t *);
op_fde_t *op_recv_fd(op_fde_t *);

const char *op_ssl_get_cipher(op_fde_t *F);

int op_ipv4_from_ipv6(const struct sockaddr_in6 *restrict ip6, struct sockaddr_in *restrict ip4);

#endif /* LIBOP_COMMIO_H */
