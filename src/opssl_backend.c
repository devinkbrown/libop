/*
 *  Ophion IRC Daemon
 *  opssl_backend.c: opssl native TLS backend.
 *
 *  opssl_backend.c: opssl native TLS backend for libop.
 *
 *  Copyright (C) 2007-2008 ircd-ratbox development team
 *  Copyright (C) 2026 ophion development team
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

#include <libop_config.h>
#include <op_lib.h>

#include <commio-int.h>
#include <commio-ssl.h>
#include <opssl/opssl.h>

#include <sys/random.h>

#ifdef HAVE_KERNEL_TLS
# include <linux/tls.h>
# include <netinet/tcp.h>
#endif

typedef enum
{
	OP_FD_TLS_DIRECTION_IN = 0,
	OP_FD_TLS_DIRECTION_OUT = 1
} op_fd_tls_direction;

#define OP_SSL_ACCEPT_TIMEOUT_DEFAULT 10

#define SSL_P(x) ((opssl_conn_t *)((x)->ssl))

static opssl_ctx_t *ssl_ctx        = NULL;
static opssl_ctx_t *ssl_client_ctx = NULL;

/* -------------------------------------------------------------------------
 * SNI context table
 * ------------------------------------------------------------------------- */
#define SNI_CTX_MAX 64

typedef struct
{
	char        *hostname;
	opssl_ctx_t *ctx;
} sni_entry_t;

static sni_entry_t sni_table[SNI_CTX_MAX];
static int sni_count = 0;

static void
sni_table_free(void)
{
	for (int i = 0; i < sni_count; i++)
	{
		op_free(sni_table[i].hostname);
		opssl_ctx_free(sni_table[i].ctx);
		sni_table[i].hostname = NULL;
		sni_table[i].ctx      = NULL;
	}
	sni_count = 0;
}

struct ssl_connect
{
	CNCB *callback;
	void *data;
	int timeout;
	char sni_hostname[256];
};

static void op_ssl_connect_realcb(op_fde_t *, int, struct ssl_connect *);
static void op_ssl_accept_common(op_fde_t *, void *);
static void op_ssl_connect_common(op_fde_t *, void *);


/*
 * Internal opssl-specific code
 */

static opssl_ctx_t *
build_client_ssl_ctx(void)
{
	opssl_ctx_t *ctx = opssl_ctx_new(OPSSL_TLS_1_2);
	if (ctx == NULL)
	{
		op_lib_log("%s: opssl_ctx_new failed", __func__);
		return NULL;
	}

	opssl_ctx_set_verify(ctx, false, NULL, NULL);
	opssl_ctx_set_min_version(ctx, OPSSL_TLS_1_2);

	opssl_ctx_set_options(ctx,
		OPSSL_OPT_NO_RENEGOTIATION |
		OPSSL_OPT_NO_COMPRESSION);

	opssl_ctx_set_curves(ctx, "X25519:P-521:P-384:P-256");

	return ctx;
}

static int
op_ssl_init_fd(op_fde_t *const F, const op_fd_tls_direction dir,
               const char *const sni_hostname, const bool wsock)
{
	opssl_ctx_t *use_ctx;

	if (dir == OP_FD_TLS_DIRECTION_OUT)
	{
		if (ssl_client_ctx == NULL)
			ssl_client_ctx = build_client_ssl_ctx();

		if (ssl_client_ctx == NULL)
		{
			op_lib_log("%s: could not create client TLS context", __func__);
			return -1;
		}
		use_ctx = ssl_client_ctx;
	}
	else
	{
		if (ssl_ctx == NULL)
		{
			op_lib_log("%s: ssl_ctx is NULL — TLS not configured", __func__);
			return -1;
		}
		use_ctx = ssl_ctx;
	}

	opssl_direction_t opssl_dir = (dir == OP_FD_TLS_DIRECTION_OUT)
	                              ? OPSSL_DIR_OUTBOUND : OPSSL_DIR_INBOUND;

	F->ssl = opssl_conn_new(use_ctx, op_get_fd(F), opssl_dir);

	if (F->ssl == NULL)
	{
		op_lib_log("%s: opssl_conn_new failed", __func__);
		return -1;
	}

	F->tls_outgoing = (dir == OP_FD_TLS_DIRECTION_OUT);

	if (sni_hostname && *sni_hostname)
		opssl_conn_set_sni(SSL_P(F), sni_hostname);

	if (dir == OP_FD_TLS_DIRECTION_OUT && sni_hostname && *sni_hostname)
	{
		const char *alpn[] = { OPSSL_ALPN_DOT };
		opssl_conn_set_alpn(SSL_P(F), alpn, 1);
	}

	if (dir == OP_FD_TLS_DIRECTION_IN)
	{
		if (!wsock)
		{
			const char *alpn[] = { OPSSL_ALPN_IRC };
			opssl_conn_set_alpn(SSL_P(F), alpn, 1);
		}
		const char *alpn_http[] = { OPSSL_ALPN_HTTP11 };
		opssl_conn_set_alpn(SSL_P(F), alpn_http, 1);
	}

	if (wsock && dir == OP_FD_TLS_DIRECTION_IN)
		opssl_ctx_set_verify(use_ctx, false, NULL, NULL);

	return 0;
}

#ifdef HAVE_KERNEL_TLS
static int
do_ktls_setsockopt(int fd, const char *caller, opssl_tls_version_t ver,
                   uint16_t cipher_type,
                   size_t key_sz, size_t salt_sz, size_t iv_sz,
                   const unsigned char *cli_key, const unsigned char *cli_iv,
                   const unsigned char *srv_key, const unsigned char *srv_iv,
                   uint64_t tx_seq, uint64_t rx_seq)
{
	if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0)
	{
		op_lib_log("%s: setsockopt(TCP_ULP, \"tls\"): %s — "
		           "kTLS unavailable (is the kernel tls module loaded?)",
		           caller, strerror(errno));
		return 0;
	}

#define WRITE_SEQ(dst, seq) do {               \
		(dst)[0] = (uint8_t)((seq) >> 56); \
		(dst)[1] = (uint8_t)((seq) >> 48); \
		(dst)[2] = (uint8_t)((seq) >> 40); \
		(dst)[3] = (uint8_t)((seq) >> 32); \
		(dst)[4] = (uint8_t)((seq) >> 24); \
		(dst)[5] = (uint8_t)((seq) >> 16); \
		(dst)[6] = (uint8_t)((seq) >>  8); \
		(dst)[7] = (uint8_t)((seq)      ); \
	} while (0)

	int result = -1;
	int tls_ver = (ver == OPSSL_TLS_1_3) ? TLS_1_3_VERSION : TLS_1_2_VERSION;

	if (cipher_type == TLS_CIPHER_AES_GCM_128)
	{
		struct tls12_crypto_info_aes_gcm_128 tx, rx;
		memset(&tx, 0, sizeof tx);
		memset(&rx, 0, sizeof rx);

		tx.info.version     = (uint16_t)tls_ver;
		tx.info.cipher_type = TLS_CIPHER_AES_GCM_128;
		memcpy(tx.key, srv_key, key_sz);
		if (ver == OPSSL_TLS_1_3) {
			memcpy(tx.salt, srv_iv,            salt_sz);
			memcpy(tx.iv,   srv_iv + salt_sz,  iv_sz);
		} else {
			memcpy(tx.salt, srv_iv, salt_sz);
			WRITE_SEQ(tx.iv, tx_seq);
		}
		WRITE_SEQ(tx.rec_seq, tx_seq);

		rx.info.version     = (uint16_t)tls_ver;
		rx.info.cipher_type = TLS_CIPHER_AES_GCM_128;
		memcpy(rx.key, cli_key, key_sz);
		if (ver == OPSSL_TLS_1_3) {
			memcpy(rx.salt, cli_iv,            salt_sz);
			memcpy(rx.iv,   cli_iv + salt_sz,  iv_sz);
		} else {
			memcpy(rx.salt, cli_iv, salt_sz);
			WRITE_SEQ(rx.iv, rx_seq);
		}
		WRITE_SEQ(rx.rec_seq, rx_seq);

		if (setsockopt(fd, SOL_TLS, TLS_TX, &tx, sizeof tx) < 0)
			op_lib_log("%s: setsockopt(TLS_TX, AES_GCM_128): %s", caller, strerror(errno));
		else if (setsockopt(fd, SOL_TLS, TLS_RX, &rx, sizeof rx) < 0)
			op_lib_log("%s: setsockopt(TLS_RX, AES_GCM_128): %s", caller, strerror(errno));
		else
			result = 1;

		memset(&tx, 0, sizeof tx);
		memset(&rx, 0, sizeof rx);
	}
	else if (cipher_type == TLS_CIPHER_AES_GCM_256)
	{
		struct tls12_crypto_info_aes_gcm_256 tx, rx;
		memset(&tx, 0, sizeof tx);
		memset(&rx, 0, sizeof rx);

		tx.info.version     = (uint16_t)tls_ver;
		tx.info.cipher_type = TLS_CIPHER_AES_GCM_256;
		memcpy(tx.key, srv_key, key_sz);
		if (ver == OPSSL_TLS_1_3) {
			memcpy(tx.salt, srv_iv,            salt_sz);
			memcpy(tx.iv,   srv_iv + salt_sz,  iv_sz);
		} else {
			memcpy(tx.salt, srv_iv, salt_sz);
			WRITE_SEQ(tx.iv, tx_seq);
		}
		WRITE_SEQ(tx.rec_seq, tx_seq);

		rx.info.version     = (uint16_t)tls_ver;
		rx.info.cipher_type = TLS_CIPHER_AES_GCM_256;
		memcpy(rx.key, cli_key, key_sz);
		if (ver == OPSSL_TLS_1_3) {
			memcpy(rx.salt, cli_iv,            salt_sz);
			memcpy(rx.iv,   cli_iv + salt_sz,  iv_sz);
		} else {
			memcpy(rx.salt, cli_iv, salt_sz);
			WRITE_SEQ(rx.iv, rx_seq);
		}
		WRITE_SEQ(rx.rec_seq, rx_seq);

		if (setsockopt(fd, SOL_TLS, TLS_TX, &tx, sizeof tx) < 0)
			op_lib_log("%s: setsockopt(TLS_TX, AES_GCM_256): %s", caller, strerror(errno));
		else if (setsockopt(fd, SOL_TLS, TLS_RX, &rx, sizeof rx) < 0)
			op_lib_log("%s: setsockopt(TLS_RX, AES_GCM_256): %s", caller, strerror(errno));
		else
			result = 1;

		memset(&tx, 0, sizeof tx);
		memset(&rx, 0, sizeof rx);
	}
	else if (cipher_type == TLS_CIPHER_CHACHA20_POLY1305)
	{
		struct tls12_crypto_info_chacha20_poly1305 tx, rx;
		memset(&tx, 0, sizeof tx);
		memset(&rx, 0, sizeof rx);

		tx.info.version     = (uint16_t)tls_ver;
		tx.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		memcpy(tx.key, srv_key, 32);
		memcpy(tx.iv, srv_iv, 12);
		WRITE_SEQ(tx.rec_seq, tx_seq);

		rx.info.version     = (uint16_t)tls_ver;
		rx.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		memcpy(rx.key, cli_key, 32);
		memcpy(rx.iv, cli_iv, 12);
		WRITE_SEQ(rx.rec_seq, rx_seq);

		if (setsockopt(fd, SOL_TLS, TLS_TX, &tx, sizeof tx) < 0)
			op_lib_log("%s: setsockopt(TLS_TX, CHACHA20_POLY1305): %s", caller, strerror(errno));
		else if (setsockopt(fd, SOL_TLS, TLS_RX, &rx, sizeof rx) < 0)
			op_lib_log("%s: setsockopt(TLS_RX, CHACHA20_POLY1305): %s", caller, strerror(errno));
		else
			result = 1;

		memset(&tx, 0, sizeof tx);
		memset(&rx, 0, sizeof rx);
	}

#undef WRITE_SEQ
	return result;
}

static int
op_ssl_try_ktls(op_fde_t *const F)
{
	if (F->tls_outgoing)
		return 0;

	opssl_conn_t *conn = SSL_P(F);
	opssl_tls_version_t ver = opssl_conn_version(conn);
	if (ver != OPSSL_TLS_1_2 && ver != OPSSL_TLS_1_3)
		return 0;

	opssl_ciphersuite_t cipher = opssl_conn_cipher_id(conn);
	uint16_t cipher_type;
	size_t key_sz, salt_sz, iv_sz;

	switch (cipher)
	{
	case OPSSL_TLS_AES_128_GCM_SHA256:
	case OPSSL_TLS_ECDHE_RSA_AES_128_GCM:
	case OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM:
	case OPSSL_TLS_DHE_RSA_AES_128_GCM:
		cipher_type = TLS_CIPHER_AES_GCM_128;
		key_sz = 16; salt_sz = 4; iv_sz = 8;
		if (ver == OPSSL_TLS_1_3) { salt_sz = 0; iv_sz = 12; }
		break;
	case OPSSL_TLS_AES_256_GCM_SHA384:
	case OPSSL_TLS_ECDHE_RSA_AES_256_GCM:
	case OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM:
	case OPSSL_TLS_DHE_RSA_AES_256_GCM:
		cipher_type = TLS_CIPHER_AES_GCM_256;
		key_sz = 32; salt_sz = 4; iv_sz = 8;
		if (ver == OPSSL_TLS_1_3) { salt_sz = 0; iv_sz = 12; }
		break;
	case OPSSL_TLS_CHACHA20_POLY1305_SHA256:
	case OPSSL_TLS_ECDHE_RSA_CHACHA20:
	case OPSSL_TLS_ECDHE_ECDSA_CHACHA20:
	case OPSSL_TLS_DHE_RSA_CHACHA20:
		cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		key_sz = 32; salt_sz = 0; iv_sz = 12;
		break;
	default:
		return 0;
	}

	uint8_t srv_key[32], cli_key[32];
	uint8_t srv_iv[12], cli_iv[12];
	size_t sk_len = sizeof srv_key, ck_len = sizeof cli_key;
	size_t si_len = sizeof srv_iv, ci_len = sizeof cli_iv;

	if (opssl_conn_get_write_key(conn, srv_key, &sk_len) != 0 ||
	    opssl_conn_get_read_key(conn, cli_key, &ck_len) != 0 ||
	    opssl_conn_get_write_iv(conn, srv_iv, &si_len) != 0 ||
	    opssl_conn_get_read_iv(conn, cli_iv, &ci_len) != 0)
		return 0;

	uint64_t tx_seq = 0, rx_seq = 0;
	opssl_conn_get_write_seq(conn, &tx_seq);
	opssl_conn_get_read_seq(conn, &rx_seq);

	int rc = do_ktls_setsockopt(op_get_fd(F), __func__, ver, cipher_type,
	                            key_sz, salt_sz, iv_sz,
	                            cli_key, cli_iv, srv_key, srv_iv,
	                            tx_seq, rx_seq);

	memset(srv_key, 0, sizeof srv_key);
	memset(cli_key, 0, sizeof cli_key);
	memset(srv_iv, 0, sizeof srv_iv);
	memset(cli_iv, 0, sizeof cli_iv);

	if (rc < 0)
	{
		op_lib_log("%s: socket fd %d left in partial kTLS state; connection must close",
		           __func__, op_get_fd(F));
		return -1;
	}

	if (rc == 1)
	{
		F->ktls = true;
		op_lib_log("kTLS: kernel TLS active on fd %d", op_get_fd(F));
	}

	return rc;
}
#endif /* HAVE_KERNEL_TLS */

static void
accept_teardown(op_fde_t *const F)
{
	op_settimeout(F, 0, NULL, NULL);
	op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE, NULL, NULL);

	struct acceptdata *const ad = F->accept;
	if (ad == NULL)
		return;
	slop_assert(ad->callback != NULL);
	F->accept = NULL;
	ad->callback(F, OP_ERROR_SSL, NULL, 0, ad->data);
	op_acceptdata_free(ad);
}

static void
op_ssl_accept_common(op_fde_t *const F, void *const data __attribute__((unused)))
{
	slop_assert(F != NULL);
	slop_assert(F->accept != NULL);
	slop_assert(F->accept->callback != NULL);
	slop_assert(F->ssl != NULL);

	opssl_result_t ret = opssl_accept(SSL_P(F));

	if (ret == OPSSL_OK)
	{
		F->handshake_count++;

#ifdef HAVE_KERNEL_TLS
		int ktls_rc = op_ssl_try_ktls(F);

		if (ktls_rc < 0)
		{
			errno = EIO;
			accept_teardown(F);
			return;
		}
#endif

		op_settimeout(F, 0, NULL, NULL);
		op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE, NULL, NULL);

		struct acceptdata *const ad = F->accept;
		F->accept = NULL;
		ad->callback(F, OP_OK, (struct sockaddr *)&ad->S, ad->addrlen, ad->data);
		op_acceptdata_free(ad);

		return;
	}
	if (ret == OPSSL_WANT_READ)
	{
		op_setselect(F, OP_SELECT_WRITE, NULL, NULL);
		op_setselect(F, OP_SELECT_READ, op_ssl_accept_common, NULL);
		return;
	}
	if (ret == OPSSL_WANT_WRITE)
	{
		op_setselect(F, OP_SELECT_READ, NULL, NULL);
		op_setselect(F, OP_SELECT_WRITE, op_ssl_accept_common, NULL);
		return;
	}

	errno = EIO;
	F->ssl_errno = (uint64_t) opssl_conn_get_error(SSL_P(F));
	accept_teardown(F);
}

static ssize_t op_ssl_read_or_write(int r_or_w, op_fde_t *F,
                                    void *rbuf, const void *wbuf, size_t count);

static void
op_ssl_connect_common(op_fde_t *const F, void *const data)
{
	slop_assert(F != NULL);
	slop_assert(F->ssl != NULL);

	opssl_result_t ret = opssl_connect(SSL_P(F));

	if (ret == OPSSL_OK)
	{
		F->handshake_count++;

		op_settimeout(F, 0, NULL, NULL);
		op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE, NULL, NULL);

		op_ssl_connect_realcb(F, OP_OK, data);

		return;
	}
	if (ret == OPSSL_WANT_READ)
	{
		op_setselect(F, OP_SELECT_WRITE, NULL, NULL);
		op_setselect(F, OP_SELECT_READ, op_ssl_connect_common, data);
		return;
	}
	if (ret == OPSSL_WANT_WRITE)
	{
		op_setselect(F, OP_SELECT_READ, NULL, NULL);
		op_setselect(F, OP_SELECT_WRITE, op_ssl_connect_common, data);
		return;
	}

	errno = EIO;
	F->ssl_errno = (uint64_t) opssl_conn_get_error(SSL_P(F));
	op_settimeout(F, 0, NULL, NULL);
	op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE, NULL, NULL);
	op_ssl_connect_realcb(F, OP_ERROR_SSL, data);
}

static ssize_t
op_ssl_read_or_write(const int r_or_w, op_fde_t *const F, void *const rbuf, const void *const wbuf, const size_t count)
{
	ssize_t ret;
	int saved_errno = errno;

	if (r_or_w == 0)
		ret = opssl_read(SSL_P(F), rbuf, count);
	else
		ret = opssl_write(SSL_P(F), wbuf, count);

	if (ret < 0)
	{
		opssl_err_t err = opssl_conn_get_error(SSL_P(F));
		int is_eagain = (saved_errno == EAGAIN  || saved_errno == EWOULDBLOCK
		              || errno       == EAGAIN  || errno       == EWOULDBLOCK);
		ssize_t need_rw = (r_or_w == 0) ? OP_RW_SSL_NEED_READ
		                                 : OP_RW_SSL_NEED_WRITE;

		/* opssl_read/write return negative for error conditions.
		 * Map the error code from the connection state. */
		(void)err;

		if (is_eagain)
		{
			errno = EAGAIN;
			return need_rw;
		}

		F->ssl_errno = (uint64_t)(unsigned int)err;
		if (err > 0)
		{
			errno = EIO;
			return OP_RW_SSL_ERROR;
		}

		if (is_eagain)
		{
			errno = EAGAIN;
			return need_rw;
		}
		errno = saved_errno;
		return OP_RW_IO_ERROR;
	}
	return ret;
}

static int
make_certfp(opssl_x509_t *const cert, uint8_t certfp[const OP_SSL_CERTFP_LEN], const int method)
{
	opssl_fingerprint_method_t fp_method;
	size_t expected_len;

	switch (method)
	{
	case OP_SSL_CERTFP_METH_CERT_SHA1:
		fp_method = OPSSL_FP_SHA1;
		expected_len = OP_SSL_CERTFP_LEN_SHA1;
		break;
	case OP_SSL_CERTFP_METH_CERT_SHA256:
		fp_method = OPSSL_FP_SHA256;
		expected_len = OP_SSL_CERTFP_LEN_SHA256;
		break;
	case OP_SSL_CERTFP_METH_CERT_SHA512:
		fp_method = OPSSL_FP_SHA512;
		expected_len = OP_SSL_CERTFP_LEN_SHA512;
		break;
	case OP_SSL_CERTFP_METH_SPKI_SHA256:
		fp_method = OPSSL_FP_SPKI_SHA256;
		expected_len = OP_SSL_CERTFP_LEN_SHA256;
		break;
	case OP_SSL_CERTFP_METH_SPKI_SHA512:
		fp_method = OPSSL_FP_SPKI_SHA512;
		expected_len = OP_SSL_CERTFP_LEN_SHA512;
		break;
	case OP_SSL_CERTFP_METH_CERT_SHA3_256:
		fp_method = OPSSL_FP_SHA3_256;
		expected_len = OP_SSL_CERTFP_LEN_SHA3_256;
		break;
	case OP_SSL_CERTFP_METH_CERT_SHA3_512:
		fp_method = OPSSL_FP_SHA3_512;
		expected_len = OP_SSL_CERTFP_LEN_SHA3_512;
		break;
	case OP_SSL_CERTFP_METH_SPKI_SHA3_256:
		fp_method = OPSSL_FP_SPKI_SHA3_256;
		expected_len = OP_SSL_CERTFP_LEN_SHA3_256;
		break;
	case OP_SSL_CERTFP_METH_SPKI_SHA3_512:
		fp_method = OPSSL_FP_SPKI_SHA3_512;
		expected_len = OP_SSL_CERTFP_LEN_SHA3_512;
		break;
	default:
		return 0;
	}

	size_t fp_len = expected_len;
	if (opssl_x509_fingerprint(cert, fp_method, certfp, &fp_len) != 0)
		return 0;

	return (int)fp_len;
}



/*
 * External opssl-specific code
 */

void
op_ssl_shutdown(op_fde_t *const F)
{
	if (F == NULL || F->ssl == NULL)
		return;

	if (!F->ktls)
		opssl_shutdown(SSL_P(F));

	opssl_conn_free(SSL_P(F));
	F->ssl  = NULL;
	F->ktls = false;
}

int
op_init_ssl(void)
{
	if (opssl_init() != 0)
	{
		op_lib_log("%s: opssl_init failed", __func__);
		return 0;
	}

	op_lib_log("%s: opssl backend initialised", __func__);
	return 1;
}

bool
op_ssl_is_ktls(op_fde_t *const F)
{
	if (F == NULL)
		return false;

#ifdef HAVE_KERNEL_TLS
	return F->ktls;
#else
	(void)F;
	return false;
#endif
}

void
op_fde_mark_ktls(op_fde_t *const F)
{
	if (F == NULL)
		return;
#ifdef HAVE_KERNEL_TLS
	F->ktls = true;
#else
	(void)F;
#endif
}

int
op_ssl_export(op_fde_t *const F, uint8_t *const buf, const size_t buflen)
{
	(void)F; (void)buf; (void)buflen;
	return -1;
}

int
op_ssl_adopt_exported(op_fde_t *const F, const uint8_t *const buf, const size_t len)
{
	(void)F; (void)buf; (void)len;
	return -1;
}

bool
op_ssl_is_outgoing_connection(const op_fde_t *const F)
{
	return F != NULL && F->tls_outgoing;
}

int
op_ssl_adopt_exported_outgoing(op_fde_t *const F, const uint8_t *const buf,
                                const size_t len)
{
	(void)F; (void)buf; (void)len;
	return -1;
}

int
op_ssl_export_keying_material(op_fde_t *const F,
                              uint8_t *const out, const size_t outlen,
                              const char *const label,
                              const uint8_t *const context, const size_t context_len)
{
	if (F == NULL || F->ssl == NULL || out == NULL || label == NULL || outlen == 0)
		return 0;

	return (opssl_conn_export_keying_material(SSL_P(F),
	        out, outlen, label, context, context_len) == 0) ? 1 : 0;
}

int
op_ssl_promote_ktls(op_fde_t *const F)
{
#ifdef HAVE_KERNEL_TLS
	if (F == NULL || F->ssl == NULL || F->ktls || F->tls_outgoing)
		return 0;

	return op_ssl_try_ktls(F);
#else
	(void)F;
	return 0;
#endif
}

static opssl_ctx_t *
build_ssl_ctx(const char *certfile, const char *keyfile,
              const char *dhfile, const char *cipherlist, bool verify,
              const char *ca_cert, const char *min_tls_version)
{
	if (certfile == NULL)
	{
		op_lib_log("%s: no certificate file specified", __func__);
		return NULL;
	}

	if (keyfile == NULL)
		keyfile = certfile;

	opssl_tls_version_t min_ver = OPSSL_TLS_1_2;
	if (min_tls_version != NULL && strcasecmp(min_tls_version, "TLSv1.3") == 0)
		min_ver = OPSSL_TLS_1_3;

	opssl_ctx_t *const ctx = opssl_ctx_new(min_ver);

	if (ctx == NULL)
	{
		op_lib_log("%s: opssl_ctx_new failed", __func__);
		return NULL;
	}

	if (opssl_ctx_use_certificate_chain_file(ctx, certfile) != 0)
	{
		op_lib_log("%s: opssl_ctx_use_certificate_chain_file ('%s') failed",
		           __func__, certfile);
		opssl_ctx_free(ctx);
		return NULL;
	}
	op_lib_log("%s: loaded certificate chain '%s'", __func__, certfile);

	if (opssl_ctx_use_private_key_file(ctx, keyfile) != 0)
	{
		op_lib_log("%s: opssl_ctx_use_private_key_file ('%s') failed",
		           __func__, keyfile);
		opssl_ctx_free(ctx);
		return NULL;
	}
	op_lib_log("%s: loaded private key '%s'", __func__, keyfile);

	if (opssl_ctx_check_private_key(ctx) != 0)
	{
		op_lib_log("%s: certificate/key mismatch (cert='%s', key='%s')",
		           __func__, certfile, keyfile);
		opssl_ctx_free(ctx);
		return NULL;
	}

	if (dhfile == NULL)
	{
		op_lib_log("%s: no DH parameters file specified", __func__);
	}
	else if (access(dhfile, R_OK) != 0)
	{
		op_lib_log("%s: DH parameters file not readable: '%s': %s",
		           __func__, dhfile, strerror(errno));
	}
	else if (opssl_ctx_use_dh_params_file(ctx, dhfile) != 0)
	{
		op_lib_log("%s: opssl_ctx_use_dh_params_file ('%s') failed — "
		           "run 'python3 setup.py' to regenerate dhparams.pem",
		           __func__, dhfile);
	}

	if (cipherlist != NULL)
		opssl_ctx_set_ciphersuites(ctx, cipherlist);

	opssl_ctx_disable_session_cache(ctx);

	if (ca_cert && *ca_cert)
	{
		if (opssl_ctx_load_verify_locations(ctx, ca_cert, NULL) != 0)
			op_lib_log("%s: opssl_ctx_load_verify_locations('%s') failed — "
			           "client certificate CA verification will not work",
			           __func__, ca_cert);
	}

	if (verify)
		opssl_ctx_set_verify(ctx, true, NULL, NULL);

	opssl_ctx_set_options(ctx,
		OPSSL_OPT_NO_RENEGOTIATION |
		OPSSL_OPT_NO_COMPRESSION |
		OPSSL_OPT_NO_TICKETS |
		OPSSL_OPT_CIPHER_SERVER_PREF |
		OPSSL_OPT_SINGLE_DH_USE |
		OPSSL_OPT_SINGLE_ECDH_USE);

	opssl_ctx_set_curves(ctx, "X25519:P-521:P-384:P-256");

	opssl_ctx_enable_postquantum(ctx, true);

	return ctx;
}

int
op_setup_ssl_server(const char *const certfile, const char *keyfile,
                    const char *const dhfile, const char *cipherlist,
                    bool verify, const char *ca_cert,
                    const char *min_tls_version)
{
	opssl_ctx_t *const ctx = build_ssl_ctx(certfile, keyfile, dhfile, cipherlist,
	                                       verify, ca_cert, min_tls_version);
	if (ctx == NULL)
		return 0;

	if (ssl_ctx)
		opssl_ctx_free(ssl_ctx);

	ssl_ctx = ctx;

	sni_table_free();

	if (certfile && *certfile)
	{
		if (ssl_client_ctx == NULL)
			ssl_client_ctx = build_client_ssl_ctx();
		if (ssl_client_ctx != NULL)
		{
			const char *kf = (keyfile && *keyfile) ? keyfile : certfile;
			opssl_ctx_use_certificate_chain_file(ssl_client_ctx, certfile);
			opssl_ctx_use_private_key_file(ssl_client_ctx, kf);
		}
	}

	op_lib_log("%s: TLS configuration successful", __func__);
	return 1;
}

int
op_setup_ssl_server_sni(const char *const hostname,
                        const char *const certfile, const char *keyfile,
                        const char *const dhfile, const char *cipherlist,
                        bool verify, const char *ca_cert,
                        const char *min_tls_version)
{
	if (hostname == NULL || *hostname == '\0')
	{
		op_lib_log("%s: empty hostname; use op_setup_ssl_server for the default certificate",
		           __func__);
		return 0;
	}

	opssl_ctx_t *const ctx = build_ssl_ctx(certfile, keyfile, dhfile, cipherlist,
	                                       verify, ca_cert, min_tls_version);
	if (ctx == NULL)
		return 0;

	for (int i = 0; i < sni_count; i++)
	{
		if (strcasecmp(sni_table[i].hostname, hostname) == 0)
		{
			opssl_ctx_free(sni_table[i].ctx);
			sni_table[i].ctx = ctx;
			if (ssl_ctx)
				opssl_ctx_add_sni(ssl_ctx, hostname, ctx);
			op_lib_log("%s: updated SNI certificate for '%s'", __func__, hostname);
			return 1;
		}
	}

	if (sni_count >= SNI_CTX_MAX)
	{
		op_lib_log("%s: SNI table full (max %d entries); cannot add '%s'",
		           __func__, SNI_CTX_MAX, hostname);
		opssl_ctx_free(ctx);
		return 0;
	}

	sni_table[sni_count].hostname = op_strdup(hostname);
	if (sni_table[sni_count].hostname == NULL)
	{
		op_lib_log("%s: out of memory for hostname '%s'", __func__, hostname);
		opssl_ctx_free(ctx);
		return 0;
	}

	sni_table[sni_count].ctx = ctx;
	sni_count++;

	if (ssl_ctx)
		opssl_ctx_add_sni(ssl_ctx, hostname, ctx);

	op_lib_log("%s: registered SNI certificate for '%s'", __func__, hostname);
	return 1;
}

int
op_init_prng(const char *const path, prng_seed_t seed_type)
{
	(void) path;
	(void) seed_type;
	op_lib_log("%s: PRNG initialised (getrandom)", __func__);
	return 1;
}

int
op_get_random(void *const buf, const size_t length)
{
	if (getrandom(buf, length, 0) != (ssize_t)length)
	{
		op_lib_log("%s: getrandom: %s", __func__, strerror(errno));
		return 0;
	}

	return 1;
}

const char *
op_get_ssl_strerror(op_fde_t *const F)
{
	if (F == NULL || F->ssl == NULL)
	{
		static _Thread_local char errbuf[64];
		(void) snprintf(errbuf, sizeof errbuf, "opssl error %" PRIu64, F ? F->ssl_errno : 0);
		return errbuf;
	}

	const char *s = opssl_conn_get_error_string(SSL_P(F));
	return (s && *s) ? s : "unknown error";
}

int
op_get_ssl_certfp(op_fde_t *const F, uint8_t certfp[const OP_SSL_CERTFP_LEN], const int method)
{
	if (F == NULL || F->ssl == NULL)
		return 0;

	opssl_x509_t *const peer_cert = opssl_conn_get_peer_cert(SSL_P(F));
	if (peer_cert == NULL)
		return 0;

	const int len = make_certfp(peer_cert, certfp, method);
	opssl_x509_free(peer_cert);
	return len;
}

int
op_get_ssl_certfp_file(const char *const filename, uint8_t certfp[const OP_SSL_CERTFP_LEN], const int method)
{
	opssl_x509_t *const cert = opssl_x509_from_file(filename);
	if (cert == NULL)
		return 0;

	int len = make_certfp(cert, certfp, method);

	opssl_x509_free(cert);
	return len;
}

void
op_get_ssl_info(char *const buf, const size_t len)
{
	(void) snprintf(buf, len, "TLS: opssl %s", opssl_version_string());
}

const char *
op_ssl_get_cipher(op_fde_t *const F)
{
	if (F == NULL || F->ssl == NULL)
		return NULL;

	static _Thread_local char buf[512];

	opssl_tls_version_t ver = opssl_conn_version(SSL_P(F));
	const char *cipher = opssl_conn_cipher_name(SSL_P(F));
	const char *version;

	switch (ver)
	{
	case OPSSL_TLS_1_2: version = "TLSv1.2"; break;
	case OPSSL_TLS_1_3: version = "TLSv1.3"; break;
	default:            version = "unknown"; break;
	}

	(void) snprintf(buf, sizeof buf, "%s, %s",
	                version, cipher ? cipher : "unknown");

	return buf;
}

ssize_t
op_ssl_read(op_fde_t *const F, void *const buf, const size_t count)
{
#ifdef HAVE_KERNEL_TLS
	if (F->ktls)
	{
#		ifndef TLS_RT_APPLICATION_DATA
#		define TLS_RT_APPLICATION_DATA 23
#		endif
#		ifndef TLS_GET_RECORD_TYPE
#		define TLS_GET_RECORD_TYPE 1
#		endif

		uint8_t        cmsg_buf[CMSG_SPACE(sizeof(uint8_t))];
		struct iovec   iov = { .iov_base = buf, .iov_len = count };
		struct msghdr  msg = {
			.msg_iov        = &iov,
			.msg_iovlen     = 1,
			.msg_control    = cmsg_buf,
			.msg_controllen = sizeof cmsg_buf,
		};

		ssize_t r;
		do { r = recvmsg(op_get_fd(F), &msg, MSG_DONTWAIT); }
		while (r < 0 && errno == EINTR);

		if (r < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				errno = EAGAIN;
				return OP_RW_SSL_NEED_READ;
			}
			if (errno == EBADMSG)
			{
				op_lib_log("kTLS read fd %d: alert/control record (EBADMSG) — closing",
				           op_get_fd(F));
				errno = EPROTO;
			}
			return OP_RW_IO_ERROR;
		}

		for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm != NULL;
		     cm = CMSG_NXTHDR(&msg, cm))
		{
			if (cm->cmsg_level == SOL_TLS &&
			    cm->cmsg_type  == TLS_GET_RECORD_TYPE)
			{
				const uint8_t rec_type = *(const uint8_t *)CMSG_DATA(cm);
				if (rec_type == TLS_RT_APPLICATION_DATA)
					break;

				if (rec_type == 21)
				{
					if (r >= 2 && ((const uint8_t *)buf)[1] == 0)
					{
						errno = 0;
						return 0;
					}
					op_lib_log("kTLS read fd %d: TLS alert level=%u desc=%u — closing",
					           op_get_fd(F),
					           r >= 1 ? ((const uint8_t *)buf)[0] : 0,
					           r >= 2 ? ((const uint8_t *)buf)[1] : 0);
				}
				else
				{
					op_lib_log("kTLS read fd %d: non-app-data record type=%u — closing",
					           op_get_fd(F), rec_type);
				}
				errno = EPROTO;
				return OP_RW_IO_ERROR;
			}
		}

		return r;
	}
#endif
	return op_ssl_read_or_write(0, F, buf, NULL, count);
}

int
op_ssl_pending(op_fde_t *const F)
{
	if (F == NULL || F->ssl == NULL || F->ktls)
		return 0;
	return opssl_pending(SSL_P(F));
}

ssize_t
op_ssl_write(op_fde_t *const F, const void *const buf, const size_t count)
{
#ifdef HAVE_KERNEL_TLS
	if (F->ktls)
	{
		ssize_t r;
		do { r = send(op_get_fd(F), buf, count, MSG_NOSIGNAL | MSG_DONTWAIT); }
		while (r < 0 && errno == EINTR);

		if (r < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				errno = EAGAIN;
				return OP_RW_SSL_NEED_WRITE;
			}
			if (errno == ENOTSUP)
			{
				errno = EAGAIN;
				return OP_RW_SSL_NEED_WRITE;
			}
			return OP_RW_IO_ERROR;
		}
		return r;
	}
#endif
	return op_ssl_read_or_write(1, F, NULL, buf, count);
}



/*
 * Internal library-agnostic code
 */

static void
op_ssl_connect_realcb(op_fde_t *const F, const int status, struct ssl_connect *const sconn)
{
	struct conndata *const conn = F->connect;
	if (conn == NULL)
	{
		op_lib_log("op_ssl_connect_realcb: F->connect is NULL (fd %d, status %d)",
		           F->fd, status);
		op_free(sconn);
		return;
	}

	conn->callback = sconn->callback;
	conn->data = sconn->data;

	op_connect_callback(F, status);
	op_free(sconn);
}

static void
op_ssl_timeout_cb(op_fde_t *const F, void *const data __attribute__((unused)))
{
	struct acceptdata *const ad = F->accept;
	if (ad == NULL)
		return;
	slop_assert(ad->callback != NULL);
	F->accept = NULL;
	ad->callback(F, OP_ERR_TIMEOUT, NULL, 0, ad->data);
	op_acceptdata_free(ad);
}

static void
op_ssl_tryconn_timeout_cb(op_fde_t *const F, void *const data)
{
	op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE, NULL, NULL);
	op_ssl_connect_realcb(F, OP_ERR_TIMEOUT, data);
}

static void
op_ssl_tryconn(op_fde_t *const F, const int status, void *const data)
{
	slop_assert(F != NULL);

	struct ssl_connect *const sconn = data;

	if (status != OP_OK)
	{
		op_ssl_connect_realcb(F, status, sconn);
		return;
	}

	F->type |= OP_FD_SSL;

	op_settimeout(F, sconn->timeout, op_ssl_tryconn_timeout_cb, sconn);
	if (op_ssl_init_fd(F, OP_FD_TLS_DIRECTION_OUT, sconn->sni_hostname, false) < 0)
	{
		op_settimeout(F, 0, NULL, NULL);
		op_ssl_connect_realcb(F, OP_ERROR_SSL, sconn);
		return;
	}
	op_ssl_connect_common(F, sconn);
}



/*
 * External library-agnostic code
 */

int
op_supports_ssl(void)
{
	return 1;
}

unsigned int
op_ssl_handshake_count(op_fde_t *const F)
{
	return F->handshake_count;
}

void
op_ssl_clear_handshake_count(op_fde_t *const F)
{
	F->handshake_count = 0;
}

void
op_ssl_start_accepted(op_fde_t *const F, ACCB *const cb, void *const data, const int timeout,
                      const bool wsock)
{
	F->type |= OP_FD_SSL;

	F->accept = op_acceptdata_alloc();
	F->accept->callback = cb;
	F->accept->data = data;
	F->accept->addrlen = 0;
	(void) memset(&F->accept->S, 0x00, sizeof F->accept->S);

	op_settimeout(F, timeout, op_ssl_timeout_cb, NULL);
	if (op_ssl_init_fd(F, OP_FD_TLS_DIRECTION_IN, NULL, wsock) < 0)
	{
		errno = EIO;
		accept_teardown(F);
		return;
	}
	op_ssl_accept_common(F, NULL);
}

void
op_ssl_accept_setup(op_fde_t *const srv_F, op_fde_t *const cli_F, struct sockaddr *const st,
                    const int addrlen, const bool wsock)
{
	cli_F->type |= OP_FD_SSL;

	cli_F->accept = op_acceptdata_alloc();
	cli_F->accept->callback = srv_F->accept->callback;
	cli_F->accept->data = srv_F->accept->data;
	const int safe_addrlen = (addrlen > 0 && (size_t)addrlen <= sizeof cli_F->accept->S)
	                         ? addrlen : (int)sizeof cli_F->accept->S;
	cli_F->accept->addrlen = (op_socklen_t) safe_addrlen;
	(void) memset(&cli_F->accept->S, 0x00, sizeof cli_F->accept->S);
	(void) memcpy(&cli_F->accept->S, st, (size_t) safe_addrlen);

	op_settimeout(cli_F, OP_SSL_ACCEPT_TIMEOUT_DEFAULT, op_ssl_timeout_cb, NULL);
	if (op_ssl_init_fd(cli_F, OP_FD_TLS_DIRECTION_IN, NULL, wsock) < 0)
	{
		errno = EIO;
		accept_teardown(cli_F);
		return;
	}
	op_ssl_accept_common(cli_F, NULL);
}

int
op_ssl_listen(op_fde_t *const F, const int backlog, const int defer_accept)
{
	const int result = op_listen(F, backlog, defer_accept);

	if (result == 0)
		F->type = OP_FD_SOCKET | OP_FD_LISTEN | OP_FD_SSL;

	return result;
}

void
op_connect_tcp_ssl(op_fde_t *const F, struct sockaddr *const dest, struct sockaddr *const clocal,
                   CNCB *const callback, void *const data, const int timeout,
                   const char *const sni_hostname)
{
	if (F == NULL)
		return;

	struct ssl_connect *const sconn = op_malloc(sizeof *sconn);
	sconn->data = data;
	sconn->callback = callback;
	sconn->timeout = timeout;
	if (sni_hostname && *sni_hostname)
		op_strlcpy(sconn->sni_hostname, sni_hostname, sizeof sconn->sni_hostname);
	else
		sconn->sni_hostname[0] = '\0';

	op_connect_tcp(F, dest, clocal, op_ssl_tryconn, sconn, timeout);
}

void
op_ssl_start_connected(op_fde_t *const F, CNCB *const callback, void *const data, const int timeout)
{
	if (F == NULL)
		return;

	struct ssl_connect *const sconn = op_malloc(sizeof *sconn);
	sconn->data = data;
	sconn->callback = callback;
	sconn->timeout = timeout;
	sconn->sni_hostname[0] = '\0';

	F->connect = op_conndata_alloc();
	F->connect->callback = callback;
	F->connect->data = data;
	F->type |= OP_FD_SSL;

	op_settimeout(F, sconn->timeout, op_ssl_tryconn_timeout_cb, sconn);
	if (op_ssl_init_fd(F, OP_FD_TLS_DIRECTION_OUT, sconn->sni_hostname, false) < 0)
	{
		op_settimeout(F, 0, NULL, NULL);
		op_ssl_connect_realcb(F, OP_ERROR_SSL, sconn);
		return;
	}
	op_ssl_connect_common(F, sconn);
}
