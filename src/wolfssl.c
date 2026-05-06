/*
 *  Ophion IRC Daemon
 *  wolfssl.c: wolfSSL native TLS backend.
 *
 *  Copyright (C) 2007-2008 ircd-ratbox development team
 *  Copyright (C) 2007-2008 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2015-2016 Aaron Jones <aaronmdjones@gmail.com>
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

#if HAVE_WOLFSSL

#include <commio-int.h>
#include <commio-ssl.h>

/* wolfssl/options.h must be included before wolfssl/ssl.h so that all
 * compile-time feature flags (WOLFSSL_SHA512, HAVE_FFDHE, etc.) defined
 * at wolfSSL build time are visible before ssl.h uses them. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <sys/random.h>

/*
 * Linux kernel TLS (kTLS) — manual implementation.
 *
 * When HAVE_KERNEL_TLS is defined (and wolfSSL was NOT built with native
 * kTLS support), ophion sets up kernel TLS itself after the TLS handshake
 * using wolfSSL's key-extraction APIs (requires --enable-atomicuser).
 * Once activated:
 *  - The kernel handles all AES-GCM / ChaCha20-Poly1305 encryption.
 *  - op_ssl_read / op_ssl_write bypass wolfSSL and call recv/send directly.
 *  - The socket FD can be transferred across /UPGRADE (via SCM_RIGHTS)
 *    without disconnecting the TLS client.
 *
 * Both TLS 1.2 and TLS 1.3 are supported.  See op_ssl_try_ktls() for the
 * per-version IV and sequence number details.
 */
#if defined(HAVE_KERNEL_TLS) && !defined(HAVE_WOLFSSL_KTLS)
# include <linux/tls.h>   /* struct tls12_crypto_info_*, TLS_TX/RX, setsockopt constants */
# include <netinet/tcp.h> /* TCP_ULP */
#elif defined(HAVE_WOLFSSL_KTLS)
/* Include linux/tls.h for SOL_TLS and TLS_GET_RECORD_TYPE — needed by the
 * raw recv/send path in op_ssl_read/write for migrated kTLS clients whose
 * wolfSSL context (F->ssl) no longer exists in the new binary. */
# include <linux/tls.h>
#endif

/* wolfSSL is our sole TLS backend and always supports modern TLS, named
 * curves, and X25519.  Define the feature macros unconditionally. */
#define LOP_HAVE_TLS_METHOD_API  1
#define LOP_HAVE_TLS_SET_CURVES  1
#define LOP_HAVE_TLS_ECDH_X25519 1

/* wolfSSL always requires explicit initialisation. */

/* Version info — wolfSSL native. */
#define LOP_SSL_VNUM_COMPILETIME  ((unsigned long)LIBWOLFSSL_VERSION_HEX)
#define LOP_SSL_VNUM_RUNTIME      ((unsigned long)wolfSSL_lib_version_hex())
#define LOP_SSL_VTEXT_COMPILETIME "wolfSSL " LIBWOLFSSL_VERSION_STRING
#define LOP_SSL_VTEXT_RUNTIME     wolfSSL_lib_version()

/*
 * Default supported ciphersuites (if the user does not provide any) and
 * curves.  We prefer AEAD ciphersuites first in order of strength, then
 * SHA2 ciphersuites, then remaining suites.
 */

static const char op_default_ciphers[] = ""
	"aECDSA+kEECDH+CHACHA20:"
	"aRSA+kEECDH+CHACHA20:"
	"aRSA+kEDH+CHACHA20:"
	"aECDSA+kEECDH+AESGCM:"
	"aRSA+kEECDH+AESGCM:"
	"aRSA+kEDH+AESGCM:"
	"aECDSA+kEECDH+AESCCM:"
	"aRSA+kEECDH+AESCCM:"
	"aRSA+kEDH+AESCCM:"
	"@STRENGTH:"
	"aECDSA+kEECDH+HIGH+SHA384:"
	"aRSA+kEECDH+HIGH+SHA384:"
	"aRSA+kEDH+HIGH+SHA384:"
	"aECDSA+kEECDH+HIGH+SHA256:"
	"aRSA+kEECDH+HIGH+SHA256:"
	"aRSA+kEDH+HIGH+SHA256:"
	"aECDSA+kEECDH+HIGH:"
	"aRSA+kEECDH+HIGH:"
	"aRSA+kEDH+HIGH:"
	"HIGH:"
	"!3DES:"
	"!aNULL";

/* X25519 is always available with our wolfSSL build requirement. */
static char op_default_curves[] = "X25519:P-521:P-384:P-256";

typedef enum
{
	OP_FD_TLS_DIRECTION_IN = 0,
	OP_FD_TLS_DIRECTION_OUT = 1
} op_fd_tls_direction;

/*
 * Timeout (seconds) applied to TLS handshakes initiated by
 * op_ssl_accept_setup().  op_ssl_start_accepted() uses a caller-supplied
 * timeout; this constant covers the accept path where the caller does not
 * provide one.
 */
#define OP_SSL_ACCEPT_TIMEOUT_DEFAULT 10

#define SSL_P(x) ((WOLFSSL *)((x)->ssl))



static WOLFSSL_CTX *ssl_ctx        = NULL;
static WOLFSSL_CTX *ssl_client_ctx = NULL; /* minimal CTX for outgoing TLS */

/* -------------------------------------------------------------------------
 * SNI context table: maps hostnames to per-hostname WOLFSSL_CTX objects.
 * The default ssl_ctx is used when no SNI hostname matches.
 * ------------------------------------------------------------------------- */
#define SNI_CTX_MAX 64

typedef struct
{
	char        *hostname;
	WOLFSSL_CTX *ctx;
} sni_entry_t;

#ifdef WOLFSSL_TLSEXT_NAMETYPE_host_name
static sni_entry_t sni_table[SNI_CTX_MAX];
static int sni_count = 0;

/* Free all SNI table entries.  Called from op_setup_ssl_server() on REHASH
 * so that stale per-hostname contexts and their strdup'd names are released.
 * After this call the caller is expected to re-register all SNI entries. */
static void
sni_table_free(void)
{
	for (int i = 0; i < sni_count; i++)
	{
		op_free(sni_table[i].hostname);
		wolfSSL_CTX_free(sni_table[i].ctx);
		sni_table[i].hostname = NULL;
		sni_table[i].ctx      = NULL;
	}
	sni_count = 0;
}

static int
sni_servername_cb(WOLFSSL *ssl, int *al __attribute__((unused)), void *arg __attribute__((unused)))
{
	const char *name = wolfSSL_get_servername(ssl, WOLFSSL_TLSEXT_NAMETYPE_host_name);
	if (name == NULL)
		return WOLFSSL_TLSEXT_ERR_OK;

	for (int i = 0; i < sni_count; i++)
	{
		if (strcasecmp(sni_table[i].hostname, name) == 0)
		{
			/*
			 * Transfer the per-session CTX reference: release the
			 * reference taken on the default ssl_ctx in op_ssl_init_fd,
			 * then take a new reference on the SNI-specific CTX.  This
			 * keeps exactly one CTX reference alive per session regardless
			 * of which CTX is ultimately used.
			 */
			WOLFSSL_CTX *old_ctx = wolfSSL_get_SSL_CTX(ssl);
			if (wolfSSL_CTX_up_ref(sni_table[i].ctx) != 1)
			{
				op_lib_log("%s: wolfSSL_CTX_up_ref failed for '%s'", __func__, name);
				return WOLFSSL_TLSEXT_ERR_OK; /* use default ctx */
			}
			wolfSSL_set_SSL_CTX(ssl, sni_table[i].ctx);
			wolfSSL_CTX_free(old_ctx);
			return WOLFSSL_TLSEXT_ERR_OK;
		}
	}
	return WOLFSSL_TLSEXT_ERR_OK; /* no match — use default */
}
#endif /* WOLFSSL_TLSEXT_NAMETYPE_host_name */

struct ssl_connect
{
	CNCB *callback;
	void *data;
	int timeout;
	char sni_hostname[256];
};

static const char *op_ssl_strerror(uint64_t);
static void op_ssl_connect_realcb(op_fde_t *, int, struct ssl_connect *);



/*
 * Internal wolfSSL-specific code
 */

/*
 * tls_client_send_cb — custom wolfSSL IOSend callback for the outgoing TLS
 * client context.  Uses MSG_NOSIGNAL to suppress SIGPIPE on all platforms.
 *
 * When OPENSSL_EXTRA is available, also logs every outgoing TLS record by
 * content type so that unexpected post-handshake sends (e.g. KeyUpdate side-
 * effects from wolfSSL 5.8.x NST processing) can be identified.  During
 * wolfSSL_connect() wolfSSL marks the handshake done after verifying the
 * server's Finished but BEFORE sending the Client Finished, so the 74-byte
 * Finished transmission is expected to appear in these logs.
 */
static int
tls_client_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx_arg)
{
	(void)ctx_arg;

#ifdef OPENSSL_EXTRA
	if (sz > 0) {
		unsigned char ct = (unsigned char)buf[0];
		op_lib_log("TLS client TX: type=%u (%s) sz=%d",
		           ct,
		           ct == 20 ? "CCS"      :
		           ct == 21 ? "ALERT"    :
		           ct == 22 ? "HANDSHAKE":
		           ct == 23 ? "APP_DATA" : "UNKNOWN",
		           sz);
	}
#endif

	int fd = wolfSSL_get_fd(ssl);
	ssize_t r;
	do { r = send(fd, buf, (size_t)sz, MSG_NOSIGNAL); }
	while (r < 0 && errno == EINTR);

	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return WOLFSSL_CBIO_ERR_WANT_WRITE;
		if (errno == ECONNRESET)
			return WOLFSSL_CBIO_ERR_CONN_RST;
		if (errno == EPIPE || errno == ENOTCONN)
			return WOLFSSL_CBIO_ERR_CONN_CLOSE;
		return WOLFSSL_CBIO_ERR_GENERAL;
	}
	return (int)r;
}

#ifdef OPENSSL_EXTRA
/*
 * tls_client_info_cb — wolfSSL info callback that logs TLS alerts on outgoing
 * connections, helping identify protocol-level rejections from remote servers.
 *
 * Called for every SSL state change; only SSL_CB_ALERT events are logged:
 *  SSL_CB_ALERT | SSL_CB_WRITE  → alert was SENT by us to the server
 *  SSL_CB_ALERT (no write bit)  → alert was RECEIVED from the server
 *  val = (level << 8) | description
 */
static void
tls_client_info_cb(const WOLFSSL *ssl __attribute__((unused)), int type, int val)
{
	if (!(type & SSL_CB_ALERT))
		return;

	int level = (val >> 8) & 0xff;
	int desc  =  val       & 0xff;
	op_lib_log("TLS client alert %s: level=%d (%s) desc=%d",
	           (type & SSL_CB_WRITE) ? "SENT" : "RECV",
	           level,
	           level == 1 ? "warning" : level == 2 ? "fatal" : "?",
	           desc);
}
#endif /* OPENSSL_EXTRA */

/*
 * build_client_ssl_ctx — create a minimal wolfSSL CTX for outgoing TLS
 * client connections (DNS-over-TLS and S2S).
 *
 * Unlike the server CTX this context:
 *  - starts with no client certificate or private key (op_setup_ssl_server
 *    loads the server cert/key into it afterwards for S2S auth)
 *  - uses wolfSSLv23_client_method() so TLS 1.3 is negotiated when the
 *    server supports it.  Forcing TLS 1.2 causes silent ALPN failure against
 *    DoT resolvers: public DoT servers (Cloudflare, Google, Quad9) only echo
 *    ALPN "dot" in TLS 1.3 EncryptedExtensions, not in TLS 1.2 ServerHello.
 *    Without the ALPN echo wolfSSL_ALPN_GetProtocol() returns NULL and the
 *    server closes per RFC 7858 §4.1.
 *
 *    NOTE: wolfSSL_CTX_set_alpn_protos() is dead code for client ALPN
 *    advertisement — it stores data in ctx->alpn_cli_protos which the
 *    handshake path never reads.  wolfSSL_UseALPN() per-session is the
 *    only working client-ALPN path (see op_ssl_init_fd below).
 *
 *    With wolfSSL 5.8.x (--enable-opensslall) NST records are processed
 *    inside wolfSSL_connect().  When an NST and close_notify arrive in the
 *    same TCP segment the drain loop in op_ssl_connect_common() handles both
 *    and reports failure; when they arrive separately the close_notify
 *    surfaces on the first wolfSSL_write().  The DoT layer handles this with
 *    an immediate no-penalty reconnect so 1-RTT resumption can succeed on the
 *    second attempt.
 *  - does NOT set server-preference cipher ordering
 *  - uses WOLFSSL_VERIFY_NONE (remote peers trusted by configuration; SNI is
 *    still sent for RFC 7858 §3.2 compliance and S2S server identification)
 */
static WOLFSSL_CTX *
build_client_ssl_ctx(void)
{
	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
	if (ctx == NULL)
	{
		op_lib_log("%s: wolfSSL_CTX_new failed", __func__);
		return NULL;
	}

	wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

	/* Enforce TLS 1.2 minimum on outgoing connections.
	 * Use native wolfSSL API first (always available), then the
	 * OpenSSL-compat version as belt-and-suspenders. */
	wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
#ifdef OPENSSL_EXTRA
	(void) wolfSSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#endif

	/* Disable deprecated/insecure TLS features on outgoing connections. */
	#ifdef WOLFSSL_OP_NO_TLSv1
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1);
	#endif
	#ifdef WOLFSSL_OP_NO_TLSv1_1
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_1);
	#endif
	#ifdef WOLFSSL_OP_NO_RENEGOTIATION
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_RENEGOTIATION);
	#endif
	#ifdef WOLFSSL_OP_NO_COMPRESSION
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_COMPRESSION);
	#endif

#if (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))
	(void) wolfSSL_CTX_set1_curves_list(ctx, op_default_curves);
#endif

	/* Enable TLS session tickets so wolfSSL can receive and cache NSTs from
	 * the server, then attempt 1-RTT (session resumption) on reconnect.
	 * This is especially important for DNS-over-TLS where reconnects occur
	 * frequently; 1-RTT avoids an extra round-trip on resume.
	 * Requires wolfSSL built with HAVE_SESSION_TICKET (--enable-sessionticket). */
#ifdef HAVE_SESSION_TICKET
	(void) wolfSSL_CTX_UseSessionTicket(ctx);
#endif

	/* Diagnostic: intercept wolfSSL sends to log any post-handshake records
	 * emitted before we write a DNS query.  wolfSSL 5.8.x may send a KeyUpdate
	 * or similar record as a side-effect of NST processing inside
	 * wolfSSL_connect(); this callback will confirm or rule that out. */
	wolfSSL_CTX_SetIOSend(ctx, tls_client_send_cb);

#ifdef OPENSSL_EXTRA
	/* Log TLS alerts (sent or received) to help diagnose server-side
	 * rejections (certificate_required, no_application_protocol, etc.)
	 * vs plain TCP RST / close_notify failures. */
	wolfSSL_CTX_set_info_callback(ctx, tls_client_info_cb);
#endif

	return ctx;
}

static int
op_ssl_init_fd(op_fde_t *const F, const op_fd_tls_direction dir,
               const char *const sni_hostname, const bool wsock)
{
	/*
	 * For outgoing (client) TLS connections use ssl_client_ctx — a
	 * minimal context without server cert/key or server-preference cipher
	 * ordering.  Session tickets are enabled so wolfSSL can cache NSTs
	 * from the server and attempt 1-RTT resumption on reconnect, which
	 * avoids repeated close_notify-before-query failures on some DoT servers.
	 *
	 * For incoming (server) TLS connections use ssl_ctx as before.
	 *
	 * Take a per-session reference on the CTX before creating the WOLFSSL
	 * object.  wolfSSL does not reference-count CTX internally (without
	 * OPENSSL_EXTRA), so if op_setup_ssl_server() replaces and frees the
	 * global ssl_ctx on REHASH, any live session would hold a dangling CTX
	 * pointer.  The matching wolfSSL_CTX_free() is in op_ssl_shutdown().
	 *
	 * For sessions whose CTX is later switched by sni_servername_cb we
	 * also transfer the reference there (release old, acquire new).
	 */
	WOLFSSL_CTX *use_ctx;

	if (dir == OP_FD_TLS_DIRECTION_OUT)
	{
		/* Lazily create the client CTX on first outgoing connection. */
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

	if (wolfSSL_CTX_up_ref(use_ctx) != 1)
	{
		op_lib_log("%s: wolfSSL_CTX_up_ref failed", __func__);
		return -1;
	}

	F->ssl = wolfSSL_new(use_ctx);

	if (F->ssl == NULL)
	{
		op_lib_log("%s: wolfSSL_new: failed", __func__);
		/* Release the reference we just took since no session was created. */
		wolfSSL_CTX_free(use_ctx);
		return -1;
	}

	F->tls_outgoing = (dir == OP_FD_TLS_DIRECTION_OUT);

	wolfSSL_set_fd(SSL_P(F), op_get_fd(F));

	/* Tell wolfSSL the socket is non-blocking so that internal I/O calls
	 * return WOLFSSL_ERROR_WANT_READ / WOLFSSL_ERROR_WANT_WRITE instead of
	 * retrying synchronously.  wolfSSL_set_fd() inspects O_NONBLOCK via
	 * fcntl() on some builds, but the explicit call is always correct and
	 * removes the dependency on that optional auto-detection path. */
	wolfSSL_set_using_nonblock(SSL_P(F), 1);

#if defined(HAVE_KERNEL_TLS) && !defined(HAVE_WOLFSSL_KTLS)
	/*
	 * Retain key material after the handshake so op_ssl_try_ktls() can
	 * extract write keys and IVs for kTLS setup.  wolfSSL zeroes these
	 * arrays by default once the handshake is complete; KeepArrays()
	 * suppresses that zeroing.  Only needed for server (IN) connections
	 * since kTLS is only set up for incoming IRC client sockets.
	 */
	if (dir == OP_FD_TLS_DIRECTION_IN)
		wolfSSL_KeepArrays(SSL_P(F));
#endif

	if (sni_hostname && *sni_hostname)
	{
		size_t sni_len = strlen(sni_hostname);
		if (sni_len <= USHRT_MAX)
			wolfSSL_UseSNI(SSL_P(F), WOLFSSL_SNI_HOST_NAME,
			               sni_hostname, (unsigned short)sni_len);
	}

	/*
	 * Advertise ALPN "dot" for outgoing DoT connections (RFC 7858 §3.2).
	 *
	 * wolfSSL_UseALPN() is the only working client-side ALPN API in
	 * wolfSSL 5.6.x.  It calls TLSX_UseALPN() which adds the extension to
	 * ssl->extensions; TLSX_WriteRequest() then includes it in the TLS
	 * ClientHello for both TLS 1.2 and TLS 1.3.
	 *
	 * wolfSSL_CTX_set_alpn_protos() stores data in ctx->alpn_cli_protos
	 * which is never read by the handshake path — it is dead code for
	 * client ALPN.  wolfSSL_set_alpn_protos() (per-session OpenSSL-compat)
	 * is not compiled into libwolfssl 5.6.6 on this system.
	 *
	 * CONTINUE_ON_MISMATCH: if the server does not echo a protocol we
	 * offered, the connection continues.  In practice every RFC 7858-
	 * compliant server WILL echo "dot", so a mismatch would indicate a
	 * mis-configured server; continuing allows us to attempt the DNS query
	 * and rely on the server closing if it truly does not accept us.
	 *
	 * HAVE_ALPN is required by meson.build — if wolfSSL was built without
	 * --enable-alpn this translation unit will not compile, which is the
	 * correct behaviour: silently omitting ALPN breaks every DoT server.
	 */
#ifndef HAVE_ALPN
#  error "wolfSSL ALPN support (HAVE_ALPN) is required for DNS-over-TLS. " \
         "Rebuild wolfSSL with --enable-alpn (see meson.build for details)."
#endif
	/*
	 * Advertise ALPN "dot" only for DNS-over-TLS connections.  DoT connections
	 * always supply an SNI hostname (the resolver address); S2S connections do
	 * not, so the sni_hostname guard correctly restricts ALPN to DoT only.
	 *
	 * S2S servers that receive an unexpected "dot" ALPN would silently
	 * continue (CONTINUE_ON_MISMATCH), but the advertisement is misleading
	 * and wastes bytes in the ClientHello, so suppress it.
	 */
	if (dir == OP_FD_TLS_DIRECTION_OUT && sni_hostname && *sni_hostname)
	{
		int alpn_rc = wolfSSL_UseALPN(SSL_P(F), "dot", 3,
		                              WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
		if (alpn_rc != WOLFSSL_SUCCESS)
			op_lib_log("%s: wolfSSL_UseALPN failed (rc=%d) — "
			           "ALPN \"dot\" will not be advertised",
			           __func__, alpn_rc);
	}

	/* For incoming TLS connections, register accepted ALPN protocols.
	 * wolfSSL's ALPN_find_match() selects a matching protocol when the client
	 * offers one; CONTINUE_ON_MISMATCH lets clients that send no ALPN (or an
	 * unrecognised protocol) connect normally — critical for legacy IRC clients.
	 *
	 * "irc" (RFC 9460 / IANA "irc") — advertised on plain IRC ports so
	 * IRCv3-aware clients and proxies can confirm they reached an IRC server.
	 * Only registered on non-WebSocket listeners; wsock connections carry HTTP
	 * upgrade traffic where "irc" is not appropriate.
	 *
	 * "http/1.1" — required on all incoming TLS connections because Chrome 125+
	 * aborts WSS handshakes with ERR_SSL_PROTOCOL_ERROR if no ALPN is
	 * negotiated, and WebSocket connections always go through ssl_ctx.
	 * Registering it on IRC ports too is harmless — IRC clients do not offer it
	 * and CONTINUE_ON_MISMATCH passes them through untouched. */
	if (dir == OP_FD_TLS_DIRECTION_IN)
	{
		if (!wsock)
			(void) wolfSSL_UseALPN(SSL_P(F), "irc", 3,
			                       WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
		(void) wolfSSL_UseALPN(SSL_P(F), "http/1.1", 8,
		                       WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
	}

	/* WebSocket listeners must not request a TLS client certificate.
	 * ssl_client_cert (and S2S certfp config) enables WOLFSSL_VERIFY_PEER on
	 * the shared ssl_ctx, which causes all incoming TLS sessions to include a
	 * CertificateRequest message.  Chrome 125+ aborts the handshake with
	 * ERR_SSL_CLIENT_AUTH_CERT_NEEDED when it receives CertificateRequest and
	 * has no client cert to offer.  Firefox sends an empty Certificate and
	 * continues, which is why Firefox worked while Chrome did not.
	 *
	 * The fix: for WebSocket connections (wss://) override the ctx-level
	 * verify mode per-session to WOLFSSL_VERIFY_NONE before the handshake
	 * starts.  This suppresses CertificateRequest for ws clients while
	 * leaving certfp intact on plain TLS IRC ports (port 6697) where opers
	 * and S2S links authenticate via TLS client certificates. */
	if (wsock && dir == OP_FD_TLS_DIRECTION_IN)
		wolfSSL_set_verify(SSL_P(F), WOLFSSL_VERIFY_NONE, NULL);

	return 0;
}

#if defined(HAVE_KERNEL_TLS) && !defined(HAVE_WOLFSSL_KTLS)
/*
 * do_ktls_setsockopt — inner kTLS setup shared by op_ssl_try_ktls() and
 * op_ssl_promote_ktls().
 *
 * Activates TCP_ULP "tls" on fd, then calls setsockopt(SOL_TLS, TLS_TX/RX)
 * with the supplied cipher parameters and sequence numbers.  Key material
 * structs are stack-allocated and explicitly zeroed on return.
 *
 *  1  — success; kTLS is active on fd.
 *  0  — TCP_ULP failed non-fatally (module not loaded, etc.).
 * -1  — fatal: TCP_ULP succeeded but a TLS_TX/RX setsockopt failed; the
 *        socket is in a partial-kTLS state and must be closed.
 */
static int
do_ktls_setsockopt(int fd, const char *caller, int ver,
                   uint16_t cipher_type,
                   size_t key_sz, size_t salt_sz, size_t iv_sz,
                   const unsigned char *cli_key, const unsigned char *cli_iv,
                   const unsigned char *srv_key, const unsigned char *srv_iv,
                   word64 tx_seq, word64 rx_seq)
{
	if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0)
	{
		op_lib_log("%s: setsockopt(TCP_ULP, \"tls\"): %s — "
		           "kTLS unavailable (is the kernel tls module loaded?)",
		           caller, strerror(errno));
		return 0;
	}

	/* Write a uint64 as 8 big-endian bytes. */
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

	if (cipher_type == TLS_CIPHER_AES_GCM_128)
	{
		struct tls12_crypto_info_aes_gcm_128 tx, rx;
		memset(&tx, 0, sizeof tx);
		memset(&rx, 0, sizeof rx);

		tx.info.version     = (uint16_t)ver;
		tx.info.cipher_type = TLS_CIPHER_AES_GCM_128;
		memcpy(tx.key, srv_key, key_sz);
		if (ver == TLS1_3_VERSION) {
			memcpy(tx.salt, srv_iv,            salt_sz);
			memcpy(tx.iv,   srv_iv + salt_sz,  iv_sz);
		} else {
			memcpy(tx.salt, srv_iv, salt_sz);
			WRITE_SEQ(tx.iv, tx_seq);
		}
		WRITE_SEQ(tx.rec_seq, tx_seq);

		rx.info.version     = (uint16_t)ver;
		rx.info.cipher_type = TLS_CIPHER_AES_GCM_128;
		memcpy(rx.key, cli_key, key_sz);
		if (ver == TLS1_3_VERSION) {
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

		tx.info.version     = (uint16_t)ver;
		tx.info.cipher_type = TLS_CIPHER_AES_GCM_256;
		memcpy(tx.key, srv_key, key_sz);
		if (ver == TLS1_3_VERSION) {
			memcpy(tx.salt, srv_iv,            salt_sz);
			memcpy(tx.iv,   srv_iv + salt_sz,  iv_sz);
		} else {
			memcpy(tx.salt, srv_iv, salt_sz);
			WRITE_SEQ(tx.iv, tx_seq);
		}
		WRITE_SEQ(tx.rec_seq, tx_seq);

		rx.info.version     = (uint16_t)ver;
		rx.info.cipher_type = TLS_CIPHER_AES_GCM_256;
		memcpy(rx.key, cli_key, key_sz);
		if (ver == TLS1_3_VERSION) {
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
#ifdef HAVE_KTLS_CHACHA20
	else /* TLS_CIPHER_CHACHA20_POLY1305 */
	{
		struct tls12_crypto_info_chacha20_poly1305 tx, rx;
		memset(&tx, 0, sizeof tx);
		memset(&rx, 0, sizeof rx);

		tx.info.version     = (uint16_t)ver;
		tx.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		memcpy(tx.key, srv_key, key_sz);
		memcpy(tx.iv,  srv_iv,  iv_sz);
		WRITE_SEQ(tx.rec_seq, tx_seq);

		rx.info.version     = (uint16_t)ver;
		rx.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		memcpy(rx.key, cli_key, key_sz);
		memcpy(rx.iv,  cli_iv,  iv_sz);
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
#endif /* HAVE_KTLS_CHACHA20 */

#undef WRITE_SEQ
	return result;
}

/* ── Cipher identification helper shared by both kTLS paths ──────────────── */

static bool
ktls_identify_cipher(WOLFSSL *ssl, uint16_t *out_cipher_type,
                     size_t *out_key_sz, size_t *out_salt_sz, size_t *out_iv_sz)
{
	const char *cipher = wolfSSL_get_cipher_name(ssl);
	if (!cipher)
		return false;

	if (strstr(cipher, "AES128-GCM") || strstr(cipher, "AES_128_GCM"))
	{
		*out_cipher_type = TLS_CIPHER_AES_GCM_128;
		*out_key_sz  = TLS_CIPHER_AES_GCM_128_KEY_SIZE;
		*out_salt_sz = TLS_CIPHER_AES_GCM_128_SALT_SIZE;
		*out_iv_sz   = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		return true;
	}
	if (strstr(cipher, "AES256-GCM") || strstr(cipher, "AES_256_GCM"))
	{
		*out_cipher_type = TLS_CIPHER_AES_GCM_256;
		*out_key_sz  = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
		*out_salt_sz = TLS_CIPHER_AES_GCM_256_SALT_SIZE;
		*out_iv_sz   = TLS_CIPHER_AES_GCM_256_IV_SIZE;
		return true;
	}
#ifdef HAVE_KTLS_CHACHA20
	if (strstr(cipher, "CHACHA20") && !strstr(cipher, "OLD"))
	{
		*out_cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		*out_key_sz  = TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE;
		*out_salt_sz = TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE;
		*out_iv_sz   = TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE;
		return true;
	}
#endif
	return false; /* CBC or unsupported cipher */
}

/*
 * op_ssl_try_ktls — attempt to promote a freshly accepted TLS 1.2 or 1.3
 * connection to Linux kernel TLS.
 *
 * Must be called immediately after wolfSSL_accept() succeeds, before any
 * application data has been exchanged.
 *
 * TLS 1.2 notes:
 *   - client_write_IV is 4 bytes (the implicit salt for AES-GCM).
 *   - The explicit IV sent in-record equals the sequence number; the kernel
 *     derives the nonce as salt || explicit_iv.
 *   - After the handshake: server TX seq = 1 (Finished was seq 0), client RX
 *     seq = 1 (client Finished was seq 0 under the same record-layer keys).
 *
 * TLS 1.3 notes:
 *   - client_write_IV is 12 bytes (the full per-connection AEAD IV).
 *   - There is no explicit IV; the kernel XORs the IV with the sequence
 *     number to form each record nonce: nonce = iv XOR (0...0 || seq).
 *   - For AES-GCM the kernel struct splits the 12-byte IV as:
 *       salt[4] = IV[0..3]   iv[8] = IV[4..11]
 *   - After the handshake: server TX seq reflects any NewSessionTicket
 *     records already sent (read via wolfSSL_GetSequenceNumber); client RX
 *     application-data seq = 0 (handshake traffic used separate keys).
 *
 * Supported cipher suites:
 *   TLS 1.2: ECDHE/DHE-{RSA,ECDSA}-AES128-GCM-*, AES256-GCM-*, CHACHA20-POLY1305
 *   TLS 1.3: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
 *            TLS_CHACHA20_POLY1305_SHA256
 *
 * Return value:
 *    1  kTLS activated; F->ktls is set; op_ssl_read/write use raw recv/send.
 *    0  kTLS not activated — unsupported version/cipher or kernel module not
 *       loaded; socket is still usable via wolfSSL (graceful fallback).
 *   -1  Fatal: TCP_ULP "tls" was enabled and at least one setsockopt for
 *       TLS_TX or TLS_RX then failed.  The socket is in an inconsistent
 *       partial-kTLS state and MUST NOT be used for further I/O; the caller
 *       must close the connection.
 */
static int
op_ssl_try_ktls(op_fde_t *const F)
{
	/* Skip kTLS for outgoing (client-role) connections — wolfSSL_GetSequenceNumber
	 * is unreliable for client connections, and kTLS offload is only beneficial
	 * for long-lived listening sockets (IRC clients, S2S).  Outgoing connections
	 * (DoT resolvers, S2S dial-outs) degrade gracefully via wolfSSL instead. */
	if (F->tls_outgoing)
		return 0;

	WOLFSSL *ssl = SSL_P(F);
	int      fd  = op_get_fd(F);
	int      ver = wolfSSL_version(ssl);

	if (ver != TLS1_2_VERSION && ver != TLS1_3_VERSION)
		return 0;

	uint16_t cipher_type;
	size_t   key_sz, salt_sz, iv_sz;
	if (!ktls_identify_cipher(ssl, &cipher_type, &key_sz, &salt_sz, &iv_sz))
		return 0;

	/* TX sequence number: read the live value so we handle NewSessionTicket
	 * records (TLS 1.3) and any unusual wolfSSL behaviour correctly.
	 * After a TLS 1.2 handshake wolfSSL resets keys.sequence_number_lo to 0
	 * for the application-data phase, so seq == 0 is normal here.
	 * After a TLS 1.3 handshake this is N >= 0 depending on how many
	 * NewSessionTicket records the server sent with application traffic keys.
	 *
	 * wolfSSL_GetSequenceNumber returns !(*seq) — it returns 1 when seq == 0
	 * and 0 when seq != 0.  Only a negative return (BAD_FUNC_ARG) is a real
	 * error; treat any non-negative return as success. */
	word64 tx_seq = 0;
	if (wolfSSL_GetSequenceNumber(ssl, &tx_seq) < 0)
	{
		op_lib_log("%s: wolfSSL_GetSequenceNumber failed", __func__);
		return 0;
	}

	/* RX sequence number: the next sequence number the kernel should expect
	 * for inbound application-data records.
	 *
	 * TLS 1.2: wolfSSL resets the SERVER TX counter to 0 for the app-data
	 *   phase, but the CLIENT's Finished was seq 0 under the same session
	 *   keys, so wolfSSL increments peer_sequence_number to 1 after receiving
	 *   it.  The first app-data record from the client therefore arrives as
	 *   seq 1.  Using 0 here causes kTLS to reject the first client record.
	 *
	 * TLS 1.3: client Finished was sent under the HANDSHAKE traffic keys,
	 *   not the APPLICATION traffic keys.  Application-data seq resets to 0
	 *   after the key change, so the first application-data record is seq 0. */
	const word64 rx_seq = (ver == TLS1_2_VERSION) ? 1 : 0;

	/* Fetch write keys and IVs from wolfSSL's retained arrays.
	 * TLS 1.2 AES-GCM: IV is 4 bytes (implicit salt only).
	 * TLS 1.3 AES-GCM: IV is 12 bytes (full per-connection AEAD IV).
	 * ChaCha20 (both): IV is 12 bytes. */
	const unsigned char *cli_key = wolfSSL_GetClientWriteKey(ssl);
	const unsigned char *cli_iv  = wolfSSL_GetClientWriteIV(ssl);
	const unsigned char *srv_key = wolfSSL_GetServerWriteKey(ssl);
	const unsigned char *srv_iv  = wolfSSL_GetServerWriteIV(ssl);

	if (!cli_key || !cli_iv || !srv_key || !srv_iv)
	{
		op_lib_log("%s: wolfSSL_GetXxxWriteKey/IV returned NULL "
		           "(was wolfSSL_KeepArrays called before the handshake?)",
		           __func__);
		return 0;
	}

	int result = do_ktls_setsockopt(fd, __func__, ver, cipher_type,
	                                key_sz, salt_sz, iv_sz,
	                                cli_key, cli_iv, srv_key, srv_iv,
	                                tx_seq, rx_seq);
	if (result < 0)
	{
		op_lib_log("%s: socket fd %d left in partial kTLS state; connection must close",
		           __func__, fd);
		return -1;
	}
	if (result == 1)
	{
		op_lib_log("kTLS: kernel TLS active on fd %d (%s %s)",
		           fd, wolfSSL_get_version(ssl), wolfSSL_get_cipher_name(ssl));
		F->ktls = true;
	}
	return result;
}
#endif /* HAVE_KERNEL_TLS && !HAVE_WOLFSSL_KTLS */

/*
 * op_ssl_promote_ktls — late kTLS promotion for established TLS connections.
 *
 * Unlike op_ssl_try_ktls() which must run immediately after the TLS handshake,
 * this function may be called on any established TLS connection at any time.
 * It reads the CURRENT TX and RX sequence numbers via
 * wolfSSL_GetSequenceNumber() and wolfSSL_GetPeerSequenceNumber() so the
 * kernel kTLS state picks up exactly where wolfSSL left off.
 *
 * Primary use case: the upgrade drain phase.  Before serialising a TLS 1.2
 * client for migration, the ircd calls op_ssl_promote_ktls().  For AES-GCM
 * or ChaCha20 cipher suites with the kernel tls module loaded, the connection
 * is promoted on the spot and migrates to the new binary via the transparent
 * kTLS FD-passing path — no graceful close required.
 *
 * TLS 1.2 with CBC ciphers (no AEAD) cannot use kTLS; those connections still
 * fall through to wolfSSL session export or graceful close as before.
 *
 * wolfSSL_GetClientWriteKey/IV reads from ssl->keys, which wolfSSL retains for
 * the lifetime of the session regardless of whether wolfSSL_FreeArrays() was
 * called after the handshake.
 *
 * Returns the same values as op_ssl_try_ktls(): 1 promoted, 0 not promoted,
 * -1 fatal partial-kTLS state.  No-op (0) when kTLS is not compiled in.
 */
int
op_ssl_promote_ktls(op_fde_t *const F)
{
#if defined(HAVE_KERNEL_TLS) && !defined(HAVE_WOLFSSL_KTLS)
	if (F == NULL || F->ssl == NULL || F->ktls || F->tls_outgoing)
		return 0;

	WOLFSSL *ssl = SSL_P(F);
	int      fd  = op_get_fd(F);
	int      ver = wolfSSL_version(ssl);

	if (ver != TLS1_2_VERSION && ver != TLS1_3_VERSION)
		return 0;

	uint16_t cipher_type;
	size_t   key_sz, salt_sz, iv_sz;
	if (!ktls_identify_cipher(ssl, &cipher_type, &key_sz, &salt_sz, &iv_sz))
		return 0;

	/* Read the LIVE TX and RX sequence numbers so the kernel picks up
	 * exactly where wolfSSL left off, regardless of how many records have
	 * been exchanged since the handshake. */
	word64 tx_seq = 0;
	if (wolfSSL_GetSequenceNumber(ssl, &tx_seq) < 0)
	{
		op_lib_log("%s: wolfSSL_GetSequenceNumber failed", __func__);
		return 0;
	}
	word64 rx_seq = 0;
	if (wolfSSL_GetPeerSequenceNumber(ssl, &rx_seq) < 0)
	{
		op_lib_log("%s: wolfSSL_GetPeerSequenceNumber failed", __func__);
		return 0;
	}

	const unsigned char *cli_key = wolfSSL_GetClientWriteKey(ssl);
	const unsigned char *cli_iv  = wolfSSL_GetClientWriteIV(ssl);
	const unsigned char *srv_key = wolfSSL_GetServerWriteKey(ssl);
	const unsigned char *srv_iv  = wolfSSL_GetServerWriteIV(ssl);

	if (!cli_key || !cli_iv || !srv_key || !srv_iv)
	{
		op_lib_log("%s: write key/IV NULL — keys unavailable for late kTLS promotion",
		           __func__);
		return 0;
	}

	int result = do_ktls_setsockopt(fd, __func__, ver, cipher_type,
	                                key_sz, salt_sz, iv_sz,
	                                cli_key, cli_iv, srv_key, srv_iv,
	                                tx_seq, rx_seq);
	if (result < 0)
	{
		op_lib_log("%s: fd %d left in partial kTLS state; connection must close",
		           __func__, fd);
		return -1;
	}
	if (result == 1)
	{
		op_lib_log("kTLS: late promotion on fd %d (%s %s tx_seq=%llu rx_seq=%llu)",
		           fd, wolfSSL_get_version(ssl), wolfSSL_get_cipher_name(ssl),
		           (unsigned long long)tx_seq, (unsigned long long)rx_seq);
		F->ktls = true;
	}
	return result;
#else
	(void)F;
	return 0;
#endif
}

/*
 * accept_teardown — common error-path teardown for a failed TLS accept.
 *
 * Cancels the handshake timeout, clears I/O readiness interest, invokes
 * the error callback, and frees acceptdata.  errno must be set by the
 * caller before this is called; F->ssl_errno should also be set when a
 * wolfSSL-level error code is available.
 *
 * Must only be called when F->accept is non-NULL.  After this returns
 * F->accept is NULL and the acceptdata has been freed.
 */
static void
accept_teardown(op_fde_t *const F)
{
	op_settimeout(F, 0, NULL, NULL);
	op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE, NULL, NULL);
	struct acceptdata *const ad = F->accept;
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

	int ret = wolfSSL_accept(SSL_P(F));
	int err = wolfSSL_get_error(SSL_P(F), ret);

	if (ret == 1)
	{
		F->handshake_count++;

#if defined(HAVE_KERNEL_TLS) && !defined(HAVE_WOLFSSL_KTLS)
		/*
		 * Attempt to promote the connection to kernel TLS immediately
		 * after the handshake, before any application data is exchanged.
		 * op_ssl_try_ktls sets F->ktls on success; op_ssl_read/write then
		 * bypass wolfSSL and call recv/send directly so the kernel handles
		 * all encryption/decryption.
		 */
		int ktls_rc = op_ssl_try_ktls(F);

		/*
		 * Release the handshake arrays retained by wolfSSL_KeepArrays().
		 * op_ssl_try_ktls() has either copied the key material into kernel
		 * setsockopt structs (kTLS success) or failed without using them.
		 * Either way the keys no longer need to live in userspace memory;
		 * wolfSSL_FreeArrays() zeroes and frees them while leaving the
		 * WOLFSSL session object intact for SNI / cipher-info queries.
		 */
		if (F->ssl != NULL)
			wolfSSL_FreeArrays(SSL_P(F));

		if (ktls_rc < 0)
		{
			/*
			 * TCP_ULP was activated but TLS_TX or TLS_RX setsockopt
			 * failed.  The socket is in a partial kTLS state and cannot
			 * be used for I/O; close the connection immediately.
			 */
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
	if (ret == -1 && err == WOLFSSL_ERROR_WANT_READ)
	{
		op_setselect(F, OP_SELECT_WRITE, NULL, NULL);
		op_setselect(F, OP_SELECT_READ, op_ssl_accept_common, NULL);
		return;
	}
	if (ret == -1 && err == WOLFSSL_ERROR_WANT_WRITE)
	{
		op_setselect(F, OP_SELECT_READ, NULL, NULL);
		op_setselect(F, OP_SELECT_WRITE, op_ssl_accept_common, NULL);
		return;
	}

	errno = EIO;
	F->ssl_errno = (uint64_t) err;
	accept_teardown(F);
}

/* Forward declaration — op_ssl_read_or_write is defined later in this file. */
static ssize_t op_ssl_read_or_write(int r_or_w, op_fde_t *F,
                                    void *rbuf, const void *wbuf, size_t count);

static void
op_ssl_connect_common(op_fde_t *const F, void *const data)
{
	slop_assert(F != NULL);
	slop_assert(F->ssl != NULL);

	int ret = wolfSSL_connect(SSL_P(F));
	int err = wolfSSL_get_error(SSL_P(F), ret);

	if (ret == 1)
	{
		{
			char          *alpn_proto     = NULL;
			unsigned short alpn_proto_len  = 0;
#ifdef HAVE_ALPN
			(void) wolfSSL_ALPN_GetProtocol(SSL_P(F),
			                                &alpn_proto, &alpn_proto_len);
#endif
			const char *tls_ver    = wolfSSL_get_version(SSL_P(F));
			const char *tls_cipher = wolfSSL_get_cipher(SSL_P(F));

			/* wolfSSL_ALPN_GetProtocol() returns NULL in TLS 1.3 even
			 * when ALPN was successfully negotiated (the extension is
			 * in EncryptedExtensions but wolfSSL doesn't expose it via
			 * this API).  Show "offered" if we advertised ALPN but the
			 * API can't confirm the echo, rather than misleading "none". */
			const char *alpn_display;
			int         alpn_display_len;
			if (alpn_proto_len) {
				alpn_display     = alpn_proto;
				alpn_display_len = (int)alpn_proto_len;
			} else if (F->tls_outgoing) {
				alpn_display     = "n/a";
				alpn_display_len = 3;
			} else {
				alpn_display     = "n/a";
				alpn_display_len = 3;
			}
			op_lib_log("TLS connect: negotiated %s (cipher: %s, ALPN: %.*s)",
			           tls_ver    ? tls_ver    : "unknown",
			           tls_cipher ? tls_cipher : "unknown",
			           alpn_display_len, alpn_display);
		}

		/*
		 * Post-handshake drain.
		 *
		 * In TLS 1.3 the server sends NewSessionTicket messages immediately
		 * after the Finished record.  wolfSSL's ProcessReply() processes one
		 * TLS record per wolfSSL_read() call and returns WOLFSSL_ERROR_WANT_READ
		 * after each internal record (NST, KeyUpdate, etc.) — even when more
		 * data is already buffered in the socket.  We therefore loop and use
		 * MSG_PEEK to determine whether more data is pending after each
		 * WANT_READ so that an NST and a close_notify arriving in the same TCP
		 * segment are both processed here rather than letting the close_notify
		 * surprise the first wolfSSL_write() call.
		 *
		 * Valid terminal states:
		 *   NEED_READ  — socket buffer empty after draining all records (normal)
		 *   NEED_WRITE — wolfSSL needs to flush a record it queued (e.g. a
		 *                TLS 1.3 KeyUpdate ack); safe to proceed.
		 * Everything else — including 0 (close_notify) and negative error
		 * codes — is a genuine failure that we propagate via the callback.
		 */
		{
			unsigned char drain_buf[4096];
			ssize_t       dn = OP_RW_SSL_NEED_READ;

			for (int drain_i = 0; drain_i < 32; drain_i++)
			{
				dn = op_ssl_read_or_write(0, F, drain_buf, NULL,
				                          sizeof drain_buf);
				if (dn > 0)
				{
					op_lib_log("TLS connect drain: unexpected app data (%zd bytes) "
					           "before query — discarding", dn);
					continue;
				}
				if (dn != OP_RW_SSL_NEED_READ)
					break; /* close_notify (0), NEED_WRITE, or error */

				/* NEED_READ: wolfSSL processed one internal record (e.g. NST).
				 * Peek at the socket — if more data is buffered, loop again
				 * to drain it; otherwise the socket is genuinely empty. */
				char peek_byte;
				ssize_t pr = recv(wolfSSL_get_fd(SSL_P(F)),
				                  &peek_byte, 1,
				                  MSG_PEEK | MSG_DONTWAIT);
				if (pr > 0)
					continue; /* more data pending, drain it */
				/* pr == 0: TCP peer closed (unusual, let wolfSSL detect it
				 * when we next write).  pr < 0: EAGAIN = socket empty. */
				break;
			}

			if (dn != OP_RW_SSL_NEED_READ && dn != OP_RW_SSL_NEED_WRITE)
			{
				/* Error or close_notify during drain — treat as failure. */
				op_settimeout(F, 0, NULL, NULL);
				op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE,
				             NULL, NULL);
				op_ssl_connect_realcb(F, OP_ERROR_SSL, data);
				return;
			}
		}

		F->handshake_count++;

		op_settimeout(F, 0, NULL, NULL);
		op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE, NULL, NULL);

		op_ssl_connect_realcb(F, OP_OK, data);

		return;
	}
	if (ret == -1 && err == WOLFSSL_ERROR_WANT_READ)
	{
		op_setselect(F, OP_SELECT_WRITE, NULL, NULL);
		op_setselect(F, OP_SELECT_READ, op_ssl_connect_common, data);
		return;
	}
	if (ret == -1 && err == WOLFSSL_ERROR_WANT_WRITE)
	{
		op_setselect(F, OP_SELECT_READ, NULL, NULL);
		op_setselect(F, OP_SELECT_WRITE, op_ssl_connect_common, data);
		return;
	}

	errno = EIO;
	F->ssl_errno = (uint64_t) err;
	op_settimeout(F, 0, NULL, NULL);
	op_setselect(F, OP_SELECT_READ | OP_SELECT_WRITE, NULL, NULL);
	op_ssl_connect_realcb(F, OP_ERROR_SSL, data);
}

static const char *
op_ssl_strerror(const uint64_t err)
{
	/* Cast back to signed long — wolfSSL stores error codes as negative ints. */
	const char *reason = wolfSSL_ERR_reason_error_string((unsigned long)err);
	if(reason && *reason)
		return reason;

	/* Fallback: format the raw code.  Thread-local so concurrent calls on
	 * different connections do not clobber each other's result. */
	static _Thread_local char errbuf[64];
	(void) snprintf(errbuf, sizeof errbuf, "wolfSSL error %" PRIu64, err);
	return errbuf;
}

static int
verify_accept_all_cb(const int preverify_ok __attribute__((unused)), WOLFSSL_X509_STORE_CTX *const x509_ctx __attribute__((unused)))
{
	return 1;
}

static ssize_t
op_ssl_read_or_write(const int r_or_w, op_fde_t *const F, void *const rbuf, const void *const wbuf, const size_t count)
{
	ssize_t ret;
	uint64_t err = 0; /* assigned in default switch branch; init avoids compiler warning */
	/* WolfSSL takes int for count; clamp to INT_MAX so large size_t values
	 * don't wrap.  In practice callers never pass more than BUFSIZE bytes. */
	int icount = (count > (size_t)INT_MAX) ? INT_MAX : (int)count;

	if (r_or_w == 0)
		ret = (ssize_t) wolfSSL_read(SSL_P(F), rbuf, icount);
	else
		ret = (ssize_t) wolfSSL_write(SSL_P(F), wbuf, icount);

	/*
	 * Snapshot errno immediately after the I/O call, before any other
	 * library function can clobber it.  wolfSSL_get_error() performs
	 * internal bookkeeping that may call system functions which alter
	 * errno, so we need the value that was set by the wolfSSL_read/write
	 * call itself.  We also capture errno again after wolfSSL_get_error
	 * (post_errno) because some wolfSSL builds only populate errno during
	 * wolfSSL_get_error() rather than during the I/O call itself.
	 */
	int saved_errno = errno;

	if (ret < 0)
	{
		int ssl_err = wolfSSL_get_error(SSL_P(F), (int)ret);
		int post_errno = errno;   /* errno after wolfSSL_get_error */

		/* If either snapshot indicates would-block, treat as non-fatal.
		 * wolfSSL should have returned WANT_READ/WANT_WRITE for this case,
		 * but some builds return WOLFSSL_ERROR_SYSCALL or SSL_ERROR_NONE.
		 *
		 * IMPORTANT: the correct return code depends on the I/O direction.
		 * A write stall must return OP_RW_SSL_NEED_WRITE so the caller arms
		 * OP_SELECT_WRITE; returning NEED_READ instead causes the event loop
		 * to wait in the wrong direction and the connection appears frozen. */
		int is_eagain = (saved_errno == EAGAIN  || saved_errno == EWOULDBLOCK
		              || post_errno  == EAGAIN  || post_errno  == EWOULDBLOCK);
		ssize_t need_rw = (r_or_w == 0) ? OP_RW_SSL_NEED_READ
		                                 : OP_RW_SSL_NEED_WRITE;

		switch (ssl_err)
		{
		case WOLFSSL_ERROR_WANT_READ:
			errno = EAGAIN;
			return OP_RW_SSL_NEED_READ;
		case WOLFSSL_ERROR_WANT_WRITE:
			errno = EAGAIN;
			return OP_RW_SSL_NEED_WRITE;
		case WOLFSSL_ERROR_ZERO_RETURN:
			/* Peer sent close_notify — clean TLS shutdown.  Errno is
			 * meaningless here; clear it so callers don't confuse a
			 * stale EAGAIN with an I/O error. */
			errno = 0;
			return 0;
		case WOLFSSL_ERROR_SYSCALL:
			F->ssl_errno = 0;
			/* Some wolfSSL builds return SYSCALL with EAGAIN/EWOULDBLOCK
			 * when the underlying socket would block (should have returned
			 * WANT_READ/WRITE instead).  Use the direction-aware code. */
			if (is_eagain) {
				errno = EAGAIN;
				return need_rw;
			}
			errno = saved_errno;
			return OP_RW_IO_ERROR;
		default:
			err = (uint64_t)(unsigned int)ssl_err;
			break;
		}

		F->ssl_errno = err;
		if (err > 0)
		{
			errno = EIO;	/* not great but... */
			return OP_RW_SSL_ERROR;
		}
		/* wolfSSL_get_error() returned 0 (SSL_ERROR_NONE) for a failed
		 * I/O call — this is a wolfSSL quirk where the error code is not
		 * populated through the normal WOLFSSL_ERROR_SYSCALL path.
		 * Use the direction-aware would-block code. */
		if (is_eagain) {
			errno = EAGAIN;
			return need_rw;
		}
		errno = saved_errno;
		return OP_RW_IO_ERROR;
	}
	return ret;
}

static int
make_certfp(WOLFSSL_X509 *const cert, uint8_t certfp[const OP_SSL_CERTFP_LEN], const int method)
{
	const unsigned char *hash_data = NULL;
	word32 hash_data_len = 0;
	unsigned char *spki_buf = NULL;
	int ret = 0;

	/* Get the DER buffer to hash: full cert DER or SubjectPublicKeyInfo DER. */
	switch (method)
	{
	case OP_SSL_CERTFP_METH_CERT_SHA1:
	case OP_SSL_CERTFP_METH_CERT_SHA256:
	case OP_SSL_CERTFP_METH_CERT_SHA512:
#if defined(WOLFSSL_SHA3)
	case OP_SSL_CERTFP_METH_CERT_SHA3_256:
	case OP_SSL_CERTFP_METH_CERT_SHA3_512:
#endif
	{
		int der_len = 0;
		const unsigned char *der = wolfSSL_X509_get_der(cert, &der_len);
		if (der == NULL || der_len <= 0)
		{
			op_lib_log("%s: wolfSSL_X509_get_der: failed", __func__);
			return 0;
		}
		hash_data = der;
		hash_data_len = (word32)der_len; /* der_len > 0 verified above */
		break;
	}
	case OP_SSL_CERTFP_METH_SPKI_SHA256:
	case OP_SSL_CERTFP_METH_SPKI_SHA512:
#if defined(WOLFSSL_SHA3)
	case OP_SSL_CERTFP_METH_SPKI_SHA3_256:
	case OP_SSL_CERTFP_METH_SPKI_SHA3_512:
#endif
	{
		/* Extract the SubjectPublicKeyInfo DER using wolfCrypt's native
		 * decoded-cert API. */
		int cert_der_len = 0;
		const unsigned char *cert_der = wolfSSL_X509_get_der(cert, &cert_der_len);
		if (cert_der == NULL || cert_der_len <= 0)
		{
			op_lib_log("%s: wolfSSL_X509_get_der: failed", __func__);
			return 0;
		}
		DecodedCert dc;
		wc_InitDecodedCert(&dc, (const byte *)cert_der, (word32)cert_der_len, NULL);
		if (wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) != 0)
		{
			op_lib_log("%s: wc_ParseCert: failed", __func__);
			wc_FreeDecodedCert(&dc);
			return 0;
		}
		/* 2048 bytes is generous: RSA-4096 SPKI ~550 B, EC ~100 B. */
		spki_buf = op_malloc(2048);
		if (spki_buf == NULL)
		{
			wc_FreeDecodedCert(&dc);
			return 0;
		}
		word32 spki_len = 2048;
		int wc_ret = wc_GetPubKeyDerFromCert(&dc, spki_buf, &spki_len);
		wc_FreeDecodedCert(&dc);
		if (wc_ret != 0)
		{
			op_lib_log("%s: wc_GetPubKeyDerFromCert: failed (%d)", __func__, wc_ret);
			op_free(spki_buf);
			return 0;
		}
		hash_data = spki_buf;
		hash_data_len = spki_len;
		break;
	}
	default:
		return 0;
	}

	/* Hash the DER buffer with the appropriate algorithm. */
	switch (method)
	{
	case OP_SSL_CERTFP_METH_CERT_SHA1:
		ret = (wc_ShaHash(hash_data, hash_data_len, certfp) == 0) ? OP_SSL_CERTFP_LEN_SHA1 : 0;
		break;
	case OP_SSL_CERTFP_METH_CERT_SHA256:
	case OP_SSL_CERTFP_METH_SPKI_SHA256:
		ret = (wc_Sha256Hash(hash_data, hash_data_len, certfp) == 0) ? OP_SSL_CERTFP_LEN_SHA256 : 0;
		break;
	case OP_SSL_CERTFP_METH_CERT_SHA512:
	case OP_SSL_CERTFP_METH_SPKI_SHA512:
		ret = (wc_Sha512Hash(hash_data, hash_data_len, certfp) == 0) ? OP_SSL_CERTFP_LEN_SHA512 : 0;
		break;
#if defined(WOLFSSL_SHA3)
	case OP_SSL_CERTFP_METH_CERT_SHA3_256:
	case OP_SSL_CERTFP_METH_SPKI_SHA3_256:
		ret = (wc_Sha3_256Hash(hash_data, hash_data_len, certfp) == 0) ? OP_SSL_CERTFP_LEN_SHA3_256 : 0;
		break;
	case OP_SSL_CERTFP_METH_CERT_SHA3_512:
	case OP_SSL_CERTFP_METH_SPKI_SHA3_512:
		ret = (wc_Sha3_512Hash(hash_data, hash_data_len, certfp) == 0) ? OP_SSL_CERTFP_LEN_SHA3_512 : 0;
		break;
#endif
	}

	op_free(spki_buf);
	return ret;
}



/*
 * External wolfSSL-specific code
 */

void
op_ssl_shutdown(op_fde_t *const F)
{
	if (F == NULL || F->ssl == NULL)
		return;

	/*
	 * Send a TLS close_notify alert.  On a non-blocking socket the first
	 * call typically returns 0 (alert sent, waiting for peer's reply) or
	 * -1/WANT_WRITE if the send buffer is full.  We do not wait for the
	 * peer's close_notify — the IRC server tears down the connection
	 * immediately after sending ours, which is permitted by RFC 8446 §6.1
	 * ("The initiator of the close need not wait for the responding
	 * close_notify alert before closing the read side of the connection.").
	 *
	 * The former 4-iteration synchronous retry loop spun without yielding
	 * to epoll and always produced a one-way (truncated) shutdown anyway.
	 * A single non-blocking attempt is strictly equivalent and cheaper.
	 *
	 * For kTLS connections wolfSSL's internal record-sequence counter is
	 * frozen at the post-handshake value (all app-data records were sent
	 * via the kernel, bypassing wolfSSL).  Calling wolfSSL_shutdown would
	 * emit a close_notify with a stale/wrong sequence number, which the
	 * peer would reject as a replay.  Skip it; the IRC protocol does not
	 * require close_notify and closing the TCP socket is sufficient.
	 */
	if (!F->ktls)
		wolfSSL_shutdown(SSL_P(F));

	/*
	 * Release the per-session CTX reference taken in op_ssl_init_fd (or
	 * transferred in sni_servername_cb).  This allows op_setup_ssl_server
	 * to safely replace the global ssl_ctx on REHASH: the old CTX is freed
	 * only after the last session that uses it closes.
	 */
	WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(SSL_P(F));
	wolfSSL_free(SSL_P(F));
	wolfSSL_CTX_free(ctx);
	F->ssl  = NULL;
	F->ktls = false;
}

int
op_init_ssl(void)
{
	if (wolfSSL_library_init() != WOLFSSL_SUCCESS)
	{
		op_lib_log("%s: wolfSSL_library_init failed", __func__);
		return 0;
	}

	op_lib_log("%s: wolfSSL backend initialised", __func__);
	return 1;
}

/*
 * op_ssl_is_ktls — returns true if this TLS connection has been offloaded to
 * Linux kernel TLS (kTLS).  Two paths activate kTLS:
 *
 *   HAVE_WOLFSSL_KTLS  wolfSSL was built with native kTLS support; it calls
 *                      setsockopt(SOL_TLS) internally and manages I/O bypass.
 *                      Queried via wolfSSL_is_ktls_tx/rx_active().
 *
 *   HAVE_KERNEL_TLS    ophion extracted keys with wolfSSL_GetXxxWriteKey/IV
 *                      and called setsockopt(SOL_TLS) itself.  F->ktls is set
 *                      by op_ssl_try_ktls(); op_ssl_read/write use raw
 *                      recv()/send() so the kernel handles all crypto.
 *
 * When true, the socket FD can be transferred to another process via
 * SCM_RIGHTS and the new process can use plain recv()/send() — the kernel
 * decrypts/encrypts TLS records transparently.  Both TLS 1.2 and TLS 1.3
 * connections can be offloaded; see op_ssl_try_ktls() for per-version details.
 *
 * Returns false when neither kTLS path is available or the cipher suite is
 * unsupported (e.g. CBC mode).
 */
bool
op_ssl_is_ktls(op_fde_t *const F)
{
	if (F == NULL)
		return false;

#ifdef HAVE_WOLFSSL_KTLS
	/* wolfSSL was built with native kTLS support; it calls setsockopt and
	 * manages I/O internally.  Query its active-state flags.
	 *
	 * For migrated kTLS clients (FD adopted via SCM_RIGHTS in a new binary)
	 * the wolfSSL context does not exist — op_fde_mark_ktls() set F->ktls
	 * instead.  Fall back to that flag when F->ssl is NULL so that
	 * session_migrate correctly re-migrates such clients on the next upgrade
	 * rather than treating them as non-kTLS SSL and disconnecting them. */
	if (F->ssl == NULL)
		return F->ktls;
	return wolfSSL_is_ktls_tx_active(SSL_P(F)) &&
	       wolfSSL_is_ktls_rx_active(SSL_P(F));

#elif defined(HAVE_KERNEL_TLS)
	/* Manual kTLS: op_ssl_try_ktls set this flag after successfully calling
	 * setsockopt(SOL_TLS).  op_ssl_read/write use raw recv/send. */
	return F->ktls;

#else
	(void)F;
	return false;
#endif
}

/*
 * op_fde_mark_ktls — mark an adopted FD as a kernel-TLS socket.
 *
 * After a kTLS client FD is transferred via SCM_RIGHTS and adopted in the
 * new binary, the kernel-TLS state is already active on the socket but
 * F->ktls defaults to false (op_open sets it up as a plain OP_FD_SOCKET).
 * Without this call op_ssl_read/write would use wolfSSL instead of the raw
 * recv()/send() path, and a subsequent upgrade would treat the client as
 * non-kTLS SSL and disconnect it rather than re-migrating it.
 */
void
op_fde_mark_ktls(op_fde_t *const F)
{
	if (F == NULL)
		return;
#if defined(HAVE_KERNEL_TLS) || defined(HAVE_WOLFSSL_KTLS)
	F->ktls = true;
#else
	(void)F;
#endif
}

/*
 * op_ssl_export — export the full wolfSSL session state into buf.
 *
 * Calls wolfSSL_tls_export() to serialise the active TLS session (keys, IVs,
 * sequence numbers, cipher suite).  The resulting blob is opaque and must be
 * imported by the same wolfSSL version via op_ssl_adopt_exported().
 *
 * Available only when HAVE_WOLFSSL_SESSION_EXPORT is defined (wolfSSL built
 * with --enable-session-export / WOLFSSL_SESSION_EXPORT).
 *
 * Returns the number of bytes written (> 0) on success, -1 on failure.
 */
int
op_ssl_export(op_fde_t *const F, uint8_t *const buf, const size_t buflen)
{
#ifdef HAVE_WOLFSSL_SESSION_EXPORT
	if (F == NULL || F->ssl == NULL || buf == NULL || buflen == 0)
		return -1;

	/* wolfSSL_tls_export returns the number of bytes written (> 0) on
	 * success, or a negative error code on failure.  It does NOT return
	 * WOLFSSL_SUCCESS (1). */
	unsigned int sz = (unsigned int)buflen;
	int ret = wolfSSL_tls_export(SSL_P(F), buf, &sz);
	if (ret <= 0)
	{
		op_lib_log("%s: wolfSSL_tls_export failed (ret=%d)", __func__, ret);
		return -1;
	}
	return ret;
#else
	(void)F; (void)buf; (void)buflen;
	return -1;
#endif
}

/*
 * op_ssl_adopt_exported — reconstruct a wolfSSL session from an export blob.
 *
 * Creates a new WOLFSSL object from the global ssl_ctx, imports the session
 * state from buf, and attaches it to F so that subsequent op_ssl_read() /
 * op_ssl_write() calls continue the TLS stream.
 *
 * The CTX reference-counting convention mirrors op_ssl_init_fd: one explicit
 * wolfSSL_CTX_up_ref() is taken here; the matching wolfSSL_CTX_free() is in
 * op_ssl_shutdown().
 *
 * Returns 0 on success, -1 on failure.
 */
int
op_ssl_adopt_exported(op_fde_t *const F, const uint8_t *const buf, const size_t len)
{
#ifdef HAVE_WOLFSSL_SESSION_EXPORT
	if (F == NULL || buf == NULL || len == 0)
		return -1;
	if (ssl_ctx == NULL)
	{
		op_lib_log("%s: ssl_ctx not initialised", __func__);
		return -1;
	}

	/* Take an explicit per-session reference on the CTX.  wolfSSL does not
	 * reference-count CTX internally; the matching release is in
	 * op_ssl_shutdown() via wolfSSL_CTX_free(). */
	if (wolfSSL_CTX_up_ref(ssl_ctx) != 1)
	{
		op_lib_log("%s: wolfSSL_CTX_up_ref failed", __func__);
		return -1;
	}

	WOLFSSL *ssl = wolfSSL_new(ssl_ctx);
	if (ssl == NULL)
	{
		op_lib_log("%s: wolfSSL_new failed", __func__);
		wolfSSL_CTX_free(ssl_ctx);
		return -1;
	}

	/* wolfSSL_tls_import returns the number of bytes consumed (> 0) on
	 * success, or a negative error code on failure. */
	int ret = wolfSSL_tls_import(ssl, buf, (unsigned int)len);
	if (ret <= 0)
	{
		op_lib_log("%s: wolfSSL_tls_import failed (ret=%d)", __func__, ret);
		wolfSSL_free(ssl);
		wolfSSL_CTX_free(ssl_ctx);
		return -1;
	}

	wolfSSL_set_fd(ssl, op_get_fd(F));
	wolfSSL_set_using_nonblock(ssl, 1);

	F->ssl   = ssl;
	F->type |= OP_FD_SSL;
	return 0;
#else
	(void)F; (void)buf; (void)len;
	return -1;
#endif
}

/*
 * op_ssl_is_outgoing_connection — return true if F's TLS session was
 * established as the connecting (client) side via OP_FD_TLS_DIRECTION_OUT.
 * Used by the session-migration code to select the correct CTX when
 * reconstructing the session in the new binary.
 */
bool
op_ssl_is_outgoing_connection(const op_fde_t *const F)
{
	return F != NULL && F->tls_outgoing;
}

/*
 * op_ssl_adopt_exported_outgoing — like op_ssl_adopt_exported but uses
 * ssl_client_ctx instead of ssl_ctx.  Called when adopting an outgoing
 * (connecting) S2S TLS link where the original WOLFSSL was created with the
 * client-side CTX (wolfSSLv23_client_method).
 */
int
op_ssl_adopt_exported_outgoing(op_fde_t *const F, const uint8_t *const buf,
                                const size_t len)
{
#ifdef HAVE_WOLFSSL_SESSION_EXPORT
	if (F == NULL || buf == NULL || len == 0)
		return -1;
	/* Lazily create the client CTX if it was never needed before this
	 * adoption (e.g. new binary with no outgoing connections yet). */
	if (ssl_client_ctx == NULL)
		ssl_client_ctx = build_client_ssl_ctx();
	if (ssl_client_ctx == NULL)
	{
		op_lib_log("%s: could not create client TLS context", __func__);
		return -1;
	}

	if (wolfSSL_CTX_up_ref(ssl_client_ctx) != 1)
	{
		op_lib_log("%s: wolfSSL_CTX_up_ref failed", __func__);
		return -1;
	}

	WOLFSSL *ssl = wolfSSL_new(ssl_client_ctx);
	if (ssl == NULL)
	{
		op_lib_log("%s: wolfSSL_new failed", __func__);
		wolfSSL_CTX_free(ssl_client_ctx);
		return -1;
	}

	/* wolfSSL_tls_import returns the number of bytes consumed (> 0) on
	 * success, or a negative error code on failure. */
	int ret = wolfSSL_tls_import(ssl, buf, (unsigned int)len);
	if (ret <= 0)
	{
		op_lib_log("%s: wolfSSL_tls_import failed (ret=%d)", __func__, ret);
		wolfSSL_free(ssl);
		wolfSSL_CTX_free(ssl_client_ctx);
		return -1;
	}

	wolfSSL_set_fd(ssl, op_get_fd(F));
	wolfSSL_set_using_nonblock(ssl, 1);

	F->ssl   = ssl;
	F->type |= OP_FD_SSL;
	return 0;
#else
	(void)F; (void)buf; (void)len;
	return -1;
#endif
}

/*
 * op_ssl_export_keying_material — RFC 5705 / RFC 8446 §7.5 TLS exporter.
 *
 * Derives outlen bytes of keying material from the TLS session on F and
 * writes them to out.  label is the ASCII exporter label; context /
 * context_len are the optional per-association context (pass NULL / 0 for
 * the no-context case, which sets use_context=0 per RFC 5705 §4).
 *
 * Primary use: SASL tls-exporter channel binding (RFC 9266).  The label
 * "EXPORTER-Channel-Binding" with no context yields a 32-byte binding
 * value that the client encodes in its AUTHENTICATE payload.
 *
 * Returns 1 on success, 0 on failure.
 */
int
op_ssl_export_keying_material(op_fde_t *const F,
                              uint8_t *const out, const size_t outlen,
                              const char *const label,
                              const uint8_t *const context, const size_t context_len)
{
#if defined(HAVE_KEYING_MATERIAL)
	if (F == NULL || F->ssl == NULL || out == NULL || label == NULL || outlen == 0)
		return 0;

	int rc = wolfSSL_export_keying_material(SSL_P(F),
	                                        out, outlen,
	                                        label, strlen(label),
	                                        context, context_len,
	                                        context != NULL ? 1 : 0);
	return (rc == WOLFSSL_SUCCESS) ? 1 : 0;
#else
	(void)F; (void)out; (void)outlen; (void)label; (void)context; (void)context_len;
	return 0;
#endif
}

/* Build and return a new WOLFSSL_CTX loaded with certfile/keyfile/dhfile/cipherlist.
 * Returns NULL on failure.  Common implementation for both the default context
 * and per-hostname SNI contexts.
 *
 * ca_cert         — path to a PEM CA bundle to load for verifying client
 *                   certificates.  NULL or empty string: skip CA loading and
 *                   use wolfSSL's verify-accept-all callback instead.
 * min_tls_version — minimum TLS protocol version string.  Accepted values:
 *                   NULL / "TLSv1.2" → TLS 1.2 (default)
 *                   "TLSv1.3"        → TLS 1.3 (reject TLS 1.2 connections)
 */
static WOLFSSL_CTX *
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

	if (cipherlist == NULL)
		cipherlist = op_default_ciphers;

	WOLFSSL_CTX *const ctx = wolfSSL_CTX_new(wolfSSLv23_method());

	if (ctx == NULL)
	{
		op_lib_log("%s: wolfSSL_CTX_new: failed", __func__);
		return NULL;
	}

	if (wolfSSL_CTX_use_certificate_chain_file(ctx, certfile) != 1)
	{
		int wssl_err = (int)wolfSSL_ERR_get_error();
		const char *wssl_str = wolfSSL_ERR_reason_error_string((unsigned long)wssl_err);
		op_lib_log("%s: wolfSSL_CTX_use_certificate_chain_file ('%s') failed: "
		           "TLS error: %s; OS error: %s",
		           __func__, certfile,
		           (wssl_str && *wssl_str) ? wssl_str : "(none)",
		           strerror(errno));
		wolfSSL_CTX_free(ctx);
		return NULL;
	}
	op_lib_log("%s: loaded certificate chain '%s'", __func__, certfile);

	if (wolfSSL_CTX_use_PrivateKey_file(ctx, keyfile, WOLFSSL_FILETYPE_PEM) != 1)
	{
		int wssl_err = (int)wolfSSL_ERR_get_error();
		const char *wssl_str = wolfSSL_ERR_reason_error_string((unsigned long)wssl_err);
		op_lib_log("%s: wolfSSL_CTX_use_PrivateKey_file ('%s') failed: "
		           "TLS error: %s; OS error: %s",
		           __func__, keyfile,
		           (wssl_str && *wssl_str) ? wssl_str : "(none)",
		           strerror(errno));
		wolfSSL_CTX_free(ctx);
		return NULL;
	}
	op_lib_log("%s: loaded private key '%s'", __func__, keyfile);

	if (wolfSSL_CTX_check_private_key(ctx) != 1)
	{
		op_lib_log("%s: wolfSSL_CTX_check_private_key: certificate/key mismatch "
		           "(cert='%s', key='%s')", __func__, certfile, keyfile);
		wolfSSL_CTX_free(ctx);
		return NULL;
	}

	if (dhfile == NULL)
	{
		op_lib_log("%s: no DH parameters file specified", __func__);
	}
	else if(access(dhfile, R_OK) != 0)
	{
		op_lib_log("%s: DH parameters file not readable: '%s': %s",
		           __func__, dhfile, strerror(errno));
	}
	else if(wolfSSL_CTX_SetTmpDH_file(ctx, dhfile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
	{
		op_lib_log("%s: wolfSSL_CTX_SetTmpDH_file ('%s'): failed — "
		           "run 'python3 setup.py' to regenerate dhparams.pem",
		           __func__, dhfile);
	}

	if (wolfSSL_CTX_set_cipher_list(ctx, cipherlist) != 1)
	{
		op_lib_log("%s: wolfSSL_CTX_set_cipher_list failed for cipher list: '%s'",
		           __func__, cipherlist);
		wolfSSL_CTX_free(ctx);
		return NULL;
	}

	wolfSSL_CTX_set_session_cache_mode(ctx, WOLFSSL_SESS_CACHE_OFF);

	/* Load CA certificate bundle for client-certificate verification.
	 * When ssl_ca_cert is configured, client certs are validated against this
	 * CA rather than being accepted unconditionally.  Without a CA bundle the
	 * verify callback accepts any certificate (certfp-based auth still works
	 * because the fingerprint is checked at the IRC layer). */
	if (ca_cert && *ca_cert)
	{
		if (wolfSSL_CTX_load_verify_locations(ctx, ca_cert, NULL) != WOLFSSL_SUCCESS)
			op_lib_log("%s: wolfSSL_CTX_load_verify_locations('%s'): failed — "
			           "client certificate CA verification will not work",
			           __func__, ca_cert);
	}

	if (verify)
		wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_CLIENT_ONCE,
		                       (ca_cert && *ca_cert) ? NULL : verify_accept_all_cb);

	#ifdef WOLFSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	(void) wolfSSL_CTX_clear_options(ctx, WOLFSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
	#endif

	/* Disable SSLv2/SSLv3 defensively — wolfSSL does not implement them but
	 * setting these options makes the restriction explicit and forwards-safe. */
	#ifdef WOLFSSL_OP_NO_SSLv2
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_SSLv2);
	#endif
	#ifdef WOLFSSL_OP_NO_SSLv3
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_SSLv3);
	#endif

	#ifdef WOLFSSL_OP_NO_TLSv1
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1);
	#endif

	#ifdef WOLFSSL_OP_NO_TICKET
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TICKET);
	#endif

	#ifdef WOLFSSL_OP_CIPHER_SERVER_PREFERENCE
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_CIPHER_SERVER_PREFERENCE);
	#endif

	#ifdef WOLFSSL_OP_SINGLE_DH_USE
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_SINGLE_DH_USE);
	#endif

	#ifdef WOLFSSL_OP_SINGLE_ECDH_USE
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_SINGLE_ECDH_USE);
	#endif

	/* Disable TLS 1.1 — floor is TLS 1.2. */
	#ifdef WOLFSSL_OP_NO_TLSv1_1
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_1);
	#endif

	/* Disable TLS renegotiation — clients must reconnect instead. */
	#ifdef WOLFSSL_OP_NO_RENEGOTIATION
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_RENEGOTIATION);
	#endif

	/* Disable TLS compression (CRIME attack mitigation). */
	#ifdef WOLFSSL_OP_NO_COMPRESSION
	(void) wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_COMPRESSION);
	#endif

	/* Set minimum TLS protocol version.
	 * Default is TLS 1.2; operator can require TLS 1.3 via ssl_minimum_tls_version.
	 * wolfSSL_CTX_SetMinVersion is the native API (always available);
	 * wolfSSL_CTX_set_min_proto_version is the OpenSSL-compat alias. */
	{
		int wssl_min = WOLFSSL_TLSV1_2;
#ifdef OPENSSL_EXTRA
		int ossl_min = TLS1_2_VERSION;
#endif
		if (min_tls_version != NULL && strcasecmp(min_tls_version, "TLSv1.3") == 0)
		{
			wssl_min = WOLFSSL_TLSV1_3;
#ifdef OPENSSL_EXTRA
			ossl_min = TLS1_3_VERSION;
#endif
		}
		wolfSSL_CTX_SetMinVersion(ctx, wssl_min);
#ifdef OPENSSL_EXTRA
		(void) wolfSSL_CTX_set_min_proto_version(ctx, ossl_min);
#endif
	}

	/* wolfSSL_CTX_set1_curves_list requires OPENSSL_EXTRA + ECC/Curve25519/448.
	 * Skip when unavailable; wolfSSL's built-in defaults include all modern
	 * curves (X25519, P-256, P-384) so no TLS compatibility is lost. */
#if (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))
	(void) wolfSSL_CTX_set1_curves_list(ctx, op_default_curves);
#endif

	/* Advertise RFC 7919 FFDHE groups for TLS 1.3 DHE key exchange.
	 * ECDHE (X25519, P-256) is preferred; FFDHE adds DHE fallback for
	 * clients that do not support ECDHE but do support FFDHE. */
#if defined(HAVE_FFDHE_2048) && defined(WOLFSSL_FFDHE_2048)
	(void) wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_FFDHE_2048);
#endif
#if defined(HAVE_FFDHE_3072) && defined(WOLFSSL_FFDHE_3072)
	(void) wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_FFDHE_3072);
#endif
#if defined(HAVE_FFDHE_4096) && defined(WOLFSSL_FFDHE_4096)
	(void) wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_FFDHE_4096);
#endif

	/* ML-KEM hybrid post-quantum key exchange.
	 * Each group pairs a classical ECDH key with ML-KEM (formerly Kyber)
	 * for forward-secrecy against future quantum adversaries.  Clients that
	 * support a hybrid group (Chrome 124+, Rustls 0.23+, OpenSSL 3.2+ with
	 * oqsprovider) perform a hybrid handshake; classic-only clients fall back
	 * to the classical ECDH groups already in the supported-curves list.
	 * Guard each constant individually — availability depends on the wolfSSL
	 * build (--enable-kyber / WOLFSSL_HAVE_MLKEM). */
#if defined(WOLFSSL_X25519MLKEM768)
	(void) wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_X25519MLKEM768);
#endif
#if defined(WOLFSSL_SECP256R1MLKEM768)
	(void) wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_SECP256R1MLKEM768);
#endif
#if defined(WOLFSSL_SECP384R1MLKEM1024)
	(void) wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_SECP384R1MLKEM1024);
#endif

	return ctx;
}

int
op_setup_ssl_server(const char *const certfile, const char *keyfile,
                    const char *const dhfile, const char *cipherlist,
                    bool verify, const char *ca_cert,
                    const char *min_tls_version)
{
	WOLFSSL_CTX *const ctx = build_ssl_ctx(certfile, keyfile, dhfile, cipherlist,
	                                       verify, ca_cert, min_tls_version);
	if (ctx == NULL)
		return 0;

	/* Register the SNI callback so per-hostname contexts can be selected
	 * during the handshake for any SSL object derived from this context. */
	#ifdef WOLFSSL_TLSEXT_NAMETYPE_host_name
	wolfSSL_CTX_set_tlsext_servername_callback(ctx, sni_servername_cb);
	wolfSSL_CTX_set_tlsext_servername_arg(ctx, NULL);
	#endif

	if (ssl_ctx)
		wolfSSL_CTX_free(ssl_ctx);

	ssl_ctx = ctx;

	/* Release all per-hostname SNI contexts and their hostname strings.
	 * The caller is expected to re-register any SNI entries via
	 * op_setup_ssl_server_sni() after this call, as is done on REHASH. */
	#ifdef WOLFSSL_TLSEXT_NAMETYPE_host_name
	sni_table_free();
	#endif

	/* Load the server cert/key into the outgoing (client) TLS context so
	 * that when a remote server requests a client certificate during the
	 * TLS handshake (for certfp-based S2S authentication) we can present
	 * one.  Eagerly create ssl_client_ctx here if it does not yet exist so
	 * the credentials are ready before the first outgoing connection. */
	if (certfile && *certfile)
	{
		if (ssl_client_ctx == NULL)
			ssl_client_ctx = build_client_ssl_ctx();
		if (ssl_client_ctx != NULL)
		{
			const char *kf = (keyfile && *keyfile) ? keyfile : certfile;
			/* Use chain_file so that an intermediate CA cert bundled
			 * with the server cert is also presented during S2S handshakes
			 * that require client-certificate authentication. */
			if (wolfSSL_CTX_use_certificate_chain_file(ssl_client_ctx,
			                                            certfile) != WOLFSSL_SUCCESS)
				op_lib_log("%s: wolfSSL_CTX_use_certificate_chain_file "
				           "for client CTX failed", __func__);
			else if (wolfSSL_CTX_use_PrivateKey_file(ssl_client_ctx, kf,
			                                          WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
				op_lib_log("%s: wolfSSL_CTX_use_PrivateKey_file "
				           "for client CTX failed", __func__);
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
	#ifndef WOLFSSL_TLSEXT_NAMETYPE_host_name
	op_lib_log("%s: SNI not supported by this wolfSSL build; ignoring hostname '%s'",
	           __func__, hostname ? hostname : "");
	return 0;
	#else
	if (hostname == NULL || *hostname == '\0')
	{
		op_lib_log("%s: empty hostname; use op_setup_ssl_server for the default certificate",
		           __func__);
		return 0;
	}

	WOLFSSL_CTX *const ctx = build_ssl_ctx(certfile, keyfile, dhfile, cipherlist,
	                                       verify, ca_cert, min_tls_version);
	if (ctx == NULL)
		return 0;

	/* Replace existing entry for this hostname if present. */
	for (int i = 0; i < sni_count; i++)
	{
		if (strcasecmp(sni_table[i].hostname, hostname) == 0)
		{
			wolfSSL_CTX_free(sni_table[i].ctx);
			sni_table[i].ctx = ctx;
			op_lib_log("%s: updated SNI certificate for '%s'", __func__, hostname);
			return 1;
		}
	}

	if (sni_count >= SNI_CTX_MAX)
	{
		op_lib_log("%s: SNI table full (max %d entries); cannot add '%s'",
		           __func__, SNI_CTX_MAX, hostname);
		wolfSSL_CTX_free(ctx);
		return 0;
	}

	sni_table[sni_count].hostname = op_strdup(hostname);
	if (sni_table[sni_count].hostname == NULL)
	{
		op_lib_log("%s: out of memory for hostname '%s'", __func__, hostname);
		wolfSSL_CTX_free(ctx);
		return 0;
	}
	sni_table[sni_count].ctx = ctx;
	sni_count++;

	op_lib_log("%s: registered SNI certificate for '%s'", __func__, hostname);
	return 1;
	#endif /* WOLFSSL_TLSEXT_NAMETYPE_host_name */
}

int
op_init_prng(const char *const path, prng_seed_t seed_type)
{
	(void) path;
	(void) seed_type;
	/* getrandom(2) draws directly from the kernel CSPRNG; no explicit
	 * seeding or status check needed. */
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
	return op_ssl_strerror(F->ssl_errno);
}

int
op_get_ssl_certfp(op_fde_t *const F, uint8_t certfp[const OP_SSL_CERTFP_LEN], const int method)
{
	if (F == NULL || F->ssl == NULL)
		return 0;

	WOLFSSL_X509 *const peer_cert = wolfSSL_get_peer_certificate(SSL_P(F));
	if (peer_cert == NULL)
		return 0;

	const int len = make_certfp(peer_cert, certfp, method);
	wolfSSL_X509_free(peer_cert);
	return len;
}

int
op_get_ssl_certfp_file(const char *const filename, uint8_t certfp[const OP_SSL_CERTFP_LEN], const int method)
{
	WOLFSSL_X509 *const cert = wolfSSL_X509_load_certificate_file(filename, WOLFSSL_FILETYPE_PEM);
	if (cert == NULL)
		return 0;

	int len = make_certfp(cert, certfp, method);

	wolfSSL_X509_free(cert);
	return len;
}

void
op_get_ssl_info(char *const buf, const size_t len)
{
	if (LOP_SSL_VNUM_RUNTIME == LOP_SSL_VNUM_COMPILETIME)
		(void) snprintf(buf, len, "wolfSSL: compiled 0x%lx, library %s",
		                LOP_SSL_VNUM_COMPILETIME, LOP_SSL_VTEXT_COMPILETIME);
	else
		(void) snprintf(buf, len, "wolfSSL: compiled (0x%lx, %s), library (0x%lx, %s)",
		                LOP_SSL_VNUM_COMPILETIME, LOP_SSL_VTEXT_COMPILETIME,
		                LOP_SSL_VNUM_RUNTIME, LOP_SSL_VTEXT_RUNTIME);
}

const char *
op_ssl_get_cipher(op_fde_t *const F)
{
	if (F == NULL || F->ssl == NULL)
		return NULL;

	/* Thread-local buffer so concurrent calls on different connections do
	 * not clobber each other's result.  In practice ophion runs a single
	 * I/O thread, but _Thread_local costs nothing and is correct. */
	static _Thread_local char buf[512];

	const char *const version = wolfSSL_get_version(SSL_P(F));
	const char *const cipher = wolfSSL_get_cipher_name(SSL_P(F));

	(void) snprintf(buf, sizeof buf, "%s, %s",
	                version ? version : "unknown",
	                cipher  ? cipher  : "unknown");

	return buf;
}

ssize_t
op_ssl_read(op_fde_t *const F, void *const buf, const size_t count)
{
#if defined(HAVE_KERNEL_TLS) || defined(HAVE_WOLFSSL_KTLS)
	/*
	 * kTLS active: the kernel decrypts incoming TLS records and delivers
	 * plaintext.  wolfSSL must not be involved (double decryption).
	 *
	 * Under HAVE_WOLFSSL_KTLS, freshly-negotiated kTLS connections are
	 * handled by wolfSSL internally (F->ssl != NULL, F->ktls == false) so
	 * this block is skipped.  The block only fires for migrated kTLS clients
	 * where op_fde_mark_ktls() set F->ktls = true and F->ssl is NULL.
	 *
	 * Linux kTLS delivers non-application-data records (alerts, handshake
	 * messages) in two ways depending on kernel version:
	 *
	 *   < 4.17 / device kTLS:
	 *     recv() returns -1 with errno == EBADMSG.  The record content is
	 *     not exposed to userspace; the only correct action is to close.
	 *
	 *   >= 4.17 software kTLS:
	 *     recvmsg() delivers the record payload and sets a control message
	 *     (cmsg_level=SOL_TLS, cmsg_type=TLS_GET_RECORD_TYPE) containing
	 *     the one-byte TLS content type.  Application data (type 23) is
	 *     returned normally; any other type (21=ALERT, 22=HANDSHAKE) is a
	 *     signal to close — we log the type and return an error.
	 *
	 * Using recvmsg() with a cmsg buffer handles both paths: on older
	 * kernels the cmsg is simply not populated, and EBADMSG is detected in
	 * the same errno check as before.
	 */
	if (F->ktls)
	{
		/* TLS application-data record type (RFC 8446 §5.1). */
#		ifndef TLS_RT_APPLICATION_DATA
#		define TLS_RT_APPLICATION_DATA 23
#		endif
		/* TLS_GET_RECORD_TYPE is defined in <linux/tls.h> (≥ 4.17). */
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
				/* Kernel-level kTLS: a non-app-data record (typically a TLS
				 * alert) arrived.  The socket cannot be used for further I/O. */
				op_lib_log("kTLS read fd %d: alert/control record (EBADMSG) — closing",
				           op_get_fd(F));
				errno = EPROTO;
			}
			return OP_RW_IO_ERROR;
		}

		/* Inspect the cmsg to detect non-application-data record types
		 * delivered by software kTLS (kernel ≥ 4.17). */
		for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm != NULL;
		     cm = CMSG_NXTHDR(&msg, cm))
		{
			if (cm->cmsg_level == SOL_TLS &&
			    cm->cmsg_type  == TLS_GET_RECORD_TYPE)
			{
				const uint8_t rec_type = *(const uint8_t *)CMSG_DATA(cm);
				if (rec_type == TLS_RT_APPLICATION_DATA)
					break; /* normal path — fall through to return r */

				/* TLS alert record (type 21): inspect for close_notify
				 * (level=any, description=0).  A close_notify is a clean
				 * peer shutdown; return 0 so callers see EOF rather than
				 * an error.  Any other alert is fatal — close with EPROTO. */
				if (rec_type == 21 /* TLS_RT_ALERT */)
				{
					/* Alert payload: 2 bytes [level][description].
					 * description 0 = close_notify. */
					if (r >= 2 && ((const uint8_t *)buf)[1] == 0)
					{
						errno = 0;
						return 0; /* clean close_notify */
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

		return r; /* 0 = clean EOF, > 0 = plaintext bytes */
	}
#endif
	return op_ssl_read_or_write(0, F, buf, NULL, count);
}

int
op_ssl_pending(op_fde_t *const F)
{
	if (F == NULL || F->ssl == NULL || F->ktls)
		return 0;
	return wolfSSL_pending(SSL_P(F));
}

ssize_t
op_ssl_write(op_fde_t *const F, const void *const buf, const size_t count)
{
#if defined(HAVE_KERNEL_TLS) || defined(HAVE_WOLFSSL_KTLS)
	/*
	 * kTLS active: the kernel encrypts and frames outgoing data as TLS
	 * records via send().  wolfSSL must not be involved or it would add
	 * another layer of TLS framing (double encryption).
	 *
	 * Under HAVE_WOLFSSL_KTLS, freshly-negotiated kTLS connections are
	 * handled by wolfSSL internally (F->ssl != NULL, F->ktls == false) so
	 * this block is skipped.  The block only fires for migrated kTLS clients
	 * where op_fde_mark_ktls() set F->ktls = true and F->ssl is NULL.
	 */
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
			/* ENOTSUP can be returned by some kernel versions when TLS 1.3
			 * KeyUpdate processing is in progress.  The kernel will complete
			 * the KeyUpdate internally; treat this as a transient write stall
			 * and let the caller retry via the normal write-ready path. */
			if (errno == ENOTSUP)
			{
				errno = EAGAIN;
				return OP_RW_SSL_NEED_WRITE;
			}
			return OP_RW_IO_ERROR; /* errno (EPIPE, ECONNRESET, …) is meaningful */
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
	/*
	 * Cache F->connect in a local so the compiler keeps it in a register
	 * for both the NULL check and the subsequent writes.  Without this,
	 * LTO can insert a memory reload between the check and the write (due
	 * to pthread barriers from inlined op_setselect/op_settimeout callers),
	 * turning a non-NULL check into a NULL dereference if op_close() races
	 * and clears F->connect on another thread.
	 */
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
		/* Cancel the timer referencing sconn before freeing it, then
		 * restore the user callback from sconn and deliver the error.
		 * Calling op_connect_callback directly would silently drop the
		 * error because F->connect->callback was already cleared by the
		 * outer op_connect_callback that dispatched op_ssl_tryconn. */
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
	/* Clamp addrlen defensively: a negative or oversized value from the
	 * kernel accept() would overflow the sockaddr_storage buffer. */
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
		/* Cancel the timer referencing sconn before freeing it (same
		 * pattern as op_ssl_tryconn).  op_ssl_connect_realcb restores
		 * the user callback from sconn, delivers the error, then frees
		 * sconn — do not op_free(sconn) here. */
		op_settimeout(F, 0, NULL, NULL);
		op_ssl_connect_realcb(F, OP_ERROR_SSL, sconn);
		return;
	}
	op_ssl_connect_common(F, sconn);
}

#endif /* HAVE_WOLFSSL */
