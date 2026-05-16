/*
 *  libop: ophion support library.
 *  commio-ssl.h: A header for the ssl code
 *
 *  Copyright (C) 2008 ircd-ratbox development team
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

#ifndef _COMMIO_SSL_H
#define _COMMIO_SSL_H

#include <stdbool.h>

int op_setup_ssl_server(const char *cert, const char *keyfile, const char *dhfile,
                        const char *cipher_list, bool verify,
                        const char *ca_cert, const char *min_tls_version);
int op_init_ssl(void);

int op_ssl_listen(op_fde_t *F, int backlog, int defer_accept);
int op_init_prng(const char *path, prng_seed_t seed_type);

int op_get_random(void *buf, size_t length);
const char *op_get_ssl_strerror(op_fde_t *F);
void op_ssl_start_accepted(op_fde_t *new_F, ACCB * cb, void *data, int timeout, bool wsock);
void op_ssl_start_connected(op_fde_t *F, CNCB * callback, void *data, int timeout);
void op_connect_tcp_ssl(op_fde_t *F, struct sockaddr *dest, struct sockaddr *clocal,
			CNCB * callback, void *data, int timeout,
			const char *sni_hostname);
void op_connect_tcp_ssl_ex(op_fde_t *F, struct sockaddr *dest, struct sockaddr *clocal,
			   CNCB * callback, void *data, int timeout,
			   const char *sni_hostname, const char *alpn);
void op_ssl_accept_setup(op_fde_t *F, op_fde_t *new_F, struct sockaddr *st, int addrlen, bool wsock);
void op_ssl_shutdown(op_fde_t *F);
ssize_t op_ssl_read(op_fde_t *F, void *buf, size_t count);
ssize_t op_ssl_write(op_fde_t *F, const void *buf, size_t count);
int op_ssl_pending(op_fde_t *F);
void op_get_ssl_info(char *buf, size_t length);

/*
 * op_ssl_is_ktls — returns true if this TLS connection has been offloaded to
 * Linux kernel TLS (kTLS).  When true, the socket FD can be transferred to
 * another process via SCM_RIGHTS; the new process can use plain recv()/send()
 * and the kernel handles TLS encryption/decryption transparently.
 *
 * kTLS is activated for TLS 1.2 and TLS 1.3 connections using AES-GCM or
 * ChaCha20-Poly1305 immediately after the handshake.  When HAVE_KERNEL_TLS
 * is defined, ophion extracts keys via the opssl key-extraction API, calls
 * setsockopt(SOL_TLS) itself, and bypasses the TLS library for I/O.
 * Returns false when kTLS is unavailable or the cipher suite is unsupported
 * (e.g. CBC mode).
 */
bool op_ssl_is_ktls(op_fde_t *F);

/*
 * op_fde_mark_ktls — mark an FDE as a kernel-TLS socket.
 *
 * Call this after adopting a kTLS-migrated FD in the new binary
 * (i.e. a socket transferred via SCM_RIGHTS whose kernel-TLS state is
 * already active).  Setting F->ktls ensures that op_ssl_read/write use
 * plain recv()/send() and that a subsequent upgrade correctly identifies
 * the client as kTLS-capable and re-migrates it instead of disconnecting.
 */
void op_fde_mark_ktls(op_fde_t *F);

/*
 * op_ssl_promote_ktls — late kTLS promotion for an established TLS connection.
 *
 * Unlike the handshake-time promotion, this reads the CURRENT TX and RX
 * sequence numbers from the live TLS session so the kernel kTLS state
 * picks up exactly where the TLS library left off.
 *
 * Intended use: upgrade drain phase — call before serialising a TLS client
 * so that connections not promoted at handshake time (e.g. TLS 1.2 clients
 * that connected before the kernel tls module was loaded) can migrate
 * transparently instead of receiving a graceful close.
 *
 * Returns: 1 promoted, 0 not promoted, -1 fatal partial-kTLS state.
 * No-op (0) if F is already kTLS, outgoing, or the build lacks kTLS support.
 */
int op_ssl_promote_ktls(op_fde_t *F);

/*
 * op_ssl_export — export the complete TLS session state into buf.
 *
 * Serialises keys, IVs, sequence numbers, and cipher-suite parameters.
 * The resulting blob can be transferred alongside the raw socket FD to a
 * new process, which calls op_ssl_adopt_exported() to resume the TLS
 * session without the kernel tls module.
 *
 * Returns the number of bytes written into buf (> 0) on success, or -1 if
 * the session state could not be exported or F has no active session.
 *
 * buf must be at least MIGRATE_SSL_EXPORT_MAX bytes.
 */
int op_ssl_export(op_fde_t *F, uint8_t *buf, size_t buflen);

/*
 * op_ssl_adopt_exported — reconstruct a TLS session from an export blob.
 *
 * Called in the new binary after adopting a live-migrated socket FD.  Creates
 * a fresh TLS connection from the global context, imports the previously
 * exported session state, and attaches it to F so that subsequent
 * op_ssl_read()/op_ssl_write() calls continue the TLS stream transparently.
 *
 * Returns 0 on success, -1 on failure (feature absent, bad blob, OOM, …).
 * On failure the FD is still valid but has no SSL layer; the caller must
 * close the connection.
 */
int op_ssl_adopt_exported(op_fde_t *F, const uint8_t *buf, size_t len);

/*
 * op_ssl_is_outgoing_connection — return true if F was established as the
 * connecting (client) side.  Used by session-migration to select the correct
 * CTX when reconstructing TLS state in the new binary.
 */
bool op_ssl_is_outgoing_connection(const op_fde_t *F);

/*
 * op_ssl_adopt_exported_outgoing — like op_ssl_adopt_exported but uses the
 * outgoing (client-side) SSL context.  Use this when adopting a migrated S2S
 * link that was originally established as an outgoing connection.
 */
int op_ssl_adopt_exported_outgoing(op_fde_t *F, const uint8_t *buf, size_t len);

/*
 * op_ssl_export_keying_material — derive keying material via RFC 5705 / RFC 8446 §7.5.
 *
 * Fills out[0..outlen-1] with bytes derived from the TLS exporter for the
 * session on F.  label is the ASCII exporter label (not NUL-terminated in the
 * wire format, but passed as a C string here); context / context_len are the
 * optional per-association context (pass NULL / 0 for the no-context case).
 *
 * Returns 1 on success, 0 on failure (no SSL session or the derivation
 * itself failed).
 *
 * Primary use: SASL EXTERNAL with tls-exporter channel binding (RFC 9266).
 * The label "EXPORTER-Channel-Binding" with no context produces a 32-byte
 * binding value that clients include in the AUTHENTICATE payload.
 */
int op_ssl_export_keying_material(op_fde_t *F,
                                  uint8_t *out, size_t outlen,
                                  const char *label,
                                  const uint8_t *context, size_t context_len);

#endif
