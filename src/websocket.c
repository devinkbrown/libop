/*
 * libop/src/websocket.c — In-process WebSocket (RFC 6455) framing layer.
 *
 * Replaces the external wsockd subprocess.  A raw TCP socket accepted by
 * ircd's listener is upgraded to a WebSocket in-process:
 *
 *   op_ws_start_accepted(F, cb, data, timeout)
 *       Arms the HTTP-upgrade read callback.  When the handshake finishes
 *       (or times out / fails) the ACCB cb is invoked, exactly as SSL does
 *       via op_ssl_start_accepted().
 *
 * After the handshake, op_read()/op_write() on the fd are transparently
 * framed/deframed via op_ws_read() / op_ws_write().
 *
 * Copyright (C) 2026 ophion development team — GPL-2.0+
 */

#define _GNU_SOURCE 1
#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <commio-ssl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "sha1.h"


/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define WS_MAX_HEADER_SIZE   4096
#define WS_INBUF_INITIAL     8192
#define WS_DECODED_INITIAL   4096
#define WS_READBUF_SIZE     16384
#define CORK_THRESHOLD       4096

#define WS_OPCODE_CONT   0x0
#define WS_OPCODE_TEXT   0x1
#define WS_OPCODE_BINARY 0x2   /* binary data frame — treated same as text for IRC */
#define WS_OPCODE_CLOSE  0x8
#define WS_OPCODE_PING   0x9
#define WS_OPCODE_PONG   0xA

#define WS_CLOSE_NORMAL         1000
#define WS_CLOSE_PROTOCOL_ERROR 1002
#define WS_CLOSE_INVALID_UTF8   1007   /* RFC 6455 §7.4.1: invalid text encoding */
#define WS_CLOSE_TOO_LARGE      1009

/* Maximum aggregate decoded message size.  IRC lines should never exceed
 * ~8 KiB (tags + line), so 64 KiB is very generous and prevents memory
 * exhaustion from a malicious peer sending unlimited continuation frames. */
#define WS_MAX_MESSAGE_SIZE     (64u * 1024u)

#define WEBSOCKET_SERVER_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static const char ws_answer_1[] =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: ";

static const char ws_answer_2[] = "\r\n\r\n";

/* -------------------------------------------------------------------------
 * Per-connection WebSocket state (stored in F->ws)
 * ---------------------------------------------------------------------- */

typedef struct {
    /* Raw bytes received from TCP, not yet parsed into frames.
     * We use a flat resizable buffer so we can "peek" without consuming. */
    uint8_t *inbuf;
    size_t   inbuf_len;
    size_t   inbuf_cap;

    /* WS-framed bytes waiting to be written to the TCP socket */
    rawbuf_head_t *frame_out;

    /* Decoded IRC text ready for op_ws_read to return to the caller */
    uint8_t *decoded;
    size_t   decoded_cap;
    size_t   decoded_len;
    size_t   decoded_pos;

    /* HTTP upgrade accumulation (NULL after handshake) */
    char    *hs_buf;
    size_t   hs_len;

    /* State */
    bool keyed;       /* HTTP upgrade complete */
    bool sent_close;  /* WS CLOSE frame sent */

    /* Fragmentation state (RFC 6455 §5.4) */
    bool    in_fragment;      /* true while receiving a multi-frame message */
    uint8_t fragment_opcode;  /* TEXT or BINARY opcode of the open fragment sequence */
} ws_state_t;

/* -------------------------------------------------------------------------
 * Allocate / free state
 * ---------------------------------------------------------------------- */

static ws_state_t *
ws_alloc(void)
{
    ws_state_t *ws      = op_malloc(sizeof *ws);
    ws->inbuf           = op_malloc(WS_INBUF_INITIAL);
    ws->inbuf_len       = 0;
    ws->inbuf_cap       = WS_INBUF_INITIAL;
    ws->frame_out       = op_new_rawbuffer();
    ws->decoded         = op_malloc(WS_DECODED_INITIAL);
    ws->decoded_cap     = WS_DECODED_INITIAL;
    ws->decoded_len     = 0;
    ws->decoded_pos     = 0;
    ws->hs_buf          = NULL;
    ws->hs_len          = 0;
    ws->keyed           = false;
    ws->sent_close      = false;
    ws->in_fragment     = false;
    ws->fragment_opcode = 0;
    return ws;
}

static void
ws_free(ws_state_t *ws)
{
    if (!ws) return;
    op_free(ws->inbuf);
    op_free_rawbuffer(ws->frame_out);
    op_free(ws->decoded);
    op_free(ws->hs_buf);
    op_free(ws);
}

/* -------------------------------------------------------------------------
 * inbuf helpers
 * ---------------------------------------------------------------------- */

/* Ensure inbuf has room for `extra` more bytes. */
static void
inbuf_grow(ws_state_t *ws, size_t extra)
{
    if (op_unlikely(extra > SIZE_MAX - ws->inbuf_len))
        abort();
    size_t need = ws->inbuf_len + extra;
    if (need > ws->inbuf_cap)
    {
        size_t newcap  = need + WS_INBUF_INITIAL;
        ws->inbuf      = op_realloc(ws->inbuf, newcap);
        ws->inbuf_cap  = newcap;
    }
}

/* Consume `n` bytes from the front of inbuf. */
static void
inbuf_consume(ws_state_t *ws, size_t n)
{
    if (n >= ws->inbuf_len)
    {
        ws->inbuf_len = 0;
    }
    else
    {
        memmove(ws->inbuf, ws->inbuf + n, ws->inbuf_len - n);
        ws->inbuf_len -= n;
    }
}

/* -------------------------------------------------------------------------
 * decoded-output helpers
 * ---------------------------------------------------------------------- */

/* Returns false if the aggregate message exceeds WS_MAX_MESSAGE_SIZE. */
static bool
decoded_append(ws_state_t *ws, const uint8_t *data, size_t len)
{
    /* Compact: slide unread bytes to front */
    if (ws->decoded_pos > 0)
    {
        size_t avail = ws->decoded_len - ws->decoded_pos;
        if (avail > 0)
            memmove(ws->decoded, ws->decoded + ws->decoded_pos, avail);
        ws->decoded_len = avail;
        ws->decoded_pos = 0;
    }

    if (op_unlikely(len > SIZE_MAX - ws->decoded_len))
        return false;
    size_t need = ws->decoded_len + len;
    if (need > WS_MAX_MESSAGE_SIZE)
        return false;
    if (need > ws->decoded_cap)
    {
        size_t newcap   = need + WS_DECODED_INITIAL;
        ws->decoded     = op_realloc(ws->decoded, newcap);
        ws->decoded_cap = newcap;
    }
    memcpy(ws->decoded + ws->decoded_len, data, len);
    ws->decoded_len += len;
    return true;
}

/* -------------------------------------------------------------------------
 * Low-level frame write helpers (server→client, unmasked)
 * ---------------------------------------------------------------------- */

static void
ws_write_frame_raw(ws_state_t *ws, uint8_t first_byte,
                   const uint8_t *payload, size_t len)
{
    uint8_t hdr[4];
    size_t  hdrsz;

    hdr[0] = first_byte;
    /* Clamp before encoding the length field so the header and payload
     * are always consistent.  IRC lines never legitimately exceed 65535
     * bytes, so truncation here indicates a caller bug. */
    if (len > 65535) len = 65535;
    if (len < 126)
    {
        hdr[1] = (uint8_t)len;
        hdrsz  = 2;
    }
    else
    {
        hdr[1] = 126;
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)(len & 0xff);
        hdrsz  = 4;
    }
    op_rawbuf_append(ws->frame_out, hdr, hdrsz);
    if (len > 0)
        op_rawbuf_append(ws->frame_out, (void *)payload, len);
}

static void
ws_write_close_frame(ws_state_t *ws, uint16_t code)
{
    if (ws->sent_close) return;
    uint8_t payload[2] = { (uint8_t)(code >> 8), (uint8_t)(code & 0xff) };
    ws_write_frame_raw(ws, WS_OPCODE_CLOSE | 0x80, payload, 2);
    ws->sent_close = true;
}

/* Queue a TEXT frame for the given plaintext payload. */
static void
ws_queue_text_frame(ws_state_t *ws, const uint8_t *data, size_t len)
{
    ws_write_frame_raw(ws, WS_OPCODE_TEXT | 0x80, data, len);
}

/* -------------------------------------------------------------------------
 * ws_is_valid_utf8 — validate a byte sequence as well-formed UTF-8.
 *
 * Used for TEXT frames per RFC 6455 §8.1: "When an endpoint is to _Fail
 * the WebSocket Connection_, it MUST _Close the WebSocket Connection_."
 * Returns true if buf[0..len) is valid UTF-8, false otherwise.
 *
 * Checks: proper start bytes, continuation bytes, overlong encodings,
 * surrogate pairs (U+D800–U+DFFF), and codepoints above U+10FFFF.
 * ---------------------------------------------------------------------- */

static bool
ws_is_valid_utf8(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; )
    {
        uint8_t c = buf[i];
        size_t  seq;

        if      (c < 0x80) { seq = 1; }
        else if (c < 0xC2) { return false; } /* continuation or overlong */
        else if (c < 0xE0) { seq = 2; }
        else if (c < 0xF0) { seq = 3; }
        else if (c < 0xF5) { seq = 4; }
        else               { return false; } /* > U+10FFFF */

        if (i + seq > len)
            return false;  /* truncated codepoint */

        for (size_t j = 1; j < seq; j++)
            if ((buf[i + j] & 0xC0) != 0x80)
                return false;  /* expected continuation byte */

        if (seq == 2 && (c & 0x1E) == 0)
            return false;  /* overlong 2-byte */

        if (seq == 3)
        {
            uint32_t cp = ((uint32_t)(c & 0x0F) << 12)
                        | ((uint32_t)(buf[i+1] & 0x3F) << 6)
                        |  (uint32_t)(buf[i+2] & 0x3F);
            if (cp < 0x800)              return false;  /* overlong 3-byte */
            if (cp >= 0xD800 && cp <= 0xDFFF) return false;  /* surrogate */
        }

        if (seq == 4)
        {
            uint32_t cp = ((uint32_t)(c & 0x07) << 18)
                        | ((uint32_t)(buf[i+1] & 0x3F) << 12)
                        | ((uint32_t)(buf[i+2] & 0x3F) << 6)
                        |  (uint32_t)(buf[i+3] & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF) return false;
        }

        i += seq;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * Frame parsing
 *
 * Parses as many complete WS frames as possible from ws->inbuf.
 * Decoded IRC text is appended to ws->decoded.
 * Returns false if the connection should be torn down.
 * ---------------------------------------------------------------------- */

static bool
ws_parse_frames(op_fde_t *F, ws_state_t *ws)
{
    while (ws->inbuf_len >= 2)
    {
        const uint8_t *p   = ws->inbuf;
        uint8_t first      = p[0];
        uint8_t second     = p[1];
        int     fin        = (first >> 7) & 1;     /* FIN bit: 1 = final frame */
        int     masked     = (second >> 7) & 1;
        size_t  payload_len = second & 0x7f;
        int     opcode     = first & 0x0f;
        int     rsv        = (first >> 4) & 0x7;
        size_t  consumed   = 2;   /* bytes consumed so far */

        int rsv_check  = rsv;

        if (rsv_check != 0)
        {
            ws_write_close_frame(ws, WS_CLOSE_PROTOCOL_ERROR);
            op_rawbuf_flush(ws->frame_out, F);
            return false;
        }

        /* Determine full payload length */
        if (payload_len == 126)
        {
            if (ws->inbuf_len < consumed + 2) break;   /* partial */
            payload_len = ((size_t)p[consumed] << 8) | p[consumed + 1];
            consumed += 2;
        }
        else if (payload_len == 127)
        {
            /* 8-byte extended length — IRC messages are never this large */
            if (ws->inbuf_len < consumed + 8) break;
            ws_write_close_frame(ws, WS_CLOSE_TOO_LARGE);
            op_rawbuf_flush(ws->frame_out, F);
            return false;
        }

        /* Control frames (CLOSE/PING/PONG, opcode ≥ 0x8):
         *   - Must not be fragmented (FIN must be 1)
         *   - Payload must be ≤ 125 bytes
         *   RFC 6455 §5.5 */
        if (opcode >= 0x8 && (!fin || payload_len > 125))
        {
            ws_write_close_frame(ws, WS_CLOSE_PROTOCOL_ERROR);
            op_rawbuf_flush(ws->frame_out, F);
            return false;
        }

        /* Fragmentation state validation (RFC 6455 §5.4):
         *   A new TEXT or BINARY frame must not arrive while a fragmented
         *   sequence is open.  A CONT frame must not arrive outside one. */
        if ((opcode == WS_OPCODE_TEXT || opcode == WS_OPCODE_BINARY) && ws->in_fragment)
        {
            ws_write_close_frame(ws, WS_CLOSE_PROTOCOL_ERROR);
            op_rawbuf_flush(ws->frame_out, F);
            return false;
        }
        if (opcode == WS_OPCODE_CONT && !ws->in_fragment)
        {
            ws_write_close_frame(ws, WS_CLOSE_PROTOCOL_ERROR);
            op_rawbuf_flush(ws->frame_out, F);
            return false;
        }

        /* Masking key */
        uint8_t mask_key[4] = { 0, 0, 0, 0 };
        if (masked)
        {
            if (ws->inbuf_len < consumed + 4) break;
            memcpy(mask_key, p + consumed, 4);
            consumed += 4;
        }

        /* Full payload available? */
        if (ws->inbuf_len < consumed + payload_len) break;

        /* Unmask into a local buffer */
        uint8_t *payload_buf = (uint8_t *)(p + consumed);
        uint8_t  local_buf[WS_READBUF_SIZE];
        if (payload_len > 0 && payload_len <= sizeof local_buf)
        {
            memcpy(local_buf, payload_buf, payload_len);
            if (masked)
                for (size_t i = 0; i < payload_len; i++)
                    local_buf[i] ^= mask_key[i & 3];
            payload_buf = local_buf;
        }
        else if (payload_len > sizeof local_buf)
        {
            ws_write_close_frame(ws, WS_CLOSE_TOO_LARGE);
            op_rawbuf_flush(ws->frame_out, F);
            return false;
        }

        consumed += payload_len;

        /* Dispatch by opcode */
        switch (opcode)
        {
        case WS_OPCODE_TEXT:
        case WS_OPCODE_BINARY:   /* treat binary frames same as text for IRC */
        case WS_OPCODE_CONT:
        {
            /* is_text: true when the message's data type is TEXT (for UTF-8
             * validation).  For CONT frames, use the type of the first frame
             * in the sequence (stored in fragment_opcode).  For new TEXT or
             * BINARY frames, use the current opcode directly. */
            bool is_text = (opcode == WS_OPCODE_TEXT) ||
                           (opcode == WS_OPCODE_CONT &&
                            ws->fragment_opcode == WS_OPCODE_TEXT);

            {
                if (payload_len > 0)
                {
                    /* UTF-8 validation on final frame of a text message. */
                    if (fin && is_text && !ws_is_valid_utf8(payload_buf, payload_len))
                    {
                        ws_write_close_frame(ws, WS_CLOSE_INVALID_UTF8);
                        op_rawbuf_flush(ws->frame_out, F);
                        return false;
                    }
                    if (!decoded_append(ws, payload_buf, payload_len))
                    {
                        ws_write_close_frame(ws, WS_CLOSE_TOO_LARGE);
                        op_rawbuf_flush(ws->frame_out, F);
                        return false;
                    }
                }
                /* CRLF only on the final (or only) frame of the message. */
                if (fin)
                    decoded_append(ws, (const uint8_t *)"\r\n", 2);
            }

            /* Update fragmentation state:
             *   Starting a new TEXT/BINARY: record its opcode; in_fragment
             *   becomes true only if FIN=0 (more frames to come).
             *   CONT frame: in_fragment clears when FIN=1. */
            if (opcode == WS_OPCODE_TEXT || opcode == WS_OPCODE_BINARY)
            {
                ws->fragment_opcode = (uint8_t)opcode;
                ws->in_fragment     = !fin;
            }
            else /* CONT */
            {
                ws->in_fragment = !fin;
            }
            break;
        }

        case WS_OPCODE_PING:
        {
            /* Echo a PONG with the same payload (RFC 6455 §5.5.3) */
            ws_write_frame_raw(ws, WS_OPCODE_PONG | 0x80, payload_buf, payload_len);
            break;
        }

        case WS_OPCODE_PONG:
            /* Unsolicited PONG — RFC 6455 §5.5.3 says discard silently */
            break;

        case WS_OPCODE_CLOSE:
        {
            /* Parse the incoming status code (if present) and echo it back.
             * RFC 6455 §5.5.1: if the close frame has a body, the first two
             * bytes are a big-endian status code.
             * RFC 6455 §7.4.1: validate the code is in an allowed range. */
            uint16_t echo_code = WS_CLOSE_NORMAL;
            if (payload_len >= 2)
            {
                echo_code = ((uint16_t)payload_buf[0] << 8) | payload_buf[1];
                /* Reject reserved or undefined codes */
                if (echo_code < 1000 ||
                    echo_code == 1004 || echo_code == 1005 || echo_code == 1006 ||
                    (echo_code >= 1012 && echo_code <= 2999) || echo_code >= 5000)
                    echo_code = WS_CLOSE_PROTOCOL_ERROR;
            }
            if (!ws->sent_close)
                ws_write_close_frame(ws, echo_code);
            op_rawbuf_flush(ws->frame_out, F);
            inbuf_consume(ws, consumed);
            return false;
        }

        default:
            /* Unknown or reserved opcode — RFC 6455 §5.2 */
            ws_write_close_frame(ws, WS_CLOSE_PROTOCOL_ERROR);
            op_rawbuf_flush(ws->frame_out, F);
            return false;
        }

        inbuf_consume(ws, consumed);
    }

    /* Flush any PONG or CLOSE frames queued during parse */
    op_rawbuf_flush(ws->frame_out, F);
    return true;
}

/* -------------------------------------------------------------------------
 * ws_fd_recv / ws_fd_send — SSL-transparent I/O helpers.
 *
 * WebSocket connections may run over plain TCP (ws://, port 8082) or over
 * TLS (wss://, port 8080).  For TLS fds the WS layer must go through the
 * TLS read/write API; raw recv/send would see encrypted bytes.
 *
 * ws_fd_recv: wraps op_ssl_read() on TLS fds, recv() on plain fds.
 *   Returns > 0 on success, 0 on EOF, < 0 on error/would-block.
 *   Sets errno = EAGAIN when the call should be retried.
 *
 * ws_fd_send: wraps op_ssl_write() on TLS fds, send() on plain fds.
 *   Returns bytes written on success, <= 0 on error.
 * ---------------------------------------------------------------------- */

static ssize_t
ws_fd_recv(op_fde_t *F, void *buf, size_t len)
{
    if (op_fd_ssl(F))
    {
        ssize_t r = op_ssl_read(F, buf, len);
        /* Normalise SSL need-read/write to EAGAIN so the caller loop works */
        if (r == OP_RW_SSL_NEED_READ || r == OP_RW_SSL_NEED_WRITE)
        {
            errno = EAGAIN;
            return -1;
        }
        return r;
    }
    return recv(F->fd, buf, len, 0);
}

static ssize_t
ws_fd_send(op_fde_t *F, const void *buf, size_t len)
{
    if (op_fd_ssl(F))
    {
        ssize_t r = op_ssl_write(F, buf, len);
        if (r < 0)
            return -1;
        return r;
    }
    return send(F->fd, buf, len, MSG_NOSIGNAL);
}

/* -------------------------------------------------------------------------
 * HTTP upgrade handshake read callback
 *
 * Registered as the read handler on F by op_ws_start_accepted().
 * Accumulates bytes in ws->hs_buf until \r\n\r\n, then validates the
 * WebSocket upgrade request, sends the HTTP 101 response, and fires the
 * ACCB that was registered by the caller.
 * ---------------------------------------------------------------------- */

static void
op_ws_handshake_read(op_fde_t *F, void *data)
{
    (void)data;
    ws_state_t *ws = (ws_state_t *)F->ws;
    if (!ws) return;

    char inbuf[WS_READBUF_SIZE];
    ssize_t nread;

    /* Read bytes from the socket (SSL-transparent) */
    while ((nread = ws_fd_recv(F, inbuf, sizeof(inbuf))) > 0)
    {
        /* Check we won't overflow the header accumulation cap */
        if (ws->hs_len + (size_t)nread > WS_MAX_HEADER_SIZE)
        {
            static const char bad[] =
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            (void)ws_fd_send(F, bad, sizeof(bad) - 1);
            goto fail;
        }
        if (ws->hs_buf == NULL)
        {
            ws->hs_buf = op_malloc(WS_MAX_HEADER_SIZE + 1);
            ws->hs_len = 0;
        }
        memcpy(ws->hs_buf + ws->hs_len, inbuf, (size_t)nread);
        ws->hs_len += (size_t)nread;
        ws->hs_buf[ws->hs_len] = '\0';

        /* Check for end of HTTP headers */
        char *hdr_end = strstr(ws->hs_buf, "\r\n\r\n");
        if (!hdr_end)
            continue;   /* need more bytes */

        /* Any bytes after the headers are early WebSocket frame data */
        {
            char  *frame_start = hdr_end + 4;
            size_t frame_len   = (ws->hs_buf + ws->hs_len) - frame_start;
            if (frame_len > 0)
            {
                inbuf_grow(ws, frame_len);
                memcpy(ws->inbuf + ws->inbuf_len, frame_start, frame_len);
                ws->inbuf_len += frame_len;
            }
        }

        /* --- Parse HTTP headers ---------------------------------------- */
        char client_key[64]  = "";
        char ws_subproto[64] = "";
        int  have_upgrade    = 0;
        int  have_connection = 0;
        int  have_version    = 0;

        char *line = strchr(ws->hs_buf, '\n');
        if (line) line++;

        while (line && line < hdr_end)
        {
            char *eol = memchr(line, '\n', hdr_end + 2 - line);
            if (!eol) break;

            size_t linelen = (size_t)(eol - line);
            char   hline[512];
            if (linelen >= sizeof(hline)) { line = eol + 1; continue; }

            memcpy(hline, line, linelen);
            hline[linelen] = '\0';
            if (linelen > 0 && hline[linelen - 1] == '\r')
                hline[--linelen] = '\0';

            char *colon = strchr(hline, ':');
            if (colon)
            {
                *colon = '\0';
                char *name  = hline;
                char *value = colon + 1;
                while (*value == ' ' || *value == '\t') value++;

                if (op_strcasecmp(name, "Upgrade") == 0)
                    have_upgrade = (op_strcasecmp(value, "websocket") == 0);
                else if (op_strcasecmp(name, "Connection") == 0)
                    have_connection = (op_strcasestr(value, "Upgrade") != NULL);
                else if (op_strcasecmp(name, "Sec-WebSocket-Version") == 0)
                    have_version = (atoi(value) == 13);
                else if (op_strcasecmp(name, "Sec-WebSocket-Key") == 0)
                    op_strlcpy(client_key, value, sizeof(client_key));
                else if (op_strcasecmp(name, "Sec-WebSocket-Protocol") == 0)
                    op_strlcpy(ws_subproto, value, sizeof(ws_subproto));
            }
            line = eol + 1;
        }

        op_free(ws->hs_buf);
        ws->hs_buf = NULL;
        ws->hs_len = 0;

        /* --- Validate -------------------------------------------------- */
        if (!have_upgrade || !have_connection || !have_version || !client_key[0])
        {
            static const char badreq[] =
                "HTTP/1.1 400 Bad Request\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Content-Length: 0\r\n\r\n";
            (void)send(F->fd, badreq, sizeof(badreq) - 1, MSG_NOSIGNAL);
            goto fail;
        }

        /* --- Compute Sec-WebSocket-Accept ------------------------------ */
        {
            SHA1    sha1;
            uint8_t digest[SHA1_DIGEST_LENGTH];
            sha1_init(&sha1);
            sha1_update(&sha1, (uint8_t *)client_key, strlen(client_key));
            sha1_update(&sha1, (uint8_t *)WEBSOCKET_SERVER_KEY,
                        strlen(WEBSOCKET_SERVER_KEY));
            sha1_final(&sha1, digest);
            char *accept = (char *)op_base64_encode(digest, SHA1_DIGEST_LENGTH);

            /* Build the 101 response */
            char response[512];
            int  rlen = 0;
            { int n = snprintf(response + rlen, sizeof(response) - rlen,
                               "%s%s", ws_answer_1, accept);
              if(n > 0) rlen += ((size_t)n >= sizeof(response) - rlen) ? (int)(sizeof(response) - rlen - 1) : n; }
            op_free(accept);

            if (ws_subproto[0] && op_strcasestr(ws_subproto, "irc"))
            { int n = snprintf(response + rlen, sizeof(response) - rlen,
                               "\r\nSec-WebSocket-Protocol: irc");
              if(n > 0) rlen += ((size_t)n >= sizeof(response) - rlen) ? (int)(sizeof(response) - rlen - 1) : n; }

            if (rlen + (int)sizeof(ws_answer_2) < (int)sizeof(response))
            {
                memcpy(response + rlen, ws_answer_2, sizeof(ws_answer_2) - 1);
                rlen += (int)sizeof(ws_answer_2) - 1;
            }

            /* Write the 101 response directly — the TCP send buffer can
             * always absorb ~300 bytes without blocking. */
            ssize_t written = 0;
            while (written < rlen)
            {
                ssize_t n = ws_fd_send(F, response + written,
                                       (size_t)(rlen - written));
                if (n <= 0) goto fail;
                written += n;
            }
        }

        /* Handshake complete */
        ws->keyed = true;
        op_settimeout(F, 0, NULL, NULL);   /* clear handshake timeout */

        /* Fire the registered ACCB */
        if (F->accept)
        {
            ACCB *cb    = F->accept->callback;
            void *cbdata = F->accept->data;
            /* Keep accept->S as the peer address */
            struct sockaddr *addr = (struct sockaddr *)&F->accept->S;
            op_socklen_t     addrlen = F->accept->addrlen;
            op_acceptdata_free(F->accept);   /* acceptdata_free via public API */
            F->accept = NULL;
            cb(F, OP_OK, addr, addrlen, cbdata);
        }
        return;
    }

    /* nread == 0: connection closed during handshake */
    if (nread == 0)
        goto fail;

    /* nread < 0 */
    if (op_ignore_errno(errno))
    {
        op_setselect(F, OP_SELECT_READ, op_ws_handshake_read, NULL);
        return;
    }

fail:
    /* Fire ACCB with error so the caller can clean up the client */
    if (F->accept)
    {
        ACCB *cb     = F->accept->callback;
        void *cbdata = F->accept->data;
        op_acceptdata_free(F->accept);
        F->accept = NULL;
        cb(F, OP_ERROR, NULL, 0, cbdata);
    }
}

static void
op_ws_timeout_cb(op_fde_t *F, void *data)
{
    (void)data;
    ws_state_t *ws = (ws_state_t *)F->ws;
    (void)ws;
    /* Fire accept callback with timeout error */
    if (F->accept)
    {
        ACCB *cb     = F->accept->callback;
        void *cbdata = F->accept->data;
        op_acceptdata_free(F->accept);
        F->accept = NULL;
        cb(F, OP_ERR_TIMEOUT, NULL, 0, cbdata);
    }
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
op_ws_start_accepted(op_fde_t *F, ACCB *cb, void *data, int timeout)
{
    if (!F) return;

    F->type |= OP_FD_WEBSOCKET;

    ws_state_t *ws = ws_alloc();
    F->ws          = ws;

    F->accept           = op_acceptdata_alloc();
    F->accept->callback = cb;
    F->accept->data     = data;
    /* peer address is not available at this point; zero it */
    memset(&F->accept->S, 0, sizeof(F->accept->S));
    F->accept->addrlen  = 0;

    if (timeout > 0)
        op_settimeout(F, timeout, op_ws_timeout_cb, NULL);

    op_setselect(F, OP_SELECT_READ, op_ws_handshake_read, NULL);
}

/*
 * op_ws_read — called by op_read() when OP_FD_WEBSOCKET is set.
 *
 * If there is already decoded IRC text buffered, return it immediately.
 * Otherwise, read raw bytes from the TCP socket, parse WS frames, and
 * return the decoded payload.  Returns EAGAIN if no complete frame yet.
 */
ssize_t
op_ws_read(op_fde_t *F, void *buf, size_t count)
{
    ws_state_t *ws = (ws_state_t *)F->ws;
    if (!ws || !ws->keyed)
    {
        errno = EAGAIN;
        return -1;
    }

    /* Return already-decoded data first */
    if (ws->decoded_len > ws->decoded_pos)
    {
        size_t avail = ws->decoded_len - ws->decoded_pos;
        size_t n     = avail < count ? avail : count;
        memcpy(buf, ws->decoded + ws->decoded_pos, n);
        ws->decoded_pos += n;
        return (ssize_t)n;
    }

    /* Read new raw bytes from the socket (SSL-transparent) */
    char   tcpbuf[WS_READBUF_SIZE];
    ssize_t nread = ws_fd_recv(F, tcpbuf, sizeof(tcpbuf));

    if (nread < 0)
    {
        if (op_ignore_errno(errno))
        {
            errno = EAGAIN;
            return -1;
        }
        return -1;
    }
    if (nread == 0)
        return 0;   /* connection closed */

    /* Append raw bytes to inbuf */
    inbuf_grow(ws, (size_t)nread);
    memcpy(ws->inbuf + ws->inbuf_len, tcpbuf, (size_t)nread);
    ws->inbuf_len += (size_t)nread;

    /* Parse frames */
    if (!ws_parse_frames(F, ws))
    {
        /* Connection should be closed */
        return 0;
    }

    /* Return decoded data if any */
    if (ws->decoded_len > ws->decoded_pos)
    {
        size_t avail = ws->decoded_len - ws->decoded_pos;
        size_t n     = avail < count ? avail : count;
        memcpy(buf, ws->decoded + ws->decoded_pos, n);
        ws->decoded_pos += n;
        return (ssize_t)n;
    }

    /* No complete frame yet */
    errno = EAGAIN;
    return -1;
}

/*
 * op_ws_write — called by op_write() when OP_FD_WEBSOCKET is set.
 *
 * If frame_out already has unwritten data (from a previous call that
 * returned NEED_WRITE), try to flush it.  Otherwise, frame the new
 * plaintext as a WebSocket TEXT frame and try to flush.
 *
 * Returns `count` on success (all plaintext consumed), or
 * OP_RW_SSL_NEED_WRITE if the TCP socket would block.
 */
ssize_t
op_ws_write(op_fde_t *F, const void *buf, size_t count)
{
    ws_state_t *ws = (ws_state_t *)F->ws;
    if (!ws || !ws->keyed)
        return 0;

    /* If there's a pending frame from a previous call, flush it first */
    if (op_rawbuf_length(ws->frame_out) > 0)
    {
        int r = op_rawbuf_flush(ws->frame_out, F);
        if (r < 0 && !op_ignore_errno(errno))
            return OP_RW_IO_ERROR;
        if (op_rawbuf_length(ws->frame_out) > 0)
            return OP_RW_SSL_NEED_WRITE;
        /* Flushed — the caller's `buf` was already framed last time;
         * return count to tell the caller we consumed everything. */
        return (ssize_t)count;
    }

    /* Frame the new plaintext */
    ws_queue_text_frame(ws, (const uint8_t *)buf, count);

    /* Try to flush immediately */
    int r = op_rawbuf_flush(ws->frame_out, F);
    if (r < 0 && !op_ignore_errno(errno))
        return OP_RW_IO_ERROR;

    if (op_rawbuf_length(ws->frame_out) > 0)
        return OP_RW_SSL_NEED_WRITE;

    return (ssize_t)count;
}

/*
 * op_ws_shutdown — called by op_close() when OP_FD_WEBSOCKET is set.
 *
 * Sends a CLOSE frame if we haven't already, frees the WS state.
 */
void
op_ws_shutdown(op_fde_t *F)
{
    ws_state_t *ws = (ws_state_t *)F->ws;
    if (!ws) return;

    if (ws->keyed && !ws->sent_close)
    {
        ws_write_close_frame(ws, WS_CLOSE_NORMAL);
        op_rawbuf_flush(ws->frame_out, F);
    }
    ws_free(ws);
    F->ws = NULL;
}

int
op_fd_ws(const op_fde_t *F)
{
    if (!F) return 0;
    return (F->type & OP_FD_WEBSOCKET) ? 1 : 0;
}

/*
 * op_ws_attach_transferred — attach WebSocket framing to an FD that was
 * transferred from the old binary via SCM_RIGHTS during live migration.
 *
 * The HTTP upgrade handshake already completed in the old binary; we skip
 * it and create a fresh ws_state_t with keyed=true so that subsequent
 * op_read()/op_write() calls transparently frame/deframe RFC 6455.
 *
 */
void
op_ws_attach_transferred(op_fde_t *F)
{
    ws_state_t *ws = ws_alloc();
    ws->keyed  = true;   /* handshake done; skip HTTP upgrade phase */
    F->type   |= OP_FD_WEBSOCKET;
    F->ws      = ws;
}

