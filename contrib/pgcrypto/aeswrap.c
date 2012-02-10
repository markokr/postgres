/*
 * aeswrap.c
 *		AES-based key wrapping (RFC3394)
 *
 * Copyright (c) 2012 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * contrib/pgcrypto/aeswrap.c
 */

/*
 * AES Key Wrap is special cipher mode to hide small but important data.
 *
 * Differences from regular cipher modes (CBC/CFB):
 * - Repeatedly encrypts whole data.
 * - One AES block (16 bytes) is split into 2 halfs:
 *   upper half contains IV and will get block number
 *   XOR'ed into it, lower half contains data.
 *
 * This results in every bit affecting whole result,
 * and makes checksum possible, to see if unwrap
 * resulted in valid data.
 */

#include "postgres.h"
#include "px.h"
#include "aeswrap.h"

/* for ntohl/htonl */
#include <netinet/in.h>
#include <arpa/inet.h>



/* Fixed initial value */
#define IV  UINT64CONST(0xA6A6A6A6A6A6A6A6)

/* AES-WRAP operates on 64-bit blocks */
#define AW_SLOT 8

/* AES operates in 128-bit blocks */
#define AW_BLOCK 16

/* shortcuts */
#define A (u.ab[0])
#define B (u.ab[1])
#define AB (u.bytes)


/* convert native int to big-endian */
static uint64 cpu2be64(uint64 v)
{
#ifndef WORDS_BIGENDIAN
	v = ((uint64)(ntohl(v)) << 32) | ntohl(v >> 32);
#endif
	return v;
}


/*
 * Wrap source data.
 *
 * source is assumed to be 8-byte multiple,
 * but is zero-filled otherwise.
 *
 * dst should have room for additional 8-byte checksum.
 */
int
px_aes_wrap(const uint8 *src, int len,
			const uint8 *key, int klen,
			uint8 *dst, int dlen)
{
	union
	{
		uint64 ab[2];
		uint8 bytes[AW_BLOCK];
	} u;
	PX_Cipher *c;
	uint64 *r = NULL;
	int nslots;
	int i, j;
	int res;
	unsigned counter;

	nslots = (len + AW_SLOT - 1) / AW_SLOT;

	/* check sanity */
	if (nslots <= 0)
		return PXE_ARGUMENT_ERROR;
	if (dlen < (nslots + 1) * AW_SLOT)
		return PXE_ARGUMENT_ERROR;

	/* init cipher */
	res = px_find_cipher("aes-ecb", &c);
	if (res < 0)
		return res;
	res = px_cipher_init(c, key, klen, NULL, PX_ENCRYPT);
	if (res < 0)
		goto fail;

	/* set up work area */
	counter = 1;
	A = IV;
	r = px_alloc(nslots * AW_SLOT);
	r[nslots - 1] = 0;
	memcpy(r, src, len);

	/* process data repeatedly */
	for (j = 0; j < 6; j++)
	{
		for (i = 0; i < nslots; i++)
		{
			B = r[i];
			res = px_cipher_encrypt(c, AB, AW_BLOCK, AB);
			if (res < 0)
				goto fail;
			A ^= cpu2be64(counter++);
			r[i] = B;
		}
	}

	/* copy result, return length */
	memcpy(dst, AB, AW_SLOT);
	memcpy(dst + AW_SLOT, r, nslots * AW_SLOT);
	res = AW_SLOT + nslots * AW_SLOT;

fail:
	if (c)
		px_cipher_free(c);
	if (r)
	{
		memset(r, 0, nslots * AW_SLOT);
		px_free(r);
		memset(&u, 0, AW_BLOCK);
	}
	return res;
}


/*
 * Unwrap key data.
 *
 * dst should have room for (srclen - 8) bytes.
 */
int
px_aes_unwrap(const uint8 *src, int len,
			  const uint8 *key, int klen,
			  uint8 *dst, int dlen)
{
	union
	{
		uint64 ab[2];
		uint8 bytes[AW_BLOCK];
	} u;
	PX_Cipher *c;
	uint64 *r = NULL;
	int nslots;
	int i, j;
	int res;
	unsigned counter;

	nslots = (len / AW_SLOT) - 1;

	/* check sanity */
	if (len < 16 || len != (nslots + 1) * 8)
		return PXE_NOTBLOCKSIZE;
	if (dlen < nslots * 8)
		return PXE_ARGUMENT_ERROR;

	/* init cipher */
	res = px_find_cipher("aes-ecb", &c);
	if (res < 0)
		return res;
	res = px_cipher_init(c, key, klen, NULL, PX_DECRYPT);
	if (res < 0)
		goto fail;

	/* set up work area */
	counter = nslots * 6;
	memcpy(u.bytes, src, AW_SLOT);
	r = px_alloc(nslots * AW_SLOT);
	memcpy(r, src + AW_SLOT, nslots * AW_SLOT);

	/* reverse of aes-wrap */
	for (j = 5; j >= 0; j--)
	{
		for (i = nslots - 1; i >= 0; i--)
		{
			A ^= cpu2be64(counter--);
			B = r[i];
			res = px_cipher_decrypt(c, AB, AW_BLOCK, AB);
			if (res < 0)
				goto fail;
			r[i] = B;
		}
	}

	/* iv must match */
	res = PXE_PGP_WRONG_KEY;
	if (A != IV)
		goto fail;

	/* copy data, return length */
	memcpy(dst, r, nslots * AW_SLOT);
	res = nslots * AW_SLOT;

fail:
	if (c)
		px_cipher_free(c);
	if (r)
	{
		memset(r, 0, nslots * AW_SLOT);
		px_free(r);
		memset(&u, 0, sizeof(u));
	}
	return res;
}
