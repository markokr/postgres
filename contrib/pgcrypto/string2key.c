/*
 * string2key.c
 *    String to binary key algorithms.
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
 * contrib/pgcrypto/string2key.c
 */

/*
 * Current algorithms:
 *
 *		PBKDF1 & PBKDF2 from RFC2898
 */

#include "postgres.h"

#include "px.h"

static int
pbkdf1(const char *algo,
	   const uint8_t *psw, unsigned psw_len,
	   const uint8_t *salt, unsigned salt_len,
	   unsigned int count,
	   uint8_t *key, unsigned key_len)
{
	PX_MD *h = NULL;
	unsigned hlen;
	uint8_t *hbuf;
	unsigned i;
	int err;

	err = px_find_digest(algo, &h);
	if (err)
		return err;
	hlen = px_md_result_size(h);
	hbuf = px_alloc(hlen);

	px_md_update(h, psw, psw_len);
	px_md_update(h, salt, salt_len);
	px_md_finish(h, hbuf);

	for (i = 1; i < count; i++)
	{
		px_md_reset(h);
		px_md_update(h, hbuf, hlen);
		px_md_finish(h, hbuf);
	}
	memcpy(key, hbuf, key_len);
	px_md_free(h);
	memset(hbuf, 0, hlen);
	px_free(hbuf);
	return 0;
}

static int
pbkdf2(const char *algo,
	   const uint8_t *psw, unsigned psw_len,
	   const uint8_t *salt, unsigned salt_len,
	   unsigned int count,
	   uint8_t *key, unsigned key_len)
{
	PX_HMAC *h = NULL;
	unsigned hlen;
	uint8_t *hbuf, *hsum;
	uint8_t nbuf[4];
	unsigned i, j, c;
	int err;

	err = px_find_hmac(algo, &h);
	if (err)
		return err;
	px_hmac_init(h, psw, psw_len);
	hlen = px_hmac_result_size(h);
	hbuf = px_alloc(hlen);
	hsum = px_alloc(hlen);

	for (i = 1; key_len > 0; i++)
	{
		/* U[0] = PRF(P, S || INT_msb(i)) */
		px_hmac_update(h, salt, salt_len);
		nbuf[0] = i >> 24;
		nbuf[1] = i >> 16;
		nbuf[2] = i >> 8;
		nbuf[3] = i;
		px_hmac_update(h, nbuf, 4);
		px_hmac_finish(h, hbuf);
		px_hmac_reset(h);
		memcpy(hsum, hbuf, hlen);

		for (c = 1; c < count; c++)
		{
			/* U[c] = PRF(P, U[c-1]) */
			px_hmac_update(h, hbuf, hlen);
			px_hmac_finish(h, hbuf);
			px_hmac_reset(h);

			/* F = U1 ^ U2 ^ ... */
			for (j = 0; j < hlen; j++)
				hsum[j] ^= hbuf[j];
		}

		if (key_len > hlen)
		{
			memcpy(key, hsum, hlen);
			key += hlen;
			key_len -= hlen;
		}
		else
		{
			memcpy(key, hsum, key_len);
			break;
		}
	}
	px_hmac_free(h);
	memset(hbuf, 0, hlen);
	memset(hsum, 0, hlen);
	px_free(hbuf);
	px_free(hsum);
	return 0;
}

/*
 * Map algorithm name to implementation.
 */
int
px_string_to_key(const char *algo,
				 const void *psw, int psw_len,
				 const void *salt, int salt_len,
				 int count,
				 void *key, int key_len)
{
	if (count <= 0)
		return PXE_BAD_SALT_ROUNDS;
	if (psw_len < 0 || salt_len < 0 || key_len < 0)
		return PXE_ARGUMENT_ERROR;
	if (strcmp(algo, "pbkdf2") == 0)
		return pbkdf2("sha1", psw, psw_len, salt, salt_len, count, key, key_len);
	if (strncmp(algo, "pbkdf2-", 7) == 0)
		return pbkdf2(algo+7, psw, psw_len, salt, salt_len, count, key, key_len);
	if (strcmp(algo, "pbkdf1") == 0)
		return pbkdf1("sha1", psw, psw_len, salt, salt_len, count, key, key_len);
	if (strncmp(algo, "pbkdf1-", 7) == 0)
		return pbkdf1(algo+7, psw, psw_len, salt, salt_len, count, key, key_len);
	return PXE_NO_HASH;
}

