/*
 * openssl.c
 *		Wrapper for OpenSSL library.
 *
 * Copyright (c) 2001 Marko Kreen
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
 * contrib/pgcrypto/openssl.c
 */

#include "postgres.h"

#include "px.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/*
 * Max lengths we might want to handle.
 */
#define MAX_KEY		(512/8)

/*
 * Provide SHA2 for older OpenSSL < 0.9.8
 */
#if OPENSSL_VERSION_NUMBER < 0x00908000L

#include "sha2.c"
#include "internal-sha2.c"

typedef void (*init_f) (PX_MD *md);

static int
compat_find_digest(const char *name, PX_MD **res)
{
	init_f		init = NULL;

	if (pg_strcasecmp(name, "sha224") == 0)
		init = init_sha224;
	else if (pg_strcasecmp(name, "sha256") == 0)
		init = init_sha256;
	else if (pg_strcasecmp(name, "sha384") == 0)
		init = init_sha384;
	else if (pg_strcasecmp(name, "sha512") == 0)
		init = init_sha512;
	else
		return PXE_NO_HASH;

	*res = px_alloc(sizeof(PX_MD));
	init(*res);
	return 0;
}
#else
#define compat_find_digest(name, res)  (PXE_NO_HASH)
#endif

/*
 * Hashes
 */

typedef struct OSSLDigest
{
	const EVP_MD *algo;
	EVP_MD_CTX	ctx;
} OSSLDigest;

static unsigned
digest_result_size(PX_MD *h)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	return EVP_MD_CTX_size(&digest->ctx);
}

static unsigned
digest_block_size(PX_MD *h)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	return EVP_MD_CTX_block_size(&digest->ctx);
}

static void
digest_reset(PX_MD *h)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	EVP_DigestInit_ex(&digest->ctx, digest->algo, NULL);
}

static void
digest_update(PX_MD *h, const uint8 *data, unsigned dlen)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	EVP_DigestUpdate(&digest->ctx, data, dlen);
}

static void
digest_finish(PX_MD *h, uint8 *dst)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	EVP_DigestFinal_ex(&digest->ctx, dst, NULL);
}

static void
digest_free(PX_MD *h)
{
	OSSLDigest *digest = (OSSLDigest *) h->p.ptr;

	EVP_MD_CTX_cleanup(&digest->ctx);

	px_free(digest);
	px_free(h);
}

static int	px_openssl_initialized = 0;

/* PUBLIC functions */

int
px_find_digest(const char *name, PX_MD **res)
{
	const EVP_MD *md;
	PX_MD	   *h;
	OSSLDigest *digest;

	if (!px_openssl_initialized)
	{
		px_openssl_initialized = 1;
		OpenSSL_add_all_algorithms();
	}

	md = EVP_get_digestbyname(name);
	if (md == NULL)
		return compat_find_digest(name, res);

	digest = px_alloc(sizeof(*digest));
	digest->algo = md;

	EVP_MD_CTX_init(&digest->ctx);
	if (EVP_DigestInit_ex(&digest->ctx, digest->algo, NULL) == 0)
		return -1;

	h = px_alloc(sizeof(*h));
	h->result_size = digest_result_size;
	h->block_size = digest_block_size;
	h->reset = digest_reset;
	h->update = digest_update;
	h->finish = digest_finish;
	h->free = digest_free;
	h->p.ptr = (void *) digest;

	*res = h;
	return 0;
}

/*
 * Ciphers
 */

struct OSSLInfo
{
	const char *name;
	int mode;
	int max_key;
	int block_size;
	int (*init)(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv, int enc);
};

struct OSSLContext
{
	const EVP_CIPHER *ciph;
	const struct OSSLInfo *info;
	EVP_CIPHER_CTX ctx;
};

typedef struct OSSLContext OSSLContext;

/* generic */

static unsigned
gen_ossl_block_size(PX_Cipher *c)
{
	OSSLContext *octx = c->ptr;

	return octx->info->block_size;
}

static unsigned
gen_ossl_key_size(PX_Cipher *c)
{
	OSSLContext *octx = c->ptr;

	return octx->info->max_key;
}

static unsigned
gen_ossl_iv_size(PX_Cipher *c)
{
	OSSLContext *octx = c->ptr;

	return octx->info->block_size;
}

static int
gen_ossl_encrypt(PX_Cipher *c, const uint8 *data, unsigned dlen, uint8 *res)
{
	OSSLContext *octx = c->ptr;
	int reslen = 0;
	int ok;

	ok = EVP_EncryptUpdate(&octx->ctx, res, &reslen, data, dlen);
	if (!ok || reslen != dlen)
		return -1;
	return 0;
}

static int
gen_ossl_decrypt(PX_Cipher *c, const uint8 *data, unsigned dlen, uint8 *res)
{
	OSSLContext *octx = c->ptr;
	int reslen = 0;
	int ok;

	ok = EVP_DecryptUpdate(&octx->ctx, res, &reslen, data, dlen);
	if (!ok || reslen != dlen)
		return -1;
	return 0;
}

static void
gen_ossl_free(PX_Cipher *c)
{
	OSSLContext *octx = c->ptr;

	EVP_CIPHER_CTX_cleanup(&octx->ctx);
	px_free(octx);
	px_free(c);
}

static int
gen_ossl_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv, int enc)
{
	OSSLContext *octx = c->ptr;
	uint8 keybuf[MAX_KEY];
	int ok;
	int err = PXE_KEY_TOO_BIG;

	if (klen < 1 || klen > octx->info->max_key)
		return PXE_KEY_TOO_BIG;

	if (!octx->ciph)
	{
		octx->ciph = EVP_get_cipherbyname(octx->info->name);
		if (!octx->ciph)
			return PXE_NO_CIPHER;
	}

	memset(keybuf, 0, sizeof(keybuf));
	memcpy(keybuf, key, klen);

	/* set up initial context */
	ok = EVP_CipherInit_ex(&octx->ctx, octx->ciph, NULL, NULL, NULL, enc);
	if (!ok)
		goto failed;

	/* disable padding */
	ok = EVP_CIPHER_CTX_set_padding(&octx->ctx, 0);
	if (!ok)
		goto failed;

	/* set actual key length */
	if (EVP_CIPHER_flags(octx->ciph) & EVP_CIPH_VARIABLE_LENGTH)
	{
		ok = EVP_CIPHER_CTX_set_key_length(&octx->ctx, klen);
		if (!ok)
			goto failed;
	}

	/* set actual key & iv */
	ok = EVP_CipherInit_ex(&octx->ctx, NULL, NULL, keybuf, iv, -1);
	if (!ok)
		goto failed;

	memset(keybuf, 0, sizeof(keybuf));
	return 0;

failed:
	/* should we map ossl errors to PXE errors? */
	memset(keybuf, 0, sizeof(keybuf));
	return err;
}

/* EVP has split AES to 3 ciphers */
static int
init_aes(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv, int enc)
{
	OSSLContext *octx = c->ptr;
	const char *name;
	int cbc = octx->info->mode == EVP_CIPH_CBC_MODE;

	if (klen <= 128/8)
		name = cbc ? "aes-128-cbc" : "aes-128-ecb";
	else if (klen <= 192/8)
		name = cbc ? "aes-192-cbc" : "aes-192-ecb";
	else if (klen <= 256/8)
		name = cbc ? "aes-256-cbc" : "aes-256-ecb";
	else
		return PXE_KEY_TOO_BIG;

	octx->ciph = EVP_get_cipherbyname(name);
	if (!octx->ciph)
		return PXE_NO_CIPHER;

	return gen_ossl_init(c, key, klen, iv, enc);
}

/* OpenSSL has split Camellia to 3 ciphers */
static int
init_camellia(PX_Cipher * c, const uint8 *key, unsigned klen, const uint8 *iv, int enc)
{
	OSSLContext *octx = c->ptr;
	const char *name;
	int cbc = octx->info->mode == EVP_CIPH_CBC_MODE;

	if (klen <= 128/8)
		name = cbc ? "camellia-128-cbc" : "camellia-128-ecb";
	else if (klen <= 192/8)
		name = cbc ? "camellia-192-cbc" : "camellia-192-ecb";
	else if (klen <= 256/8)
		name = cbc ? "camellia-256-cbc" : "camellia-256-ecb";
	else
		return PXE_KEY_TOO_BIG;

	octx->ciph = EVP_get_cipherbyname(name);
	if (!octx->ciph)
		return PXE_NO_CIPHER;

	return gen_ossl_init(c, key, klen, iv, enc);
}

/* EVP does not know des3_ecb */
static int
init_des3_ecb(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv, int enc)
{
	OSSLContext *octx = c->ptr;

	octx->ciph = EVP_des_ede3_ecb();
	if (!octx->ciph)
		return PXE_NO_CIPHER;

	return gen_ossl_init(c, key, klen, iv, enc);
}

/*
 * aliases
 */

static const PX_Alias ossl_aliases[] = {
	{"bf", "bf-cbc"},
	{"blowfish", "bf-cbc"},
	{"blowfish-cbc", "bf-cbc"},
	{"blowfish-ecb", "bf-ecb"},
	{"blowfish-cfb", "bf-cfb"},
	{"des", "des-cbc"},
	{"3des", "des-ede3-cbc"},
	{"3des-ecb", "des-ede3-ecb"},
	{"3des-cbc", "des-ede3-cbc"},
	{"des3", "des-ede3-cbc"},
	{"des3-ecb", "des-ede3-ecb"},
	{"des3-cbc", "des-ede3-cbc"},
	{"cast5", "cast5-cbc"},
	{"aes", "aes-cbc"},
	{"rijndael", "aes-cbc"},
	{"rijndael-cbc", "aes-cbc"},
	{"rijndael-ecb", "aes-ecb"},
	{"camellia", "camellia-cbc"},
	{NULL}
};

static const struct OSSLInfo info_list[] = {
	{ "aes-ecb", EVP_CIPH_ECB_MODE, 256/8, 128/8, init_aes },
	{ "aes-cbc", EVP_CIPH_CBC_MODE, 256/8, 128/8, init_aes },
	{ "bf-ecb", EVP_CIPH_ECB_MODE, 448/8, 64/8 },
	{ "bf-cbc", EVP_CIPH_CBC_MODE, 448/8, 64/8 },
	{ "des-ecb", EVP_CIPH_ECB_MODE, 64/8, 64/8 },
	{ "des-cbc", EVP_CIPH_CBC_MODE, 64/8, 64/8 },
	{ "des-ede3-ecb", EVP_CIPH_ECB_MODE, 192/8, 64/8, init_des3_ecb },
	{ "des-ede3-cbc", EVP_CIPH_CBC_MODE, 192/8, 64/8 },
	{ "cast5-ecb", EVP_CIPH_ECB_MODE, 128/8, 64/8 },
	{ "cast5-cbc", EVP_CIPH_CBC_MODE, 128/8, 64/8 },
	{ "camellia-ecb", EVP_CIPH_ECB_MODE, 256/8, 128/8, init_camellia },
	{ "camellia-cbc", EVP_CIPH_CBC_MODE, 256/8, 128/8, init_camellia },
	{ NULL },
};

/* PUBLIC functions */

int
px_find_cipher(const char *name, PX_Cipher **res)
{
	PX_Cipher  *c = NULL;
	OSSLContext   *octx;
	const struct OSSLInfo *info;

	if (!px_openssl_initialized)
	{
		px_openssl_initialized = 1;
		OpenSSL_add_all_algorithms();
	}

	name = px_resolve_alias(ossl_aliases, name);
	for (info = info_list; info->name; info++)
	{
		if (strcmp(name, info->name) == 0)
			break;
	}
	if (!info->name)
		return PXE_NO_CIPHER;

	octx = px_alloc(sizeof(*octx));
	memset(octx, 0, sizeof(*octx));
	octx->info = info;
	EVP_CIPHER_CTX_init(&octx->ctx);

	c = px_alloc(sizeof(*c));
	c->block_size = gen_ossl_block_size;
	c->key_size = gen_ossl_key_size;
	c->iv_size = gen_ossl_iv_size;
	c->free = gen_ossl_free;
	c->init = info->init ? info->init : gen_ossl_init;
	c->encrypt = gen_ossl_encrypt;
	c->decrypt = gen_ossl_decrypt;
	c->ptr = octx;

	*res = c;
	return 0;
}


static int	openssl_random_init = 0;

/*
 * OpenSSL random should re-feeded occasionally. From /dev/urandom
 * preferably.
 */
static void
init_openssl_rand(void)
{
	if (RAND_get_rand_method() == NULL)
		RAND_set_rand_method(RAND_SSLeay());
	openssl_random_init = 1;
}

int
px_get_random_bytes(uint8 *dst, unsigned count)
{
	int			res;

	if (!openssl_random_init)
		init_openssl_rand();

	res = RAND_bytes(dst, count);
	if (res == 1)
		return count;

	return PXE_OSSL_RAND_ERROR;
}

int
px_get_pseudo_random_bytes(uint8 *dst, unsigned count)
{
	int			res;

	if (!openssl_random_init)
		init_openssl_rand();

	res = RAND_pseudo_bytes(dst, count);
	if (res == 0 || res == 1)
		return count;

	return PXE_OSSL_RAND_ERROR;
}

int
px_add_entropy(const uint8 *data, unsigned count)
{
	if (!openssl_random_init)
		init_openssl_rand();

	/*
	 * estimate 0 bits
	 */
	RAND_add(data, count, 0);
	return 0;
}
