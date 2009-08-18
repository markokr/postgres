/*
 * Based on:
 *
 *   SHA256-based Unix crypt implementation.
 *   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.
 *
 *   SHA512-based Unix crypt implementation.
 *   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.
 *
 * As published at <http://people.redhat.com/drepper/sha-crypt.html>
 */

#include "postgres.h"
#include "px.h"
#include "px-crypt.h"

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

#define MAXHASH (512/8)

#define PREFIX_LEN 3
#define ROUNDS_LEN 7

/* $x$rounds=1234567890$salt$result\0 */
#define RESULT256 (PREFIX_LEN + ROUNDS_LEN + 10 + 1 + SALT_LEN_MAX + 1 + 43 + 1 ) /* 80 */
#define RESULT512 (PREFIX_LEN + ROUNDS_LEN + 10 + 1 + SALT_LEN_MAX + 1 + 86 + 1 ) /* 123 */

static const char rounds_prefix[] = "rounds=";
static const char sha256_prefix[] = "$5$";
static const char sha512_prefix[] = "$6$";

/* Table with characters for base64 transformation.  */
static const char b64t[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#define b64_from_24bit(B2, B1, B0, N)						\
	do {													\
		unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);	\
		int n = (N);										\
		while (n-- > 0) {									\
			*cp++ = b64t[w & 0x3f];							\
			w >>= 6;										\
		}													\
	} while (0)

#define b64_output(o2, o1, o0, n) \
		b64_from_24bit((o2 < 0) ? 0 : hash[o2], \
					   (o1 < 0) ? 0 : hash[o1], \
					   (o0 < 0) ? 0 : hash[o0], n)

/*
 * Original eeny-meeny-miny-moe algorithm for output encryption.
 */

static char *output_sha512(const uint8 *hash, char *cp)
{
	b64_output( 0, 21, 42, 4);
	b64_output(22, 43,  1, 4);
	b64_output(44,  2, 23, 4);
	b64_output( 3, 24, 45, 4);
	b64_output(25, 46,  4, 4);
	b64_output(47,  5, 26, 4);
	b64_output( 6, 27, 48, 4);
	b64_output(28, 49,  7, 4);
	b64_output(50,  8, 29, 4);
	b64_output( 9, 30, 51, 4);
	b64_output(31, 52, 10, 4);
	b64_output(53, 11, 32, 4);
	b64_output(12, 33, 54, 4);
	b64_output(34, 55, 13, 4);
	b64_output(56, 14, 35, 4);
	b64_output(15, 36, 57, 4);
	b64_output(37, 58, 16, 4);
	b64_output(59, 17, 38, 4);
	b64_output(18, 39, 60, 4);
	b64_output(40, 61, 19, 4);
	b64_output(62, 20, 41, 4);
	b64_output(-1, -1, 63, 2);
	return cp;
}

static char *output_sha256(const uint8 *hash, char *cp)
{
	b64_output( 0, 10, 20, 4);
	b64_output(21,  1, 11, 4);
	b64_output(12, 22,  2, 4);
	b64_output( 3, 13, 23, 4);
	b64_output(24,  4, 14, 4);
	b64_output(15, 25,  5, 4);
	b64_output( 6, 16, 26, 4);
	b64_output(27,  7, 17, 4);
	b64_output(18, 28,  8, 4);
	b64_output( 9, 19, 29, 4);
	b64_output(-1, 31, 30, 3);
	return cp;
}

/* wrap MD to get void * argument */
static void md_update(PX_MD *ctx, const void *data, int len)
{
	px_md_update(ctx, data, len);
}

char *
px_crypt_sha_r(const char *key, const char *salt, char *buffer, int buflen)
{
	PX_MD *ctx = NULL, *alt_ctx = NULL;
	uint8 alt_result[MAXHASH];
	uint8 temp_result[MAXHASH];
	unsigned salt_len;
	unsigned key_len;
	unsigned cnt;
	char *cp;
	char *p_bytes = NULL;
	char s_bytes[SALT_LEN_MAX];
	unsigned rounds = ROUNDS_DEFAULT;
	bool rounds_custom = false;
	unsigned hashlen;
	const char *hashname;
	bool bigsha;

	/* decide which algo to use */
	if (strncmp(salt, sha256_prefix, PREFIX_LEN) == 0)
		bigsha = false;
	else if (strncmp(salt, sha512_prefix, PREFIX_LEN) == 0)
		bigsha = true;
	else
		goto einval;
	salt += 3;

	/* initialize */
	if (buflen < (bigsha ? RESULT512 : RESULT256))
		goto erange;
	hashname = bigsha ? "sha512" : "sha256";
	hashlen = bigsha ? 512/8 : 256/8;
	if (px_find_digest(hashname, &ctx) < 0)
		goto enomem;
	if (px_find_digest(hashname, &alt_ctx) < 0)
	{
		px_md_free(ctx);
		goto enomem;
	}

	/* parse optional rounds= */
	if (strncmp(salt, rounds_prefix, ROUNDS_LEN) == 0)
	{
		const char *num = salt + ROUNDS_LEN;
		char *endp;
		unsigned long int srounds = strtoul (num, &endp, 10);
		if (*endp == '$')
		{
			salt = endp + 1;
			if (srounds > ROUNDS_MAX)
				srounds = ROUNDS_MAX;
			else if (srounds < ROUNDS_MIN)
				srounds = ROUNDS_MIN;
			rounds_custom = true;
			rounds = srounds;
		}
	}

	/* key & salt sizes */
	cp = strchr(salt, '$');
	salt_len = cp ? cp - salt : strlen(salt);
	if (salt_len > SALT_LEN_MAX)
		salt_len = SALT_LEN_MAX;
	key_len = strlen(key);

	/* allocate shadow key buffer */
	p_bytes = palloc(key_len);

	/*
	 * Start real work.
	 */

	/* Add the key string.  */
	md_update(ctx, key, key_len);

	/* The last part is the salt string.  This must be at most 8
	   characters and it ends at the first `$' character (for
	   compatibility with existing implementations).  */
	md_update(ctx, salt, salt_len);

	/* Compute alternate SHA sum with input KEY, SALT, and KEY.  The
	   final result will be added to the first context.  */

	/* Add key.  */
	md_update(alt_ctx, key, key_len);

	/* Add salt.  */
	md_update(alt_ctx, salt, salt_len);

	/* Add key again.  */
	md_update(alt_ctx, key, key_len);

	/* Now get result of this and add it to the other context.  */
	px_md_finish(alt_ctx, alt_result);

	/* Add for any character in the key one byte of the alternate sum.  */
	for (cnt = key_len; cnt > hashlen; cnt -= hashlen)
		md_update(ctx, alt_result, hashlen);
	md_update(ctx, alt_result, cnt);

	/* Take the binary representation of the length of the key and for every
	   1 add the alternate sum, for every 0 the key.  */
	for (cnt = key_len; cnt > 0; cnt >>= 1)
	{
		if ((cnt & 1) != 0)
			md_update(ctx, alt_result, hashlen);
		else
			md_update(ctx, key, key_len);
	}

	/* Create intermediate result.  */
	px_md_finish(ctx, alt_result);

	/* Start computation of P byte sequence.  */
	px_md_reset(alt_ctx);

	/* For every character in the password add the entire password.  */
	for (cnt = 0; cnt < key_len; ++cnt)
		md_update(alt_ctx, key, key_len);

	/* Finish the digest.  */
	px_md_finish(alt_ctx, temp_result);

	/* Create byte sequence P.  */
	cp = p_bytes;
	for (cnt = key_len; cnt >= hashlen; cnt -= hashlen)
	{
		memcpy (cp, temp_result, hashlen);
		cp += hashlen;
	}
	memcpy(cp, temp_result, cnt);

	/* Start computation of S byte sequence.  */
	px_md_reset(alt_ctx);

	/* For DS - add salt */
	for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
		md_update(alt_ctx, salt, salt_len);

	/* Finish the digest.  */
	px_md_finish(alt_ctx, temp_result);

	/* Create byte sequence S.  */
	cp = s_bytes;
	for (cnt = salt_len; cnt >= hashlen; cnt -= hashlen)
	{
		memcpy(cp, temp_result, hashlen);
		cp += hashlen;
	}
	memcpy(cp, temp_result, cnt);

	/* Repeatedly run the collected hash value through SHA to burn
	   CPU cycles.  */
	for (cnt = 0; cnt < rounds; ++cnt)
	{
		/* New context.  */
		px_md_reset(ctx);

		/* Add key or last result.  */
		if ((cnt & 1) != 0)
			md_update(ctx, p_bytes, key_len);
		else
			md_update(ctx, alt_result, hashlen);

		/* Add salt for numbers not divisible by 3.  */
		if (cnt % 3 != 0)
			md_update(ctx, s_bytes, salt_len);

		/* Add key for numbers not divisible by 7.  */
		if (cnt % 7 != 0)
			md_update(ctx, p_bytes, key_len);

		/* Add key or last result.  */
		if ((cnt & 1) != 0)
			md_update(ctx, alt_result, hashlen);
		else
			md_update(ctx, p_bytes, key_len);

		/* Create intermediate result.  */
		px_md_finish(ctx, alt_result);
	}

	/* Now we can construct the result string. */

	memcpy(buffer, bigsha ? sha512_prefix : sha256_prefix, PREFIX_LEN);
	cp = buffer + PREFIX_LEN;
	if (rounds_custom)
	{
		sprintf(cp, "%s%u$", rounds_prefix, rounds);
		cp += strlen(cp);
	}
	memcpy(cp, salt, salt_len);
	cp += salt_len;
	*cp++ = '$';
	if (bigsha)
		cp = output_sha512(alt_result, cp);
	else
		cp = output_sha256(alt_result, cp);
	*cp++ = 0;

	/* Clear the buffer for the intermediate result so that people
	   attaching to processes or reading core dumps cannot get any
	   information. */
	px_md_free(ctx);
	px_md_free(alt_ctx);
	memset(temp_result, 0, sizeof(temp_result));
	memset(alt_result, 0, sizeof(alt_result));
	memset(p_bytes, 0, key_len);
	memset(s_bytes, 0, salt_len);
	pfree(p_bytes);

	/* last sanity check */
	if (cp > buffer + buflen)
		goto erange;

	return buffer;

erange:
	errno = ERANGE;
	return NULL;
enomem:
	errno = ENOMEM;
	return NULL;
einval:
	errno = EINVAL;
	return NULL;
}

