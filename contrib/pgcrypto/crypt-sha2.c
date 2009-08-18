/*
 * crypt-sha2.c
 *   SHA256/512-based password hashing.
 *
 * Original code from people.redhat.com/drepper/SHA-crypt.txt:
 *
 *   SHA256-based Unix crypt implementation.
 *   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.
 *
 *   SHA512-based Unix crypt implementation.
 *   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.
 *
 * Combined implementation by Marko Kreen.  Public Domain.
 */

#include "postgres.h"
#include "px.h"
#include "px-crypt.h"

#define ROUNDS_DEFAULT 5000
#define ROUNDS_MIN 1000
#define ROUNDS_MAX 999999999

#define MAXHASH (512/8)

#define SALT_LEN_MAX 16
#define PREFIX_LEN 3
#define ROUNDS_LEN 7

/* $x$rounds=1234567890$salt$result\0 */
#define RESULT256 (PREFIX_LEN + ROUNDS_LEN + 10 + 1 + SALT_LEN_MAX + 1 + 43 + 1 ) /* 80 */
#define RESULT512 (PREFIX_LEN + ROUNDS_LEN + 10 + 1 + SALT_LEN_MAX + 1 + 86 + 1 ) /* 123 */

static const char rounds_prefix[] = "rounds=";
static const char sha256_prefix[] = "$5$";
static const char sha512_prefix[] = "$6$";

/*
 * Hash output
 */

static const char base64map[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

typedef signed char SMap[3];

static const SMap smap1[22] = {
	{ 0,21,42}, {22,43, 1}, {44, 2,23}, { 3,24,45},
	{25,46, 4}, {47, 5,26}, { 6,27,48}, {28,49, 7},
	{50, 8,29}, { 9,30,51}, {31,52,10}, {53,11,32},
	{12,33,54}, {34,55,13}, {56,14,35}, {15,36,57},
	{37,58,16}, {59,17,38}, {18,39,60}, {40,61,19},
	{62,20,41}, {-1,-1,63}
};

static const SMap smap2[11] = {
	{ 0,10,20}, {21, 1,11}, {12,22, 2}, { 3,13,23},
	{24, 4,14}, {15,25, 5}, { 6,16,26}, {27, 7,17},
	{18,28, 8}, { 9,19,29}, {-1,31,30}
};

static char *
splurge(char *cp, const uint8 *hash, int bigsha)
{
	const SMap *map = bigsha ? smap1 : smap2;
	int hashlen = bigsha ? 64 : 32;
	int maplen = (hashlen + 2) / 3;
	int i, j, b, x, w, n;

	for (i = 0; i < maplen; i++)
	{
		w = 0;
		n = 4;
		for (j = 0; j < 3; j++)
		{
			x = map[i][j];
			b = (x >= 0) ? hash[x] : 0;
			w = (w << 8) | b;
			if (x < 0) n--;
		}
		while (n--)
		{
			*cp++ = base64map[w & 0x3f];
			w >>= 6;
		}
	}
	return cp;
}

/*
 * Combined implementation for both sha256 and sha512.
 */

char *
px_crypt_sha2_r(const char *key, const char *salt, char *buffer, int buflen)
{
	PX_MD *ctx = NULL;
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

	/* decide which algorithm to use */
	if (strncmp(salt, sha256_prefix, PREFIX_LEN) == 0)
		bigsha = false;
	else if (strncmp(salt, sha512_prefix, PREFIX_LEN) == 0)
		bigsha = true;
	else
		goto einval;
	if (buflen < (bigsha ? RESULT512 : RESULT256))
		goto erange;
	salt += PREFIX_LEN;

	/* load hash */
	hashname = bigsha ? "sha512" : "sha256";
	hashlen = bigsha ? 512/8 : 256/8;
	if (px_find_digest(hashname, &ctx) < 0)
		goto enomem;

	/* allocate shadow key buffer */
	key_len = strlen(key);
	p_bytes = px_alloc(key_len);
	if (!p_bytes)
	{
		px_md_free(ctx);
		goto enomem;
	}

	/* parse optional rounds= */
	if (strncmp(salt, rounds_prefix, ROUNDS_LEN) == 0)
	{
		const char *num = salt + ROUNDS_LEN;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			salt = endp + 1;
			if (srounds > ROUNDS_MAX)
				srounds = ROUNDS_MAX;
			else if (srounds < ROUNDS_MIN)
				srounds = ROUNDS_MIN;
			rounds = srounds;
		}
		/* set even if parsing failed, to avoid confusion later */
		rounds_custom = true;
	}

	/* set up salt */
	cp = strchr(salt, '$');
	salt_len = cp ? (cp - salt) : strlen(salt);
	if (salt_len > SALT_LEN_MAX)
		salt_len = SALT_LEN_MAX;

	/*
	 * Fill alt_result.  Input: key, salt.
	 */

	px_md_update(ctx, key, key_len);
	px_md_update(ctx, salt, salt_len);
	px_md_update(ctx, key, key_len);
	px_md_finish(ctx, alt_result);

	px_md_reset(ctx);
	px_md_update(ctx, key, key_len);
	px_md_update(ctx, salt, salt_len);

	for (cnt = key_len; cnt > hashlen; cnt -= hashlen)
		px_md_update(ctx, alt_result, hashlen);
	px_md_update(ctx, alt_result, cnt);

	for (cnt = key_len; cnt > 0; cnt >>= 1)
	{
		if ((cnt & 1) != 0)
			px_md_update(ctx, alt_result, hashlen);
		else
			px_md_update(ctx, key, key_len);
	}
	px_md_finish(ctx, alt_result);

	/*
	 * Fill p_bytes.  Input: key.
	 */

	px_md_reset(ctx);
	for (cnt = 0; cnt < key_len; ++cnt)
		px_md_update(ctx, key, key_len);
	px_md_finish(ctx, temp_result);

	cp = p_bytes;
	for (cnt = key_len; cnt >= hashlen; cnt -= hashlen)
	{
		memcpy(cp, temp_result, hashlen);
		cp += hashlen;
	}
	memcpy(cp, temp_result, cnt);

	/*
	 * Fill s_bytes.  Input: alt_result, salt.
	 */

	px_md_reset(ctx);
	for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
		px_md_update(ctx, salt, salt_len);
	px_md_finish(ctx, temp_result);

	cp = s_bytes;
	for (cnt = salt_len; cnt >= hashlen; cnt -= hashlen)
	{
		memcpy(cp, temp_result, hashlen);
		cp += hashlen;
	}
	memcpy(cp, temp_result, cnt);

	/*
	 * Burn cycles.  Input: p_bytes, s_bytes, alt_result.
	 */

	for (cnt = 0; cnt < rounds; ++cnt)
	{
		px_md_reset(ctx);

		if (cnt & 1)
			px_md_update(ctx, p_bytes, key_len);
		else
			px_md_update(ctx, alt_result, hashlen);

		if (cnt % 3)
			px_md_update(ctx, s_bytes, salt_len);
		if (cnt % 7)
			px_md_update(ctx, p_bytes, key_len);

		if (cnt & 1)
			px_md_update(ctx, alt_result, hashlen);
		else
			px_md_update(ctx, p_bytes, key_len);

		px_md_finish(ctx, alt_result);
	}

	/*
	 * Create final output.  Input: rounds, salt, alt_result.
	 */

	/* write prefix */
	memcpy(buffer, bigsha ? sha512_prefix : sha256_prefix, PREFIX_LEN);
	cp = buffer + PREFIX_LEN;
	if (rounds_custom)
	{
		snprintf(cp, buflen - PREFIX_LEN, "%s%u$", rounds_prefix, rounds);
		cp += strlen(cp);
	}

	/* write salt */
	memcpy(cp, salt, salt_len);
	cp += salt_len;
	*cp++ = '$';

	/* write final hash */
	cp = splurge(cp, alt_result, bigsha);
	*cp++ = '\0';

	/* Clear the buffers */
	memset(temp_result, 0, sizeof(temp_result));
	memset(alt_result, 0, sizeof(alt_result));
	memset(p_bytes, 0, key_len);
	memset(s_bytes, 0, salt_len);
	px_free(p_bytes);
	px_md_free(ctx);

	/* Final sanity check */
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

