/*
 * pgp-mpi-internal.c
 *	  OpenPGP MPI functions.
 *
 * Copyright (c) 2005 Marko Kreen
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
 * contrib/pgcrypto/pgp-mpi-internal.c
 */
#include "postgres.h"

#include "imath.h"

#include "px.h"
#include "mbuf.h"
#include "pgp.h"

static mpz_t *
mp_new(void)
{
	mpz_t	   *mp = mp_int_alloc();

	if (mp_int_init_size(mp, 256) == MP_OK)
		return mp;
	mp_int_free(mp);
	return NULL;
}

static void
mp_clear_free(mpz_t *a)
{
	if (!a)
		return;
	if (a->digits)
		memset(a->digits, 0, a->alloc * sizeof(mp_digit));
	mp_int_free(a);
}

static mpz_t *
mp_new_value(const uint8 *data, int bytes)
{
	mpz_t *mp = mp_new();
	if (!mp)
		return NULL;
	if (mp_int_read_unsigned(mp, (uint8*)data, bytes) != MP_OK)
	{
		mp_clear_free(mp);
		return NULL;
	}
	return mp;
}

/* check if bit is set in mp value */
static unsigned int
mp_test_bit(mpz_t *mp, unsigned int bit)
{
	unsigned int d, b;
	d = bit / MP_DIGIT_BIT;
	b = bit % MP_DIGIT_BIT;
	if (d >= MP_USED(mp))
		return 0;
	return (mp->digits[d] & (1 << b)) > 0;
}

static int
mp_px_rand(uint32 bits, mpz_t *res, int top_one)
{
	int			err;
	unsigned	bytes = (bits + 7) / 8;
	int			last_bits = bits & 7;
	uint8	   *buf;

	buf = px_alloc(bytes);
	err = px_get_random_bytes(buf, bytes);
	if (err < 0)
	{
		px_free(buf);
		return err;
	}

	/* clear unnecessary bits and set last bit to one */
	if (last_bits)
	{
		buf[0] >>= 8 - last_bits;
		if (top_one)
			buf[0] |= 1 << (last_bits - 1);
	}
	else if (top_one)
		buf[0] |= 1 << 7;

	mp_int_read_unsigned(res, buf, bytes);

	px_free(buf);

	return 0;
}

static void
mp_modmul(mpz_t *a, mpz_t *b, mpz_t *p, mpz_t *res)
{
	mpz_t	   *tmp = mp_new();

	mp_int_mul(a, b, tmp);
	mp_int_mod(tmp, p, res);
	mp_clear_free(tmp);
}

static mpz_t *
mpi_to_bn(PGP_MPI *n)
{
	mpz_t	   *bn = mp_new();

	mp_int_read_unsigned(bn, n->data, n->bytes);

	if (!bn)
		return NULL;
	if (mp_int_count_bits(bn) != n->bits)
	{
		px_debug("mpi_to_bn: bignum conversion failed: mpi=%d, bn=%d",
				 n->bits, mp_int_count_bits(bn));
		mp_clear_free(bn);
		return NULL;
	}
	return bn;
}

static PGP_MPI *
bn_to_mpi(mpz_t *bn)
{
	int			res;
	PGP_MPI    *n;
	int			bytes;

	res = pgp_mpi_alloc(mp_int_count_bits(bn), &n);
	if (res < 0)
		return NULL;

	bytes = (mp_int_count_bits(bn) + 7) / 8;
	if (bytes != n->bytes)
	{
		px_debug("bn_to_mpi: bignum conversion failed: bn=%d, mpi=%d",
				 bytes, n->bytes);
		pgp_mpi_free(n);
		return NULL;
	}
	mp_int_to_unsigned(bn, n->data, n->bytes);
	return n;
}

/*
 * Decide the number of bits in the random componont k
 *
 * It should be in the same range as p for signing (which
 * is deprecated), but can be much smaller for encrypting.
 *
 * Until I research it further, I just mimic gpg behaviour.
 * It has a special mapping table, for values <= 5120,
 * above that it uses 'arbitrary high number'.	Following
 * algorihm hovers 10-70 bits above gpg values.  And for
 * larger p, it uses gpg's algorihm.
 *
 * The point is - if k gets large, encryption will be
 * really slow.  It does not matter for decryption.
 */
static int
decide_k_bits(int p_bits)
{
	if (p_bits <= 5120)
		return p_bits / 10 + 160;
	else
		return (p_bits / 8 + 200) * 3 / 2;
}

int
pgp_elgamal_encrypt(PGP_PubKey *pk, PGP_MPI *_m,
					PGP_MPI **c1_p, PGP_MPI **c2_p)
{
	int			res = PXE_PGP_MATH_FAILED;
	int			k_bits;
	mpz_t	   *m = mpi_to_bn(_m);
	mpz_t	   *p = mpi_to_bn(pk->pub.elg.p);
	mpz_t	   *g = mpi_to_bn(pk->pub.elg.g);
	mpz_t	   *y = mpi_to_bn(pk->pub.elg.y);
	mpz_t	   *k = mp_new();
	mpz_t	   *yk = mp_new();
	mpz_t	   *c1 = mp_new();
	mpz_t	   *c2 = mp_new();

	if (!m || !p || !g || !y || !k || !yk || !c1 || !c2)
		goto err;

	/*
	 * generate k
	 */
	k_bits = decide_k_bits(mp_int_count_bits(p));
	res = mp_px_rand(k_bits, k, 1);
	if (res < 0)
		return res;

	/*
	 * c1 = g^k c2 = m * y^k
	 */
	mp_int_exptmod(g, k, p, c1);
	mp_int_exptmod(y, k, p, yk);
	mp_modmul(m, yk, p, c2);

	/* result */
	*c1_p = bn_to_mpi(c1);
	*c2_p = bn_to_mpi(c2);
	if (*c1_p && *c2_p)
		res = 0;
err:
	mp_clear_free(c2);
	mp_clear_free(c1);
	mp_clear_free(yk);
	mp_clear_free(k);
	mp_clear_free(y);
	mp_clear_free(g);
	mp_clear_free(p);
	mp_clear_free(m);
	return res;
}

int
pgp_elgamal_decrypt(PGP_PubKey *pk, PGP_MPI *_c1, PGP_MPI *_c2,
					PGP_MPI **msg_p)
{
	int			res = PXE_PGP_MATH_FAILED;
	mpz_t	   *c1 = mpi_to_bn(_c1);
	mpz_t	   *c2 = mpi_to_bn(_c2);
	mpz_t	   *p = mpi_to_bn(pk->pub.elg.p);
	mpz_t	   *x = mpi_to_bn(pk->sec.elg.x);
	mpz_t	   *c1x = mp_new();
	mpz_t	   *div = mp_new();
	mpz_t	   *m = mp_new();

	if (!c1 || !c2 || !p || !x || !c1x || !div || !m)
		goto err;

	/*
	 * m = c2 / (c1^x)
	 */
	mp_int_exptmod(c1, x, p, c1x);
	mp_int_invmod(c1x, p, div);
	mp_modmul(c2, div, p, m);

	/* result */
	*msg_p = bn_to_mpi(m);
	if (*msg_p)
		res = 0;
err:
	mp_clear_free(m);
	mp_clear_free(div);
	mp_clear_free(c1x);
	mp_clear_free(x);
	mp_clear_free(p);
	mp_clear_free(c2);
	mp_clear_free(c1);
	return res;
}

int
pgp_rsa_encrypt(PGP_PubKey *pk, PGP_MPI *_m, PGP_MPI **c_p)
{
	int			res = PXE_PGP_MATH_FAILED;
	mpz_t	   *m = mpi_to_bn(_m);
	mpz_t	   *e = mpi_to_bn(pk->pub.rsa.e);
	mpz_t	   *n = mpi_to_bn(pk->pub.rsa.n);
	mpz_t	   *c = mp_new();

	if (!m || !e || !n || !c)
		goto err;

	/*
	 * c = m ^ e
	 */
	mp_int_exptmod(m, e, n, c);

	*c_p = bn_to_mpi(c);
	if (*c_p)
		res = 0;
err:
	mp_clear_free(c);
	mp_clear_free(n);
	mp_clear_free(e);
	mp_clear_free(m);
	return res;
}

int
pgp_rsa_decrypt(PGP_PubKey *pk, PGP_MPI *_c, PGP_MPI **m_p)
{
	int			res = PXE_PGP_MATH_FAILED;
	mpz_t	   *c = mpi_to_bn(_c);
	mpz_t	   *d = mpi_to_bn(pk->sec.rsa.d);
	mpz_t	   *n = mpi_to_bn(pk->pub.rsa.n);
	mpz_t	   *m = mp_new();

	if (!m || !d || !n || !c)
		goto err;

	/*
	 * m = c ^ d
	 */
	mp_int_exptmod(c, d, n, m);

	*m_p = bn_to_mpi(m);
	if (*m_p)
		res = 0;
err:
	mp_clear_free(m);
	mp_clear_free(n);
	mp_clear_free(d);
	mp_clear_free(c);
	return res;
}


/*
 * ECDH - Elliptic Curve Diffie-Hellman
 *
 * EC math from RFC6090
 * ECDH from draft-jivsov-openpgp-ecc-08
 * Curve data from FIPS 186-3
 */

/* max bytes in constants */
#define EC_MAXFIELD ((521 + 7) / 8)

/* temp vars, last one is reserved to modular arithmetic helpers */
#define EC_NTEMPS (16+1)

struct EcPoint {
	mpz_t *x, *y, *z;
};
typedef struct EcPoint EcPoint;

struct EcCurve {
	int bits;					/* bits in field elements */
	uint8 p[EC_MAXFIELD];		/* field modulus */
	uint8 n[EC_MAXFIELD];		/* base point order */
	uint8 b[EC_MAXFIELD];		/* curve parameter */
	uint8 gx[EC_MAXFIELD];		/* base point X coord */
	uint8 gy[EC_MAXFIELD];		/* base point Y coord */
};

struct EcGroup {
	EcPoint *g;					/* base point */
	mpz_t	*p;					/* field modulus */
	mpz_t	*n;					/* base point order (max multiplier) */
	mpz_t	*b;					/* curve parameter */
	int		bits;				/* bits in field element */
	int		bytes;				/* bytes in field element */
	mpz_t	*tmp[EC_NTEMPS];	/* temp vars */
};

typedef struct EcGroup EcGroup;
typedef struct EcCurve EcCurve;

/*
 * P-256, P-384, P-521 curves from FIPS 186-3
 *
 * They all share same form:
 *
 *   y^2 = x^3 + ax + b
 *
 * where a is fixed to -3.
 */

static const struct EcCurve curve_list[] = {
{ 256, { /* p */
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	}, { /* n */
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
	}, { /* b */
		0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
		0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
	}, { /* gx */
		0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
		0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
	}, { /* gy */
		0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
		0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
	}},
{ 384, { /* p */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
	}, { /* n */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
		0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
	}, { /* b */
		0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
		0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a,
		0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef
	}, { /* gx */
		0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
		0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
		0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7
	}, { /* gy */
		0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
		0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
		0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f
	}},
{ 521, { /* p */
		0x01, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	}, { /* n */
		0x01, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa,
		0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 0xa5, 0xd0,
		0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09
	}, { /* b */
		0x00, 0x51,
		0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6, 0x85, 0x40, 0xee,
		0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3, 0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1, 0x09, 0xe1,
		0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93, 0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf, 0x07,
		0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c, 0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f, 0x00
	}, { /* gx */
		0x00, 0xc6,
		0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e, 0x3e, 0xcb, 0x66, 0x23, 0x95, 0xb4, 0x42,
		0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f, 0xb5, 0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d, 0x3d, 0xba,
		0xa1, 0x4b, 0x5e, 0x77, 0xef, 0xe7, 0x59, 0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff, 0xa8, 0xde,
		0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a, 0x42, 0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5, 0xbd, 0x66
	}, { /* gy */
		0x01, 0x18,
		0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c, 0x7d, 0x1b, 0xd9,
		0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e, 0x66, 0x2c,
		0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4, 0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad, 0x07, 0x61,
		0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1, 0x66, 0x50
	}}
};

/*
 * Point utility functions.
 */

/* set point to special zero/infinity value */
static int
ec_point_set_zero(struct EcPoint *p)
{
	mp_int_zero(p->x);
	mp_int_zero(p->z);
	return mp_int_set_value(p->y, 1);
}

/* is special zero/infinity point? */
static int
ec_point_is_zero(const struct EcPoint *p)
{
	if (mp_int_compare_zero(p->x) != 0)
		return 0;
	if (mp_int_compare_zero(p->z) != 0)
		return 0;
	return 1;
}

static void
ec_point_free(struct EcPoint *p)
{
	if (!p)
		return;
	mp_clear_free(p->x);
	mp_clear_free(p->y);
	mp_clear_free(p->z);
	px_free(p);
}

static struct EcPoint *
ec_point_new(void)
{
	struct EcPoint *p;

	p = px_alloc(sizeof(*p));
	if (!p)
		return NULL;
	p->x = mp_new();
	p->y = mp_new();
	p->z = mp_new();
	if (!p->x || !p->y || !p->z)
		goto fail;
	ec_point_set_zero(p);
	return p;
fail:
	ec_point_free(p);
	return NULL;
}

static struct EcPoint *
ec_point_new_value(const uint8 *xdata, const uint8 *ydata, int bytes)
{
	struct EcPoint *p;
	p = ec_point_new();
	if (!p)
		return NULL;
	if (mp_int_read_unsigned(p->x, (uint8*)xdata, bytes) != MP_OK)
		goto fail;
	if (mp_int_read_unsigned(p->y, (uint8*)ydata, bytes) != MP_OK)
		goto fail;
	if (mp_int_set_value(p->z, 1) != MP_OK)
		goto fail;
	return p;
fail:
	ec_point_free(p);
	return NULL;
}

static int
ec_point_copy(struct EcPoint *src, struct EcPoint *dst)
{
	int rc;
	if (src == dst)
		return MP_OK;
	rc = mp_int_copy(src->x, dst->x);
	if (rc != MP_OK)
		return rc;
	rc = mp_int_copy(src->y, dst->y);
	if (rc != MP_OK)
		return rc;
	return mp_int_copy(src->z, dst->z);
}

/*
 * Curve data initialization.
 */

static void
ec_curve_free(struct EcGroup *eg)
{
	int i;
	if (!eg)
		return;
	for (i = 0; i < EC_NTEMPS; i++)
		mp_clear_free(eg->tmp[i]);
	mp_clear_free(eg->p);
	mp_clear_free(eg->n);
	mp_clear_free(eg->b);
	ec_point_free(eg->g);
	memset(eg, 0, sizeof(*eg));
	px_free(eg);
}

static struct EcGroup *
ec_curve_load(const PGP_PubKey *pk)
{
	int curve = pk->pub.ecc.curve;
	struct EcGroup *eg;
	const struct EcCurve *ec;
	int i;

	if (curve < 0 && curve >= PGP_EC_NUM_CURVES)
		return NULL;
	ec = curve_list + curve;

	eg = px_alloc(sizeof(*eg));
	memset(eg, 0, sizeof(*eg));

	eg->bits = ec->bits;
	eg->bytes = (ec->bits + 7) / 8;

	eg->p = mp_new_value(ec->p, eg->bytes);
	eg->n = mp_new_value(ec->n, eg->bytes);
	eg->b = mp_new_value(ec->b, eg->bytes);
	eg->g = ec_point_new_value(ec->gx, ec->gy, eg->bytes);

	if (!eg->p || !eg->n || !eg->b || !eg->g)
		goto failed;
	for (i = 0; i < EC_NTEMPS; i++)
	{
		eg->tmp[i] = mp_new();
		if (!eg->tmp[i])
			goto failed;
	}
	return eg;

failed:
	ec_curve_free(eg);
	return NULL;
}

/*
 * modular arithmetic helpers
 */

/* c = a + b (mod p) */
static int
ec_add(struct EcGroup *eg, mpz_t *a, mpz_t *b, mpz_t *c)
{
	int rc;
	rc = mp_int_add(a, b, c);
	if (rc != MP_OK)
		return rc;
	if (mp_int_compare(c, eg->p) < 0)
		return MP_OK;
	return mp_int_sub(c, eg->p, c);
}

/* c = a - b (mod p) */
static int
ec_sub(struct EcGroup *eg, mpz_t *a, mpz_t *b, mpz_t *c)
{
	int rc;
	rc = mp_int_sub(a, b, c);
	if (rc != MP_OK)
		return rc;
	if (MP_SIGN(c) == MP_NEG)
		return mp_int_add(c, eg->p, c);
	return MP_OK;
}


/* c = a * b (mod p) */
static int
ec_mul(struct EcGroup *eg, mpz_t *a, mpz_t *b, mpz_t *c)
{
	int rc;
	mpz_t *buf = eg->tmp[EC_NTEMPS - 1];
	rc = mp_int_mul(a, b, buf);
	if (rc != MP_OK)
		return rc;
	return mp_int_mod(buf, eg->p, c);
}

/* c = a * b (mod p) */
static int
ec_mul_value(struct EcGroup *eg, mpz_t *a, int b, mpz_t *c)
{
	int rc;
	mpz_t *buf = eg->tmp[EC_NTEMPS - 1];
	rc = mp_int_mul_value(a, b, buf);
	if (rc != MP_OK)
		return rc;
	return mp_int_mod(buf, eg->p, c);
}

/* c = a^2 (mod p) */
static int
ec_sqr(struct EcGroup *eg, mpz_t *a, mpz_t *c)
{
	int rc;
	mpz_t *buf = eg->tmp[EC_NTEMPS - 1];
	rc = mp_int_sqr(a, buf);
	if (rc != MP_OK)
		return rc;
	return mp_int_mod(buf, eg->p, c);
}

/* automatic error handling */
#define ec_wrap(op) do { rc = op; if (rc != MP_OK) goto failed; } while (0)
#define EC_add(eg, a, b, c) ec_wrap(ec_add(eg, a,b,c))
#define EC_sub(eg, a, b, c) ec_wrap(ec_sub(eg, a,b,c))
#define EC_mul(eg, a, b, c) ec_wrap(ec_mul(eg, a,b,c))
#define EC_sqr(eg, a, c) ec_wrap(ec_sqr(eg, a,c))
#define EC_mul_value(eg, a, b, c) ec_wrap(ec_mul_value(eg, a,b,c))

#define EC_point_add(eg, p1, p2, res) ec_wrap(ec_point_add(eg, p1, p2, res))
#define EC_point_mul(eg, p, n, res) ec_wrap(ec_point_mul(eg, p, n, res))

/*
 * Basic EC math from RFC6090.
 */

/* 'combine' operation for EC points */
static int
ec_point_add(struct EcGroup *eg, struct EcPoint *p1, struct EcPoint *p2, struct EcPoint *sum)
{
	mpz_t *x1 = p1->x;
	mpz_t *y1 = p1->y;
	mpz_t *z1 = p1->z;
	mpz_t *x2 = p2->x;
	mpz_t *y2 = p2->y;
	mpz_t *z2 = p2->z;
	mpz_t *u = eg->tmp[0];
	mpz_t *u2 = eg->tmp[1];
	mpz_t *u3 = eg->tmp[2];
	mpz_t *v = eg->tmp[3];
	mpz_t *v2 = eg->tmp[4];
	mpz_t *v3 = eg->tmp[5];
	mpz_t *t1 = eg->tmp[6];
	mpz_t *t2 = eg->tmp[7];
	mpz_t *t3 = eg->tmp[8];
	mpz_t *x3 = eg->tmp[9];
	mpz_t *y3 = eg->tmp[10];
	mpz_t *z3 = eg->tmp[11];
	mpz_t *w = eg->tmp[12];
	mpz_t *w2 = eg->tmp[13];
	mpz_t *w3 = eg->tmp[14];
	mpz_t *yy = eg->tmp[15];
	int rc;

	/* 0 + p2 = p2 */
	if (ec_point_is_zero(p1))
		return ec_point_copy(p2, sum);

	/* p1 + 0 = p1 */
	if (ec_point_is_zero(p2))
		return ec_point_copy(p1, sum);

	/* if pointers are equal, no need to look at u/v */
	if (p1 == p2)
		goto same_point;

	/* u = Y2 * Z1 - Y1 * Z2  */
	EC_mul(eg, y2, z1, t1);
	EC_mul(eg, y1, z2, t2);
	EC_sub(eg, t1, t2, u);

	/* v = X2 * Z1 - X1 * Z2  */
	EC_mul(eg, x2, z1, t1);
	EC_mul(eg, x1, z2, t2);
	EC_sub(eg, t1, t2, v);

	/* if u<>0 && v == 0, thus p1 = -p2, thus sum = 0 */
	if (mp_int_compare_value(u, 0) != 0 && mp_int_compare_value(v, 0) == 0)
		return ec_point_set_zero(sum);

	/* if (u<>0 && v <> 0) then p1 != p2, need to do full operation */
	if (mp_int_compare_value(u, 0) != 0 && mp_int_compare_value(v, 0) != 0)
	{
		EC_sqr(eg, u, u2);
		EC_mul(eg, u, u2, u3);
		EC_sqr(eg, v, v2);
		EC_mul(eg, v, v2, v3);

		/*
		 * X3 = v * (Z2 * (Z1 * u^2 - 2 * X1 * v^2) - v^3)
		 */

		/* t1 = z1 * u^2 */
		EC_mul(eg, z1, u2, t1);

		/* t2 = 2*x1*v^2 */
		EC_mul_value(eg, x1, 2, t2);
		EC_mul(eg, t2, v2, t2);

		/* t1 = z2 * (t1 - t2) - v^3 */
		EC_sub(eg, t1, t2, t1);
		EC_mul(eg, t1, z2, t1);
		EC_sub(eg, t1, v3, t1);

		/* x3 = v * t1 */
		EC_mul(eg, v, t1, x3);

		/*
		 * Y3 = Z2 * (3 * X1 * u * v^2 - Y1 * v^3 - Z1 * u^3) + u * v^3
		 */

		/* t1 = 3 * X1 * u * v^2 */
		EC_mul_value(eg, x1, 3, t1);
		EC_mul(eg, t1, u, t1);
		EC_mul(eg, t1, v2, t1);

		/* t2 = Y1 * v^3 */
		EC_mul(eg, y1, v3, t2);

		/* t3 = Z1 * u^3 */
		EC_mul(eg, z1, u3, t3);

		/* t1 = z2 * (t1 - t2 - t3) */
		EC_sub(eg, t1, t2, t1);
		EC_sub(eg, t1, t3, t1);
		EC_mul(eg, t1, z2, t1);

		/* t2 = u * v^3 */
		EC_mul(eg, u, v3, t2);

		/* y3 = t1 + t2 */
		EC_add(eg, t1, t2, y3);

		/*
		 * Z3 = v^3 * Z1 * Z2
		 */
		EC_mul(eg, v3, z1, t1);
		EC_mul(eg, t1, z2, z3);
	}
	/*  u == 0 && v == 0  thus  p1 == p2 */
	else
	{
same_point:
		/*
		 * w = 3 * X1^2 + a * Z1^2
		 */
		EC_sqr(eg, x1, t1);
		EC_mul_value(eg, t1, 3, t1);
		EC_sqr(eg, z1, t2);
		EC_mul_value(eg, t2, 3, t2);
		EC_sub(eg, t1, t2, w);

		EC_sqr(eg, w, w2);
		EC_mul(eg, w, w2, w3);

		/*
		 * X3 = 2 * Y1 * Z1 * (w^2 - 8 * X1 * Y1^2 * Z1)
		 */

		/* t1 = w^2 - 8 * X1 * Y1^2 * Z1  */
		EC_mul_value(eg, x1, 8, t1);
		EC_sqr(eg, y1, yy);
		EC_mul(eg, t1, yy, t1);
		EC_mul(eg, t1, z1, t1);
		EC_sub(eg, w2, t1, t1);

		/* x3 = 2 * Y1 * Z1 * t1 */
		EC_mul_value(eg, y1, 2, t2);
		EC_mul(eg, t2, z1, t2);
		EC_mul(eg, t1, t2, x3);

		/*
		 * Y3 = 4 * Y1^2 * Z1 * (3 * w * X1 - 2 * Y1^2 * Z1) - w^3
		 */

		/* t1 = 3 * w * X1 */
		EC_mul_value(eg, w, 3, t1);
		EC_mul(eg, t1, x1, t1);

		/* t2 = 2 * Y1^2 * Z1 */
		EC_mul_value(eg, z1, 2, t2);
		EC_mul(eg, t2, yy, t2);

		/* t1 = 4 * Y1^2 * Z1 * (t1 - t2) */
		EC_sub(eg, t1, t2, t1);
		EC_mul_value(eg, z1, 4, t2);
		EC_mul(eg, t1, t2, t1);
		EC_mul(eg, t1, yy, t1);

		/* y3 = t1 - w^3 */
		EC_sub(eg, t1, w3, y3);

		/*
		 * Z3 = 8 * (Y1 * Z1)^3
		 */

		EC_mul(eg, y1, z1, t1);
		EC_sqr(eg, t1, t2);
		EC_mul(eg, t1, t2, t1);
		EC_mul_value(eg, t1, 8, z3);
	}
	mp_int_copy(x3, sum->x);
	mp_int_copy(y3, sum->y);
	mp_int_copy(z3, sum->z);
	return 0;
failed:
	px_debug("ec_point_add failed: %d", rc);
	return rc;
}

/* repeat 'combine' operation n times */
static int
ec_point_mul(struct EcGroup *eg, struct EcPoint *p, mpz_t *_n, struct EcPoint *res)
{
	int bits;
	struct EcPoint *tmp;
	mpz_t *n;
	int i;
	int rc;

	rc = MP_MEMORY;
	n = mp_new();
	tmp = ec_point_new();
	if (!tmp || !n)
		goto failed;

	/*
	 * Create equivalent n with fixed bit-length.
	 */
	rc = mp_int_copy(_n, n);
	if (rc != MP_OK)
		goto failed;
	rc = mp_int_add(n, eg->p, n);
	if (rc != MP_OK)
		goto failed;
	bits = mp_int_count_bits(n);
	if (bits <= eg->bits) {
		rc = mp_int_add(n, eg->p, n);
		if (rc != MP_OK)
			goto failed;
		bits = mp_int_count_bits(n);
	}

	/*
	 * Montgomery ladder - binary multiplication in fixed time.
	 *
	 * Basic idea: tmp = res + p
	 */
	EC_point_add(eg, p, p, tmp);
	ec_point_copy(p, res);
	for (i = bits - 2; i >= 0; i--)
	{
		if (mp_test_bit(n, i))
		{
			EC_point_add(eg, res, tmp, res);
			EC_point_add(eg, tmp, tmp, tmp);
		}
		else
		{
			EC_point_add(eg, tmp, res, tmp);
			EC_point_add(eg, res, res, res);
		}
	}

	mp_clear_free(n);
	ec_point_free(tmp);
	return MP_OK;

failed:
	mp_clear_free(n);
	ec_point_free(tmp);
	px_debug("ec_point_mul failed: %d", rc);
	return rc;
}

/*
 * EC Point load/store.
 */

/* convert (x, y, z) to (x/z, y/z, 1) */
static int ec_point_to_affine(struct EcGroup *eg, struct EcPoint *p)
{
	mpz_t *invz;
	int rc;

	invz = eg->tmp[0];

	if (mp_int_compare_value(p->z, 1) == 0)
		return MP_OK;

	/* invz = 1/z */
	rc = mp_int_invmod(p->z, eg->p, invz);
	if (rc != MP_OK)
		goto failed;

	/* x = x/z */
	EC_mul(eg, p->x, invz, p->x);

	/* y = y/z */
	EC_mul(eg, p->y, invz, p->y);

	/* z = 1 */
	rc = mp_int_set_value(p->z, 1);
	if (rc != MP_OK)
		goto failed;
	return MP_OK;

failed:
	px_debug("ec_point_to_affine failed: %d", rc);
	return rc;
}

/* execute curve expression to see if point is on curve */
static int
ec_valid_point(struct EcGroup *eg, struct EcPoint *p)
{
	int rc;
	mpz_t *l = eg->tmp[0];
	mpz_t *r = eg->tmp[1];
	mpz_t *t = eg->tmp[2];

	/* check sanity */
	if (mp_int_compare_value(p->x, 0) == 0)
		return 0;
	if (mp_int_compare_value(p->y, 0) == 0)
		return 0;
	if (mp_int_compare(p->x, eg->p) >= 0)
		return 0;
	if (mp_int_compare(p->y, eg->p) >= 0)
		return 0;

	/* evaluate: y^2 = x^3 - 3x + b */

	EC_sqr(eg, p->y, l);

	EC_sqr(eg, p->x, r);
	EC_mul(eg, p->x, r, r);
	EC_mul_value(eg, p->x, 3, t);
	EC_sub(eg, r, t, r);
	EC_add(eg, r, eg->b, r);

	if (mp_int_compare(l, r) != 0)
	{
		px_debug("ec_valid_point: invalid point");
		return 0;
	}
	return 1;

failed:
	px_debug("ec_valid_point: math failure: %d", rc);
	return 0;
}

/*
 * Load point from PGP_MPI.
 *
 * Values are stored in MPI data with following format:
 *
 *   04 || x || y
 *
 * Both x and y are same, fixed length for particular curve (256/384/521+7).
 *
 * OpenSSL supports 0x04 format natively, also the input routines check whether
 * bignum size is valid and whether the point is actually on curve.  So no need
 * to do such checks here.
 */

static struct EcPoint *
mpi_to_point(struct EcGroup *eg, const PGP_MPI *n)
{
	struct EcPoint *p;
	int bits = (eg->bytes * 2 * 8) + 3;

	if (n->data[0] != 0x04 || n->bits != bits)
	{
		px_debug("Invalid MPI point format (fmt=%d, bits=%d)",
				 n->data[0], n->bits);
		return NULL;
	}

	p = ec_point_new_value(n->data + 1, n->data + 1 + eg->bytes, eg->bytes);
	if (!p)
		return NULL;

	/* check if point is on curve */
	if (!ec_valid_point(eg, p))
	{
		ec_point_free(p);
		return NULL;
	}

	return p;
}

static PGP_MPI *
point_to_mpi(struct EcGroup *eg, struct EcPoint *p)
{
	int			rc;
	PGP_MPI    *n;
	int			bytes;
	int			bits;
	int			skip;

	rc = ec_point_to_affine(eg, p);
	if (rc != MP_OK)
	{
		px_debug("ec_point_to_affine failure");
		return NULL;
	}

	/* bits in final number */
	bits = 3 + 2*8*eg->bytes;

	/* new mpi */
	rc = pgp_mpi_alloc(bits, &n);
	if (rc < 0)
		return NULL;
	memset(n->data, 0, n->bytes);
	n->data[0] = 0x04;

	/* write x */
	bytes = (mp_int_count_bits(p->x) + 7) / 8;
	if (bytes > n->bytes)
		goto failed;
	skip = (eg->bytes - bytes);
	rc = mp_int_to_unsigned(p->x, n->data + 1 + skip, bytes);
	if (rc != MP_OK)
		goto failed;

	/* write y */
	bytes = (mp_int_count_bits(p->y) + 7) / 8;
	if (bytes > n->bytes)
		goto failed;
	skip = (eg->bytes - bytes);
	rc = mp_int_to_unsigned(p->y, n->data + 1 + eg->bytes + skip, bytes);
	if (rc != MP_OK)
		goto failed;

	return n;

failed:
	pgp_mpi_free(n);
	px_debug("point_to_mpi failed: %d", rc);
	return NULL;
}

/*
 * ECDH operation in OpenPGP:
 *
 * You have given a 'group' of points with 'add' and 'multiply' operations.
 * Pre-existing information:   (Lower-case is integer, upper-case is point.)
 *
 *   G - pre-defined point in group
 *   r - private key (random number)
 *   R - public key (R = rG)
 *
 * On encryption, session keypair is generated:
 *
 *   v - random number (0 < v < p)
 *   V - public point (V = vG), will be put into message
 *
 * that is used to calculate shared secret point:
 *
 *   S = vR = vrG
 *
 * On decryption, public point V and private key r
 * are used to calculate S:
 *
 *   S = rV = rvG
 */

int
pgp_ecdh_encrypt(const PGP_PubKey *pk, PGP_MPI **vg_p, PGP_MPI **sp_p)
{
	int			rc = 0;
	int			res = PXE_PGP_MATH_FAILED;
	EcGroup *eg = NULL;
	EcPoint *vg = NULL;
	EcPoint *sp = NULL;
	EcPoint *r = NULL;
	mpz_t	   *v = NULL;
	mpz_t	   *n = NULL;

	eg = ec_curve_load(pk);
	v = mp_new();
	n = mp_new();
	if (!v || !n || !eg)
		goto failed;

	/* load other values */
	sp = ec_point_new();
	vg = ec_point_new();
	if (!sp || !vg)
		goto failed;
	r = mpi_to_point(eg, pk->pub.ecc.rp);
	if (!r)
	{
		res = PXE_PGP_KEYPKT_CORRUPT;
		goto failed;
	}

	/* create session private key */
	do
	{
		/* generate value without top bit set */
		if (mp_px_rand(eg->bits, v, 0) != MP_OK)
			goto failed;
		/* it must be in range 0 < v < n */
	} while (mp_int_compare(v, eg->n) >= 0 ||
			 mp_int_compare_value(v, 1) < 0);

	/* create session public key */
	EC_point_mul(eg, eg->g, v, vg);

	/* create shared point */
	EC_point_mul(eg, r, v, sp);

	/* convert result */
	*vg_p = point_to_mpi(eg, vg);
	if (!*vg_p)
		goto failed;
	*sp_p = point_to_mpi(eg, sp);
	if (!*sp_p)
	{
		pgp_mpi_free(*vg_p);
		*vg_p = NULL;
		goto failed;
	}
	res = 0;

failed:
	ec_point_free(vg);
	ec_point_free(sp);
	ec_point_free(r);
	mp_clear_free(n);
	mp_clear_free(v);
	ec_curve_free(eg);
	return res;
}

int
pgp_ecdh_decrypt(const PGP_PubKey *pk, const PGP_MPI *_vg, PGP_MPI **sp_p)
{
	int			res = PXE_PGP_MATH_FAILED;
	EcGroup *eg = NULL;
	EcPoint *vg = NULL;
	EcPoint	 *sp = NULL;
	mpz_t		*r = NULL;

	eg = ec_curve_load(pk);
	if (!eg)
		goto err;
	r = mpi_to_bn(pk->sec.ecc.r);
	sp = ec_point_new();
	if (!r || !sp)
		goto err;

	/* session public key, comes from data */
	vg = mpi_to_point(eg, _vg);
	if (!vg)
	{
		px_debug("invalid point in packet");
		res = PXE_PGP_KEYPKT_CORRUPT;
		goto err;
	}

	/* create shared secret */
	if (ec_point_mul(eg, vg, r, sp) != MP_OK)
		goto err;

	/* convert result */
	*sp_p = point_to_mpi(eg, sp);
	if (*sp_p)
		res = 0;

err:
	ec_point_free(vg);
	ec_point_free(sp);
	mp_clear_free(r);
	ec_curve_free(eg);
	return res;
}

