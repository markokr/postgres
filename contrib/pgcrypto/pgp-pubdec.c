/*
 * pgp-pubdec.c
 *	  Decrypt public-key encrypted session key.
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
 * contrib/pgcrypto/pgp-pubdec.c
 */
#include "postgres.h"

#include "px.h"
#include "mbuf.h"
#include "pgp.h"
#include "aeswrap.h"

/*
 * padded msg = 02 || PS || 00 || M
 * PS - pad bytes
 * M - msg
 */
static uint8 *
check_eme_pkcs1_v15(uint8 *data, int len, int *msglen_p)
{
	uint8	   *data_end = data + len;
	uint8	   *p = data;
	int			rnd = 0;

	if (len < 1 + 8 + 1)
		return NULL;

	if (*p++ != 2)
		return NULL;

	while (p < data_end && *p)
	{
		p++;
		rnd++;
	}

	if (p == data_end)
		return NULL;
	if (*p != 0)
		return NULL;
	if (rnd < 8)
		return NULL;
	p++;
	*msglen_p = data_end - p;
	return p;
}

/*
 * padded msg = M || PAD
 * M - msg
 * PAD - pad bytes, all equal to pad length
 */
static uint8 *
check_pkcs5_pad(uint8 *data, int len, int *msglen_p)
{
	uint8	   *data_end;
	int			plen;
	int			i;

	if (len < 8 || (len % 8) != 0)
		return NULL;

	/* get pad length */
	plen = data[len - 1];
	if (plen == 0 || plen >= len)
		return NULL;

	/* pad bytes must match length */
	data_end = data + len - plen;
	for (i = 0; i < plen; i++)
	{
		if (data_end[i] != plen)
			return NULL;
	}

	*msglen_p = len - plen;
	return data;
}

/*
 * secret message: 1 byte algo, sesskey, 2 byte cksum
 * ignore algo in cksum
 */
static int
control_cksum(uint8 *msg, int msglen)
{
	int			i;
	unsigned	my_cksum,
				got_cksum;

	if (msglen < 3)
		return PXE_PGP_WRONG_KEY;

	my_cksum = 0;
	for (i = 1; i < msglen - 2; i++)
		my_cksum += msg[i];
	my_cksum &= 0xFFFF;
	got_cksum = ((unsigned) (msg[msglen - 2]) << 8) + msg[msglen - 1];
	if (my_cksum != got_cksum)
	{
		px_debug("pubenc cksum failed");
		return PXE_PGP_WRONG_KEY;
	}
	return 0;
}

static int
decrypt_elgamal(PGP_PubKey *pk, PullFilter *pkt, PGP_MPI **m_p)
{
	int			res;
	PGP_MPI    *c1 = NULL;
	PGP_MPI    *c2 = NULL;

	if (pk->algo != PGP_PUB_ELG_ENCRYPT)
		return PXE_PGP_WRONG_KEY;

	/* read elgamal encrypted data */
	res = pgp_mpi_read(pkt, &c1);
	if (res < 0)
		goto out;
	res = pgp_mpi_read(pkt, &c2);
	if (res < 0)
		goto out;

	/* decrypt */
	res = pgp_elgamal_decrypt(pk, c1, c2, m_p);

out:
	pgp_mpi_free(c1);
	pgp_mpi_free(c2);
	return res;
}

static int
decrypt_rsa(PGP_PubKey *pk, PullFilter *pkt, PGP_MPI **m_p)
{
	int			res;
	PGP_MPI    *c;

	if (pk->algo != PGP_PUB_RSA_ENCRYPT
		&& pk->algo != PGP_PUB_RSA_ENCRYPT_SIGN)
		return PXE_PGP_WRONG_KEY;

	/* read rsa encrypted data */
	res = pgp_mpi_read(pkt, &c);
	if (res < 0)
		return res;

	/* decrypt */
	res = pgp_rsa_decrypt(pk, c, m_p);

	pgp_mpi_free(c);
	return res;
}

static int
decrypt_ecdh(PGP_PubKey *pk, PullFilter *pkt, PGP_MPI **m_p)
{
	uint8		wlen, zklen;
	uint8		wbuf[256];
	uint8		mbuf[256];
	uint8		zkey[PGP_MAX_KEY];
	PGP_MPI    *vg = NULL;
	PGP_MPI    *sp = NULL;
	PGP_MPI		*m = NULL;
	int res;

	if (pk->algo != PGP_PUB_ECDH_ENCRYPT)
		return PXE_PGP_WRONG_KEY;

	/* read public point */
	res = pgp_mpi_read(pkt, &vg);
	if (res < 0)
		goto err;

	/* read wrapped session key */
	res = pullf_read_fixed(pkt, 1, &wlen);
	if (res < 0)
		goto err;
	if (wlen == 255 || wlen < 16+8)
		/* reserved or invalid value */
		goto err;
	res = pullf_read_fixed(pkt, wlen, wbuf);
	if (res < 0)
		goto err;

	/* calculate shared point */
	res = pgp_ecdh_decrypt(pk, vg, &sp);
	if (res < 0)
		goto err;

	/* generate temp key from shared point */
	res = PXE_PGP_UNSUPPORTED_CIPHER;
	zklen = pgp_get_cipher_key_size(pk->pub.ecc.skey_ciph);
	if (!zklen)
		goto err;
	res = pgp_point_kdf(pk, sp, zkey, zklen);
	if (res < 0)
		goto err;

	/* unwrap session key */
	res = pgp_mpi_alloc(wlen * 8, &m);
	if (res < 0)
		goto err;
	res = px_aes_unwrap(wbuf, wlen, zkey, zklen, m->data, m->bytes);
	if (res < 0)
		goto err;

	/* done, fill correct length */
	m->bytes = res;
	m->bits = res * 8;
	res = 0;

err:
	pgp_mpi_free(vg);
	pgp_mpi_free(sp);
	memset(wbuf, 0, sizeof(wbuf));
	memset(zkey, 0, sizeof(zkey));
	memset(mbuf, 0, sizeof(mbuf));
	if (res == 0)
		*m_p = m;
	else
		pgp_mpi_free(m);
	return res;
}

/* key id is missing - user is expected to try all keys */
static const uint8
			any_key[] = {0, 0, 0, 0, 0, 0, 0, 0};

int
pgp_parse_pubenc_sesskey(PGP_Context *ctx, PullFilter *pkt)
{
	int			ver;
	int			algo;
	int			res;
	uint8		key_id[8];
	PGP_PubKey *pk;
	uint8	   *msg;
	int			msglen;
	PGP_MPI    *m = NULL;

	pk = ctx->pub_key;
	if (pk == NULL)
	{
		px_debug("no pubkey?");
		return PXE_BUG;
	}

	GETBYTE(pkt, ver);
	if (ver != 3)
	{
		px_debug("unknown pubenc_sesskey pkt ver=%d", ver);
		return PXE_PGP_CORRUPT_DATA;
	}

	/*
	 * check if keyid's match - user-friendly msg
	 */
	res = pullf_read_fixed(pkt, 8, key_id);
	if (res < 0)
		return res;
	if (memcmp(key_id, any_key, 8) != 0
		&& memcmp(key_id, pk->key_id, 8) != 0)
	{
		px_debug("key_id's does not match");
		return PXE_PGP_WRONG_KEY;
	}

	/*
	 * Decrypt
	 */
	GETBYTE(pkt, algo);
	switch (algo)
	{
		case PGP_PUB_ELG_ENCRYPT:
			res = decrypt_elgamal(pk, pkt, &m);
			break;
		case PGP_PUB_RSA_ENCRYPT:
		case PGP_PUB_RSA_ENCRYPT_SIGN:
			res = decrypt_rsa(pk, pkt, &m);
			break;
		case PGP_PUB_ECDH_ENCRYPT:
			res = decrypt_ecdh(pk, pkt, &m);
			break;
		default:
			res = PXE_PGP_UNKNOWN_PUBALGO;
	}
	if (res < 0 || !m)
		return res;

	/*
	 * extract message
	 */
	if (algo == PGP_PUB_ECDH_ENCRYPT)
		msg = check_pkcs5_pad(m->data, m->bytes, &msglen);
	else
		msg = check_eme_pkcs1_v15(m->data, m->bytes, &msglen);
	if (msg == NULL)
	{
		px_debug("session key padding failed");
		res = PXE_PGP_WRONG_KEY;
		goto out;
	}

	/*
	 * got sesskey
	 */
	ctx->cipher_algo = *msg;
	ctx->sess_key_len = pgp_get_cipher_key_size(ctx->cipher_algo);

	if (!ctx->sess_key_len || (int)ctx->sess_key_len != (msglen - 3))
	{
		px_debug("invalid cipher or key in key pkt (ciph:%d skey:%d)",
				 ctx->cipher_algo, ctx->sess_key_len);
		return PXE_PGP_KEYPKT_CORRUPT;
	}

	res = control_cksum(msg, msglen);
	if (res < 0)
		goto out;

	memcpy(ctx->sess_key, msg + 1, ctx->sess_key_len);

out:
	pgp_mpi_free(m);
	if (res < 0)
		return res;
	return pgp_expect_packet_end(pkt);
}
