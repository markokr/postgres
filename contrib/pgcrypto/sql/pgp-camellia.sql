--
-- test rare ciphers
--

set bytea_output = 'escape';

-- camellia 128
select pgp_sym_decrypt_bytea(dearmor('
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.10 (GNU/Linux)

jA0ECwMC7c3uT6GQW4hg0kEBuDIHjoP3hxzGsNqEgWIwQ8Cn6unoya1TbGYVxDzZ
pwSi6kLDiebu6Y3QXTuoYrVyacwCtQe7YE9ID898eoDz0w==
=Sktv
-----END PGP MESSAGE-----
'), 'password');

-- camellia 192
select pgp_sym_decrypt_bytea(dearmor('
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.10 (GNU/Linux)

jA0EDAMCv3g2FsyaYyNg0kEBHglUDa6V9RzyMBSACYxZCDVLaA5pPJZj5Rj5+fx+
LlD3v7FvLX/MtYMtN7vKYeO4iHrLsf5cmDfbA5m0Tg9I9w==
=thb0
-----END PGP MESSAGE-----
'), 'password');

-- camellia 256
select pgp_sym_decrypt_bytea(dearmor('
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.10 (GNU/Linux)

jA0EDQMC+fsRMecJqzdg0kEB81pdl1EQo6HrnyUsQbVRfYPx/aXxel7Yo1iOV4t3
6qwSXvSKL9JoDeKwpj0VcTWjC5YiHyhS4Heh0Z8CnQoILQ==
=SQL7
-----END PGP MESSAGE-----
'), 'password');

-- now test encryption

select pgp_sym_decrypt(
    pgp_sym_encrypt('test', 'password', 'cipher-algo=camellia128'),
    'password', 'expect-cipher-algo=camellia128');

select pgp_sym_decrypt(
    pgp_sym_encrypt('test', 'password', 'cipher-algo=camellia192'),
    'password', 'expect-cipher-algo=camellia192');

select pgp_sym_decrypt(
    pgp_sym_encrypt('test', 'password', 'cipher-algo=camellia256'),
    'password', 'expect-cipher-algo=camellia256');

