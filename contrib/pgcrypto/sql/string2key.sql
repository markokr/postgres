
--
-- PBKDF2-SHA1 test vectors from RFC6070
--

-- 0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6 
select encode(string2key('pbkdf2-sha1', 'password', 'salt', 1, 20), 'hex') as s2k;

-- ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57  
select encode(string2key('pbkdf2-sha1', 'password', 'salt', 2, 20), 'hex') as s2k;

-- 4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1
select encode(string2key('pbkdf2-sha1', 'password', 'salt', 4096, 20), 'hex') as s2k;

-- ee fe 3d 61 cd 4d a4 e4 e9 94 5b 3d 6b a2 15 8c 26 34 e9 84 
-- select encode(string2key('pbkdf2-sha1', 'password', 'salt', 16777216, 20), 'hex') as s2k;

-- 3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38   
select encode(string2key('pbkdf2-sha1', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25), 'hex') as s2k;

-- 56 fa 6a a7 55 48 09 9d cc 37 d7 f0 34 25 e0 c3 
select encode(string2key('pbkdf2-sha1', E'pass\\000word'::bytea, E'sa\\000lt'::bytea, 4096, 16), 'hex') as s2k;

-- weird params
select encode(string2key('pbkdf2-sha1', 'password', '', 1, 32), 'hex') as s2k;
select encode(string2key('pbkdf2-sha1', '', 'salt', 1, 32), 'hex') as s2k;
select encode(string2key('pbkdf2-sha1', '', '', 1, 32), 'hex') as s2k;
select encode(string2key('pbkdf2', 'password', 'salt', 1, 20), 'hex') as s2k;

-- other algos

select encode(string2key('pbkdf2-md5', 'password', 'salt', 1, 20), 'hex') as s2k;
select encode(string2key('pbkdf2-md5', 'password', 'salt', 2, 20), 'hex') as s2k;
select encode(string2key('pbkdf2-md5', 'password', 'salt', 4096, 20), 'hex') as s2k;
select encode(string2key('pbkdf2-md5', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25), 'hex') as s2k;
select encode(string2key('pbkdf2-md5', E'pass\\000word'::bytea, E'sa\\000lt'::bytea, 4096, 16), 'hex') as s2k;

select encode(string2key('pbkdf2-sha224', 'password', 'salt', 1, 28), 'hex') as s2k;
select encode(string2key('pbkdf2-sha224', 'password', 'salt', 2, 28), 'hex') as s2k;
select encode(string2key('pbkdf2-sha224', 'password', 'salt', 4096, 28), 'hex') as s2k;
select encode(string2key('pbkdf2-sha224', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 35), 'hex') as s2k;
select encode(string2key('pbkdf2-sha224', E'pass\\000word'::bytea, E'sa\\000lt'::bytea, 4096, 16), 'hex') as s2k;

select encode(string2key('pbkdf2-sha256', 'password', 'salt', 1, 32), 'hex') as s2k;
select encode(string2key('pbkdf2-sha256', 'password', 'salt', 2, 32), 'hex') as s2k;
select encode(string2key('pbkdf2-sha256', 'password', 'salt', 4096, 32), 'hex') as s2k;
select encode(string2key('pbkdf2-sha256', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 45), 'hex') as s2k;
select encode(string2key('pbkdf2-sha256', E'pass\\000word'::bytea, E'sa\\000lt'::bytea, 4096, 16), 'hex') as s2k;

select encode(string2key('pbkdf2-sha384', 'password', 'salt', 1, 48), 'hex') as s2k;
select encode(string2key('pbkdf2-sha384', 'password', 'salt', 2, 48), 'hex') as s2k;
select encode(string2key('pbkdf2-sha384', 'password', 'salt', 4096, 48), 'hex') as s2k;
select encode(string2key('pbkdf2-sha384', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 64), 'hex') as s2k;
select encode(string2key('pbkdf2-sha384', E'pass\\000word'::bytea, E'sa\\000lt'::bytea, 4096, 16), 'hex') as s2k;

select encode(string2key('pbkdf2-sha512', 'password', 'salt', 1, 64), 'hex') as s2k;
select encode(string2key('pbkdf2-sha512', 'password', 'salt', 2, 64), 'hex') as s2k;
select encode(string2key('pbkdf2-sha512', 'password', 'salt', 4096, 64), 'hex') as s2k;
select encode(string2key('pbkdf2-sha512', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 128), 'hex') as s2k;
select encode(string2key('pbkdf2-sha512', E'pass\\000word'::bytea, E'sa\\000lt'::bytea, 4096, 16), 'hex') as s2k;


--
-- PBKDF1
--

-- http://www.di-mgt.com.au/cryptoKDFs.html
-- D1F94C4D447039B034494400F2E7DF9DCB67C308
select encode(string2key('pbkdf1-sha1', 'password', decode('78578E5A5D63CB06', 'hex'), 1, 20), 'hex') as s2k;
-- 2BB479C1D369EA74BB976BBA2629744E8259C6F5
select encode(string2key('pbkdf1-sha1', 'password', decode('78578E5A5D63CB06', 'hex'), 2, 20), 'hex') as s2k;
-- 6663F4611D61571068B5DA168974C6FF2C9775AC
select encode(string2key('pbkdf1-sha1', 'password', decode('78578E5A5D63CB06', 'hex'), 999, 20), 'hex') as s2k;
-- DC19847E05C64D2FAF10EBFB4A3D2A20
select encode(string2key('pbkdf1-sha1', 'password', decode('78578E5A5D63CB06', 'hex'), 1000, 16), 'hex') as s2k;

select encode(string2key('pbkdf1-sha1', 'password', 'salt', 1, 20), 'hex') as s2k;
select encode(string2key('pbkdf1-sha1', 'password', 'salt', 2, 20), 'hex') as s2k;
select encode(string2key('pbkdf1-sha1', 'password', 'salt', 4096, 20), 'hex') as s2k;
select encode(string2key('pbkdf1-sha1', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 20), 'hex') as s2k;
select encode(string2key('pbkdf1-sha1', E'pass\\000word'::bytea, E'sa\\000lt'::bytea, 4096, 16), 'hex') as s2k;

select encode(string2key('pbkdf1-md5', 'password', 'salt', 4096, 16), 'hex') as s2k;
select encode(string2key('pbkdf1-sha1', 'password', 'salt', 4096, 16), 'hex') as s2k;
select encode(string2key('pbkdf1-sha256', 'password', 'salt', 4096, 16), 'hex') as s2k;
select encode(string2key('pbkdf1-sha512', 'password', 'salt', 4096, 16), 'hex') as s2k;

select encode(string2key('pbkdf1-sha1', 'password', '', 1, 20), 'hex') as s2k;
select encode(string2key('pbkdf1-sha1', '', 'salt', 1, 20), 'hex') as s2k;
select encode(string2key('pbkdf1-sha1', '', '', 1, 20), 'hex') as s2k;
select encode(string2key('pbkdf1', 'password', 'salt', 1, 20), 'hex') as s2k;

