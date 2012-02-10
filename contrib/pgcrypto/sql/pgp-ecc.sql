--
-- PGP ECDH Public Key Encryption
--
-- Test vectors from http://sites.google.com/site/brainhub/pgpecckeys
--

\set ECHO off
insert into keytbl (id, name, pubkey, seckey)
values (100, 'ecc256', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.1.0-ecc (GNU/Linux)

mFIETJPQrRMIKoZIzj0DAQcCAwQLx6e669XwjHTHe3HuROe7C1oYMXuZbaU5PjOs
xSkyxtL2D00e/jWgufuNN4ftS+6XygEtB7j1g1vnCTVF1TLmtCRlY19kc2FfZGhf
MjU2IDxvcGVucGdwQGJyYWluaHViLm9yZz6IegQTEwgAIgUCTJPQrQIbAwYLCQgH
AwIGFQgCCQoLBBYCAwECHgECF4AACgkQC6Ut8LqlnZzmXQEAiKgiSzPSpUOJcX9d
JtLJ5As98Alit2oFwzhxG7mSVmQA/RP67yOeoUtdsK6bwmRA95cwf9lBIusNjehx
XDfpHj+/uFYETJPQrRIIKoZIzj0DAQcCAwR/cMCoGEzcrqXbILqP7Rfke977dE1X
XsRJEwrzftreZYrn7jXSDoiXkRyfVkvjPZqUvB5cknsaoH/3UNLRHClxAwEIB4hh
BBgTCAAJBQJMk9CtAhsMAAoJEAulLfC6pZ2c1yYBAOSUmaQ8rkgihnepbnpK7tNz
3QEocsLEtsTCDUBGNYGyAQDclifYqsUChXlWKaw3md+yHJPcWZXzHt37c4q/MhIm
oQ==
=hMzp
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2.1.0-ecc (GNU/Linux)

lJ0ETJPQrRMIKoZIzj0DAQcCAwQLx6e669XwjHTHe3HuROe7C1oYMXuZbaU5PjOs
xSkyxtL2D00e/jWgufuNN4ftS+6XygEtB7j1g1vnCTVF1TLm/gMDAmHomSLb9NbE
oyWUoqgKTbZzbFR/SWmiCcuiQEhREcTyvyU1hAglj7FsBJoQ6/pbeAEQZ3bVzlNM
8F0nF8KPLPuEADF1+4CntCRlY19kc2FfZGhfMjU2IDxvcGVucGdwQGJyYWluaHVi
Lm9yZz6IegQTEwgAIgUCTJPQrQIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AA
CgkQC6Ut8LqlnZzmXQEAiKgiSzPSpUOJcX9dJtLJ5As98Alit2oFwzhxG7mSVmQA
/RP67yOeoUtdsK6bwmRA95cwf9lBIusNjehxXDfpHj+/nKEETJPQrRIIKoZIzj0D
AQcCAwR/cMCoGEzcrqXbILqP7Rfke977dE1XXsRJEwrzftreZYrn7jXSDoiXkRyf
VkvjPZqUvB5cknsaoH/3UNLRHClxAwEIB/4DAwJh6Jki2/TWxKO7gHKWIcOcxYZp
CRWjlUghbKb6Q83p8GLPjKRN0USl/U1tObWdksqMXhUO0ePLWUnrbwoWYfYXg9Er
ADTgCYhhBBgTCAAJBQJMk9CtAhsMAAoJEAulLfC6pZ2c1yYA/3eJRirPQZmBno+Z
P/HOBSFWmFt4cUBGUx3oqiUd5loOAP480pb+vXx9ipljJWCJDSl/boRSuqB4hePP
qt9Rd5gNdQ==
=O8Dg
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (102, 'ec256-signonly', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: PGP Command Line v10.2.0 (Linux)

mQBSBE1TYr0TCCqGSM49AwEHAgMEGztmS6KdJzgYJIiMt5M2iatqH3duRGl78C/t
cX47pmNruw+PVqx+AEteUnxLGZQ3Zlbz8OFz23hrcBP/E6x647QhZWNfZHNhXzI1
NiA8b3BlbnBncEBicmFpbmh1Yi5vcmc+iQCrBBATCABTBQJNU2K9MBSAAAAAACAA
B3ByZWZlcnJlZC1lbWFpbC1lbmNvZGluZ0BwZ3AuY29tcGdwbWltZQQLBwkIAhkB
BRsDAAAAAhYCBR4BAAAABBUICQoACgkQK6rMIFboiIKPXAD+PWP31q35h7tWBhIX
nIeUHHovdEsj8oW3q/xqYNmNSIYBAIJBfM+DYCwJkKBgRJx9leiLryRgZnazOMA4
vG5ngTTQ
=lckD
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: PGP Command Line v10.2.0 (Linux)

lQClBE1TYr0TCCqGSM49AwEHAgMEGztmS6KdJzgYJIiMt5M2iatqH3duRGl78C/t
cX47pmNruw+PVqx+AEteUnxLGZQ3Zlbz8OFz23hrcBP/E6x64/4HAwJp/NxOrMLF
DKRCxpmQodt/xK57tUxG0mnZLNW6iLmihFCjhBjSuJoVOdvoV0SYmvJnw5MCpwvL
+4g2MFzuCZeEt+hw5FCXFpDdDPYPqF5jtCFlY19kc2FfMjU2IDxvcGVucGdwQGJy
YWluaHViLm9yZz4=
=Cf/8
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (103, 'ecc384', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: PGP Command Line v10.2.0 (Linux)

mQBvBE1TBZITBSuBBAAiAwME9rjFrO1bhO+fSiCdsuSp37cNKMuMEOzVdnSp+lpn
OJlCti1eUTZ99Me/0/jlAP7s8H7SZaYhqOu75T6UfseMZ366FDvRUzwrNQ4cKfgj
E+HhEI66Bjvh5ksQ5pUOeZwttCRlY19kc2FfZGhfMzg0IDxvcGVucGdwQGJyYWlu
aHViLm9yZz6JAMsEEBMJAFMFAk1TBZIwFIAAAAAAIAAHcHJlZmVycmVkLWVtYWls
LWVuY29kaW5nQHBncC5jb21wZ3BtaW1lBAsJCAcCGQEFGwMAAAACFgIFHgEAAAAE
FQkKCAAKCRAJgDOID1Rxn8orAYCqNzUJaL1fEVr9jOe8exA4IhUtv/BtCvzag1Mp
UQkFuYy0abogj6q4fHQSt5nntjMBf1g2TqSA6KGj8lOgxfIsRG6L6an85iEBNu4w
gRq71JE53ii1vfjcNtBq50hXnp/1A7kAcwRNUwWSEgUrgQQAIgMDBC+qhAJKILZz
XEiX76W/tBv4W37v6rXKDLn/yOoEpGrLJVNKV3aU+eJTQKSrUiOp3R7aUwyKouZx
jbENfmclWMdzb+CTaepXOaKjVUvxbUH6pQVi8RxtObvV3/trmp7JGAMBCQmJAIQE
GBMJAAwFAk1TBZIFGwwAAAAACgkQCYAziA9UcZ+AlwGA7uem2PzuQe5PkonfF/m8
+dlV3KJcWDuUM286Ky1Jhtxc9Be40tyG90Gp4abSNsDjAX0cdldUWKDPuTroorJ0
/MZc7s16ke7INla6EyGZafBpRbSMVr0EFSw6BVPF8vS9Emc=
=I76R
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: PGP Command Line v10.2.0 (Linux)

lQDSBE1TBZITBSuBBAAiAwME9rjFrO1bhO+fSiCdsuSp37cNKMuMEOzVdnSp+lpn
OJlCti1eUTZ99Me/0/jlAP7s8H7SZaYhqOu75T6UfseMZ366FDvRUzwrNQ4cKfgj
E+HhEI66Bjvh5ksQ5pUOeZwt/gcDAkrFTsfF6LKsqD/tW6Eot2DDE8znJjnQQ/Nr
H98XT1WQ9V0ED8l9DDIIj7z80ED3NR8XMSI8Ew/A/0w6NDPL978BX0MGvpaeBaWV
tEuH1EPAxiA+hFALwftY+a8s1zLktCRlY19kc2FfZGhfMzg0IDxvcGVucGdwQGJy
YWluaHViLm9yZz6dANYETVMFkhIFK4EEACIDAwQvqoQCSiC2c1xIl++lv7Qb+Ft+
7+q1ygy5/8jqBKRqyyVTSld2lPniU0Ckq1Ijqd0e2lMMiqLmcY2xDX5nJVjHc2/g
k2nqVzmio1VL8W1B+qUFYvEcbTm71d/7a5qeyRgDAQkJ/gkDAqqmkngPLoJGqI4O
rHyyU3wrrPzDDDURkseoUEZlDZINjyto26A8N825mqLqeFytJuuABYH1UnLs4d2x
ZJZIYjEoFMPcFPuUtx+IZnECa1Vcyq2aRFCixVO0G/xrSFar
=a4k3
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (105, 'ecc521', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: PGP Command Line v10.2.0 (Linux)

mQCTBE1TFQITBSuBBAAjBCMEAWuwULfE2XoQmJhSQZ8rT5Ecr/kooudn4043gXHy
NZEdTeFfY2G7kwEaxj8TXfd1U1b4PkEoqhzKxhz/MHK/lwi2ARzW1XQiJ1/kFPsv
IUnQI1CUS099WKKQhD8JMPPyje1dKfjFjm2gzyF3TOMX1Cyy8wFyF0MiHVgB3ezb
w7C6jY+3tCRlY19kc2FfZGhfNTIxIDxvcGVucGdwQGJyYWluaHViLm9yZz6JAO0E
EBMKAFMFAk1TFQIwFIAAAAAAIAAHcHJlZmVycmVkLWVtYWlsLWVuY29kaW5nQHBn
cC5jb21wZ3BtaW1lBAsJCAcCGQEFGwMAAAACFgIFHgEAAAAEFQoJCAAKCRBrQYTh
Ra8v/sm3Agjl0YO73iEpu1z1wGtlUnACi21ti2PJNGlyi84yvDQED0+mxhhTRQYz
3ESaS1s/+4psP4aH0jeVQhce15a9RqfX+AIHam7i8K/tiKFweEjpyMCB594zLzY6
lWbUf1/1a+tNv3B6yuIwFB1LY1B4HNrze5DUnngEOkmQf2esw/4nQGB87Rm5AJcE
TVMVAhIFK4EEACMEIwQBsRFES0RLIOcCyO18cq2GaphSGXqZtyvtHQt7PKmVNrSw
UuxNClntOe8/DLdq5mYDwNsbT8vi08PyQgiNsdJkcIgAlAayAGB556GKHEmP1JC7
lCUxRi/2ecJS0bf6iTTqTqZWEFhYs2aXESwFFt3V4mga/OyTGXOpnauHZ22pVLCz
6kADAQoJiQCoBBgTCgAMBQJNUxUCBRsMAAAAAAoJEGtBhOFFry/++p0CCQFJgUCn
kiTKCNfP8Q/MO2BCp1QyESk53GJlCgIBAoa7U6X2fQxe2+OU+PNCjicJmZiSrV6x
6nYfGJ5Jx753sqJWtwIJAc9ZxCQhj4V52FmbPYexZPPneIdeCDjtowD6KUZxiS0K
eD8EzdmeJQWBQsnPtJC/JJL4zz6JyYMXf4jIb5JyGNQC
=5yaB
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: PGP Command Line v10.2.0 (Linux)

lQEIBE1TFQITBSuBBAAjBCMEAWuwULfE2XoQmJhSQZ8rT5Ecr/kooudn4043gXHy
NZEdTeFfY2G7kwEaxj8TXfd1U1b4PkEoqhzKxhz/MHK/lwi2ARzW1XQiJ1/kFPsv
IUnQI1CUS099WKKQhD8JMPPyje1dKfjFjm2gzyF3TOMX1Cyy8wFyF0MiHVgB3ezb
w7C6jY+3/gcDAv+CotECRPpSqGkqKrz+xAhAqswHXzFIBprFF0XiDooWktZSTAUR
JVB2U6m28wC4rE3RkqFeR1B+kg4nxEAJ9k6BI8oDE0iyOY5aklF2TxPpTs/BA+N2
O4hnXb1l5qXfuyd3bSwDeyfq3CdFe4TeKp7vtCRlY19kc2FfZGhfNTIxIDxvcGVu
cGdwQGJyYWluaHViLm9yZz6dAQwETVMVAhIFK4EEACMEIwQBsRFES0RLIOcCyO18
cq2GaphSGXqZtyvtHQt7PKmVNrSwUuxNClntOe8/DLdq5mYDwNsbT8vi08PyQgiN
sdJkcIgAlAayAGB556GKHEmP1JC7lCUxRi/2ecJS0bf6iTTqTqZWEFhYs2aXESwF
Ft3V4mga/OyTGXOpnauHZ22pVLCz6kADAQoJ/gkDAki71k/zBW2qqGyScDNNuWaA
9A5aWhpNNyRrFembt7f/W+b591G3twdNmdCIh29VoOmQw3fO8wwgsPTUxQFgd8J3
ncft0zciEcDZi/ztLZA3+rIIP2myZLIs9xLG+k+gf3nXpeED4uYqQX3GL+32PKwg
=Qnd8
-----END PGP PRIVATE KEY BLOCK-----
');
insert into encdata (id, data) values (100, '
-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.1.0-ecc (GNU/Linux)

hH4Dd863o0CJq3MSAgMEHdIYZQx+rV1cjy7qitIOEICFFzp4cjsRX4r+rDdMcQUs
h7VZmbP1c9C0s9sgCKwubWfkcYUl2ZOju4gy+s4MYTBb4/j8JjnJ9Bqn6LWutTXJ
zwsdP13VIJLnhiNqISdR3/6xWQ0ICRYzwb95nUZ1c1DSVgFpjPgUvi4pgYbTpcDB
jzILKWBfBDT/jck169XE8vgtbcqVQYZ7lZpaY9CzEbC+4dXZmV1gm5MafpTyFWgH
VnyrZB4gad9Lp9e0RKHHcOOE7s/NeLuu
=odUZ
-----END PGP MESSAGE-----
');
insert into encdata (id, data) values (103, '
-----BEGIN PGP MESSAGE-----
Version: PGP Command Line v10.2.0 (Linux)

qANQR1DBngOqi5OPmiAZRhIDAwQqIr/00cJyf+QP+VA4QKVkk77KMHdz9OVaR2XK
0VYu0F/HPm89vL2orfm2hrAZxY9G2R0PG4Wk5Lg04UjKca/O72uWtjdPYulFidmo
uB0QpzXFz22ZZinxeVPLPEr19Pow0EwCc95cg4HAgrD0nV9vRcTJ/+juVfvsJhAO
isMKqrFNMvwnK5A1ECeyVXe7oLZl0lUBRhLr59QTtvf85QJjg/m5kaGy8XCJvLv3
61pZa6KUmw89PjtPak7ebcjnINL01vwmyeg1PAyW/xjeGGvcO+R4P1b4ewyFnJyR
svzIJcP7d4DqYOw7
=oiTJ
-----END PGP MESSAGE-----
');
insert into encdata (id, data) values (105, '
-----BEGIN PGP MESSAGE-----
Version: PGP Command Line v10.2.0 (Linux)

qANQR1DBwAIDB+qqSKgcSDgSBCMEAKpzTUxB4c56C7g09ekD9I+ttC5ER/xzDmXU
OJmFqU5w3FllhFj4TgGxxdH+8fv4W2Ag0IKoJvIY9V1V7oUCClfqAR01QbN7jGH/
I9GFFnH19AYEgMKgFmh14ZwN1BS6/VHh+H4apaYqapbx8/09EL+DV9zWLX4GRLXQ
VqCR1N2rXE29MJFzGmDOCueQNkUjcbuenoCSKcNT+6xhO27U9IYVCg4BhRUDGfD6
dhfRzBLxL+bKR9JVAe46+K8NLjRVu/bd4Iounx4UF5dBk8ERy+/8k9XantDoQgo6
RPqCad4Dg/QqkpbK3y574ds3VFNJmc4dVpsXm7lGV5w0FBxhVNPoWNhhECMlTroX
Rg==
=5GqW
-----END PGP MESSAGE-----
');

set bytea_output = 'escape';
\set ECHO all

select pgp_key_id(dearmor(pubkey)) from keytbl k where k.id = 100;
select pgp_key_id(dearmor(seckey)) from keytbl k where k.id = 100;
select pgp_key_id(dearmor(data)) from encdata where id = 100;
select pgp_key_id(dearmor(pubkey)) from keytbl k where k.id = 102;
select pgp_key_id(dearmor(seckey)) from keytbl k where k.id = 102;
select pgp_key_id(dearmor(pubkey)) from keytbl k where k.id = 103;
select pgp_key_id(dearmor(seckey)) from keytbl k where k.id = 103;
select pgp_key_id(dearmor(data)) from encdata where id = 103;
select pgp_key_id(dearmor(pubkey)) from keytbl k where k.id = 105;
select pgp_key_id(dearmor(seckey)) from keytbl k where k.id = 105;
select pgp_key_id(dearmor(data)) from encdata where id = 105;



select pgp_pub_decrypt_bytea(dearmor(data), dearmor(seckey), 'ecc')
from keytbl, encdata where keytbl.id=100 and encdata.id=100;

select pgp_pub_decrypt_bytea(dearmor(data), dearmor(seckey), 'ecc')
from keytbl, encdata where keytbl.id=103 and encdata.id=103;

select pgp_pub_decrypt_bytea(dearmor(data), dearmor(seckey), 'ecc')
from keytbl, encdata where keytbl.id=105 and encdata.id=105;

insert into encdata (id, data)
select 201, armor(pgp_pub_encrypt('test with ec256', dearmor(pubkey)))
  from keytbl k where k.id = 100;
-- select data from encdata where id = 201;
select pgp_pub_decrypt(dearmor(data), dearmor(seckey), 'ecc')
  from keytbl, encdata where keytbl.id=100 and encdata.id=201;

insert into encdata (id, data)
select 203, armor(pgp_pub_encrypt('test with ec384', dearmor(pubkey)))
  from keytbl k where k.id = 103;
-- select data from encdata where id = 203;
select pgp_pub_decrypt(dearmor(data), dearmor(seckey), 'ecc')
  from keytbl, encdata where keytbl.id=103 and encdata.id=203;

insert into encdata (id, data)
select 205, armor(pgp_pub_encrypt('test with ec521', dearmor(pubkey)))
  from keytbl k where k.id = 105;
-- select data from encdata where id = 205;
select pgp_pub_decrypt(dearmor(data), dearmor(seckey), 'ecc')
  from keytbl, encdata where keytbl.id=105 and encdata.id=205;

