# Bandit Report


**High Severity**: 108

**Medium Severity**: 205

**Low Severity**: 152

**Undefined Severity**: 0

**Lines of Code**: 8438

**Lines Purposefully Skipped**: 22


## Issues


### Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**Test**: assert_used (B101)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/703.html)

`bandit-main/examples/assert.py`

```
1 assert True
```


### Possible binding to all interfaces.

**Test**: hardcoded_bind_all_interfaces (B104)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/605.html)

`bandit-main/examples/binding.py`

```
3 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
4 s.bind(('0.0.0.0', 31137))
5 s.bind(('192.168.0.1', 8080))
```


### Use of insecure cipher mode cryptography.hazmat.primitives.ciphers.modes.ECB.

**Test**: blacklist (B305)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/cipher-modes.py`

```
5 # Insecure mode
6 mode = ECB(iv)
7 
```


### The pyCrypto library and its module ARC2 are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
1 from Crypto.Cipher import ARC2 as pycrypto_arc2
2 from Crypto.Cipher import ARC4 as pycrypto_arc4
3 from Crypto.Cipher import Blowfish as pycrypto_blowfish
```


### The pyCrypto library and its module ARC4 are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
1 from Crypto.Cipher import ARC2 as pycrypto_arc2
2 from Crypto.Cipher import ARC4 as pycrypto_arc4
3 from Crypto.Cipher import Blowfish as pycrypto_blowfish
```


### The pyCrypto library and its module Blowfish are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
2 from Crypto.Cipher import ARC4 as pycrypto_arc4
3 from Crypto.Cipher import Blowfish as pycrypto_blowfish
4 from Crypto.Cipher import DES as pycrypto_des
```


### The pyCrypto library and its module DES are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
3 from Crypto.Cipher import Blowfish as pycrypto_blowfish
4 from Crypto.Cipher import DES as pycrypto_des
5 from Crypto.Cipher import XOR as pycrypto_xor
```


### The pyCrypto library and its module XOR are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
4 from Crypto.Cipher import DES as pycrypto_des
5 from Crypto.Cipher import XOR as pycrypto_xor
6 from Cryptodome.Cipher import ARC2 as pycryptodomex_arc2
```


### The pyCrypto library and its module SHA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
10 from Cryptodome.Cipher import XOR as pycryptodomex_xor
11 from Crypto.Hash import SHA
12 from Crypto import Random
```


### The pyCrypto library and its module Random are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
11 from Crypto.Hash import SHA
12 from Crypto import Random
13 from Crypto.Util import Counter
```


### The pyCrypto library and its module Counter are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
12 from Crypto import Random
13 from Crypto.Util import Counter
14 from cryptography.hazmat.primitives.ciphers import Cipher
```


### Use of insecure cipher Crypto.Cipher.ARC2.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
21 iv = Random.new().read(pycrypto_arc2.block_size)
22 cipher = pycrypto_arc2.new(key, pycrypto_arc2.MODE_CFB, iv)
23 msg = iv + cipher.encrypt(b'Attack at dawn')
```


### Use of insecure cipher Cryptodome.Cipher.ARC2.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
23 msg = iv + cipher.encrypt(b'Attack at dawn')
24 cipher = pycryptodomex_arc2.new(key, pycryptodomex_arc2.MODE_CFB, iv)
25 msg = iv + cipher.encrypt(b'Attack at dawn')
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
28 nonce = Random.new().read(16)
29 tempkey = SHA.new(key+nonce).digest()
30 cipher = pycrypto_arc4.new(tempkey)
```


### Use of insecure cipher Crypto.Cipher.ARC4.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
29 tempkey = SHA.new(key+nonce).digest()
30 cipher = pycrypto_arc4.new(tempkey)
31 msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')
```


### Use of insecure cipher Cryptodome.Cipher.ARC4.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
31 msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')
32 cipher = pycryptodomex_arc4.new(tempkey)
33 msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')
```


### Use of insecure cipher Crypto.Cipher.Blowfish.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
41 bs = pycrypto_blowfish.block_size
42 cipher = pycrypto_blowfish.new(key, pycrypto_blowfish.MODE_CBC, iv)
43 msg = iv + cipher.encrypt(plaintext + padding)
```


### Use of insecure cipher Cryptodome.Cipher.Blowfish.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
44 bs = pycryptodomex_blowfish.block_size
45 cipher = pycryptodomex_blowfish.new(key, pycryptodomex_blowfish.MODE_CBC, iv)
46 msg = iv + cipher.encrypt(plaintext + padding)
```


### Use of insecure cipher Crypto.Cipher.DES.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
51 ctr = Counter.new(pycrypto_des.block_size*8/2, prefix=nonce)
52 cipher = pycrypto_des.new(key, pycrypto_des.MODE_CTR, counter=ctr)
53 msg = nonce + cipher.encrypt(plaintext)
```


### Use of insecure cipher Cryptodome.Cipher.DES.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
55 ctr = Counter.new(pycryptodomex_des.block_size*8/2, prefix=nonce)
56 cipher = pycryptodomex_des.new(key, pycryptodomex_des.MODE_CTR, counter=ctr)
57 msg = nonce + cipher.encrypt(plaintext)
```


### Use of insecure cipher Crypto.Cipher.XOR.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
60 plaintext = b'Encrypt me'
61 cipher = pycrypto_xor.new(key)
62 msg = cipher.encrypt(plaintext)
```


### Use of insecure cipher Cryptodome.Cipher.XOR.new. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
62 msg = cipher.encrypt(plaintext)
63 cipher = pycryptodomex_xor.new(key)
64 msg = cipher.encrypt(plaintext)
```


### Use of insecure cipher cryptography.hazmat.primitives.ciphers.algorithms.ARC4. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
65 
66 cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
67 encryptor = cipher.encryptor()
```


### Use of insecure cipher cryptography.hazmat.primitives.ciphers.algorithms.Blowfish. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
69 
70 cipher = Cipher(algorithms.Blowfish(key), mode=None, backend=default_backend())
71 encryptor = cipher.encryptor()
```


### Use of insecure cipher cryptography.hazmat.primitives.ciphers.algorithms.IDEA. Replace with a known secure cipher such as AES.

**Test**: blacklist (B304)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ciphers.py`

```
73 
74 cipher = Cipher(algorithms.IDEA(key), mode=None, backend=default_backend())
75 encryptor = cipher.encryptor()
```


### The pyCrypto library and its module MD2 are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
1 from cryptography.hazmat.primitives import hashes
2 from Crypto.Hash import MD2 as pycrypto_md2
3 from Crypto.Hash import MD4 as pycrypto_md4
```


### The pyCrypto library and its module MD4 are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
2 from Crypto.Hash import MD2 as pycrypto_md2
3 from Crypto.Hash import MD4 as pycrypto_md4
4 from Crypto.Hash import MD5 as pycrypto_md5
```


### The pyCrypto library and its module MD5 are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
3 from Crypto.Hash import MD4 as pycrypto_md4
4 from Crypto.Hash import MD5 as pycrypto_md5
5 from Crypto.Hash import SHA as pycrypto_sha
```


### The pyCrypto library and its module SHA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
4 from Crypto.Hash import MD5 as pycrypto_md5
5 from Crypto.Hash import SHA as pycrypto_sha
6 from Cryptodome.Hash import MD2 as pycryptodomex_md2
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
11 
12 hashlib.md5(1)
13 hashlib.md5(1).hexdigest()
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
12 hashlib.md5(1)
13 hashlib.md5(1).hexdigest()
14 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
14 
15 abc = str.replace(hashlib.md5("1"), "###")
16 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
16 
17 print(hashlib.md5("1"))
18 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
18 
19 hashlib.sha1(1)
20 
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
22 
23 pycrypto_md2.new()
24 pycrypto_md4.new()
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
23 pycrypto_md2.new()
24 pycrypto_md4.new()
25 pycrypto_md5.new()
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
24 pycrypto_md4.new()
25 pycrypto_md5.new()
26 pycrypto_sha.new()
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
25 pycrypto_md5.new()
26 pycrypto_sha.new()
27 
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
27 
28 pycryptodomex_md2.new()
29 pycryptodomex_md4.new()
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
28 pycryptodomex_md2.new()
29 pycryptodomex_md4.new()
30 pycryptodomex_md5.new()
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
29 pycryptodomex_md4.new()
30 pycryptodomex_md5.new()
31 pycryptodomex_sha.new()
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
30 pycryptodomex_md5.new()
31 pycryptodomex_sha.new()
32 
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
32 
33 hashes.MD5()
34 hashes.SHA1()
```


### Use of insecure MD2, MD4, MD5, or SHA1 hash function.

**Test**: blacklist (B303)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/crypto-md5.py`

```
33 hashes.MD5()
34 hashes.SHA1()
```


### Consider possible security implications associated with dill module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/dill.py`

```
1 import dill
2 import StringIO
3 
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/dill.py`

```
5 pick = dill.dumps({'a': 'b', 'c': 'd'})
6 print(dill.loads(pick))
7 
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/dill.py`

```
10 file_obj.seek(0)
11 print(dill.load(file_obj))
12 
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
11 
12 User.objects.filter(username='admin').extra(dict(could_be='insecure'))
13 User.objects.filter(username='admin').extra(select=dict(could_be='insecure'))
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
12 User.objects.filter(username='admin').extra(dict(could_be='insecure'))
13 User.objects.filter(username='admin').extra(select=dict(could_be='insecure'))
14 query = '"username") AS "username", * FROM "auth_user" WHERE 1=1 OR "username"=? --'
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
14 query = '"username") AS "username", * FROM "auth_user" WHERE 1=1 OR "username"=? --'
15 User.objects.filter(username='admin').extra(select={'test': query})
16 User.objects.filter(username='admin').extra(select={'test': '%secure' % 'nos'})
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
15 User.objects.filter(username='admin').extra(select={'test': query})
16 User.objects.filter(username='admin').extra(select={'test': '%secure' % 'nos'})
17 User.objects.filter(username='admin').extra(select={'test': '{}secure'.format('nos')})
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
16 User.objects.filter(username='admin').extra(select={'test': '%secure' % 'nos'})
17 User.objects.filter(username='admin').extra(select={'test': '{}secure'.format('nos')})
18 
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
19 where_var = ['1=1) OR 1=1 AND (1=1']
20 User.objects.filter(username='admin').extra(where=where_var)
21 where_str = '1=1) OR 1=1 AND (1=1'
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
21 where_str = '1=1) OR 1=1 AND (1=1'
22 User.objects.filter(username='admin').extra(where=[where_str])
23 User.objects.filter(username='admin').extra(where=['%secure' % 'nos'])
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
22 User.objects.filter(username='admin').extra(where=[where_str])
23 User.objects.filter(username='admin').extra(where=['%secure' % 'nos'])
24 User.objects.filter(username='admin').extra(where=['{}secure'.format('no')])
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
23 User.objects.filter(username='admin').extra(where=['%secure' % 'nos'])
24 User.objects.filter(username='admin').extra(where=['{}secure'.format('no')])
25 
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
26 tables_var = ['django_content_type" WHERE "auth_user"."username"="admin']
27 User.objects.all().extra(tables=tables_var).distinct()
28 tables_str = 'django_content_type" WHERE "auth_user"."username"="admin'
```


### Use of extra potential SQL attack vector.

**Test**: django_extra_used (B610)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_extra.py`

```
28 tables_str = 'django_content_type" WHERE "auth_user"."username"="admin'
29 User.objects.all().extra(tables=[tables_str]).distinct()
```


### Use of RawSQL potential SQL attack vector.

**Test**: django_rawsql_used (B611)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_raw.py`

```
4 User.objects.annotate(val=RawSQL('secure', []))
5 User.objects.annotate(val=RawSQL('%secure' % 'nos', []))
6 User.objects.annotate(val=RawSQL('{}secure'.format('no'), []))
```


### Use of RawSQL potential SQL attack vector.

**Test**: django_rawsql_used (B611)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_raw.py`

```
5 User.objects.annotate(val=RawSQL('%secure' % 'nos', []))
6 User.objects.annotate(val=RawSQL('{}secure'.format('no'), []))
7 raw = '"username") AS "val" FROM "auth_user" WHERE "username"="admin" --'
```


### Use of RawSQL potential SQL attack vector.

**Test**: django_rawsql_used (B611)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_raw.py`

```
7 raw = '"username") AS "val" FROM "auth_user" WHERE "username"="admin" --'
8 User.objects.annotate(val=RawSQL(raw, []))
9 raw = '"username") AS "val" FROM "auth_user"' \
```


### Use of RawSQL potential SQL attack vector.

**Test**: django_rawsql_used (B611)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/django_sql_injection_raw.py`

```
10       ' WHERE "username"="admin" OR 1=%s --'
11 User.objects.annotate(val=RawSQL(raw, [0]))
```


### Use of possibly insecure function - consider using safer ast.literal_eval.

**Test**: blacklist (B307)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/eval.py`

```
2 
3 print(eval("1+1"))
4 print(eval("os.getcwd()"))
```


### Use of possibly insecure function - consider using safer ast.literal_eval.

**Test**: blacklist (B307)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/eval.py`

```
3 print(eval("1+1"))
4 print(eval("os.getcwd()"))
5 print(eval("os.chmod('%s', 0777)" % 'test.txt'))
```


### Use of possibly insecure function - consider using safer ast.literal_eval.

**Test**: blacklist (B307)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/eval.py`

```
4 print(eval("os.getcwd()"))
5 print(eval("os.chmod('%s', 0777)" % 'test.txt'))
6 
```


### Use of exec detected.

**Test**: exec_used (B102)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/exec.py`

```
1 exec("do evil")
```


### A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.

**Test**: flask_debug_true (B201)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/94.html)

`bandit-main/examples/flask_debug.py`

```
9 #bad
10 app.run(debug=True)
11 
```


### A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.

**Test**: blacklist (B402)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/319.html)

`bandit-main/examples/ftplib.py`

```
1 from ftplib import FTP
2 
3 ftp = FTP('ftp.debian.org')
4 ftp.login()
```


### FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.

**Test**: blacklist (B321)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/319.html)

`bandit-main/examples/ftplib.py`

```
2 
3 ftp = FTP('ftp.debian.org')
4 ftp.login()
```


### Possible hardcoded password: 'class_password'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
3 class SomeClass:
4     password = "class_password"
5 
```


### Possible hardcoded password: 'Admin'

**Test**: hardcoded_password_default (B107)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
7 # Severity: Low   Confidence: Medium
8 def someFunction(user, password="Admin"):
9     print("Hi " + user)
10 
11 def someFunction2(password):
```


### Possible hardcoded password: 'root'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
13     # Severity: Low   Confidence: Medium
14     if password == "root":
15         print("OK, logged in")
```


### Possible hardcoded password: ''

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
19     # Severity: Low   Confidence: Medium
20     if password == '':
21         print("No password!")
```


### Possible hardcoded password: 'ajklawejrkl42348swfgkg'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
25     # Severity: Low   Confidence: Medium
26     if password == "ajklawejrkl42348swfgkg":
27         print("Nice password!")
```


### Possible hardcoded password: 'this cool password'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
32     # Severity: Low   Confidence: Medium
33     if obj.password == "this cool password":
34         print(obj.password)
```


### Possible hardcoded password: 'blerg'

**Test**: hardcoded_password_default (B107)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
37 # Severity: Low   Confidence: Medium
38 def doLogin(password="blerg"):
39     pass
40 
41 def NoMatch3(a, b):
```


### Possible hardcoded password: 'blerg'

**Test**: hardcoded_password_funcarg (B106)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
45 # Severity: Low   Confidence: Medium
46 doLogin(password="blerg")
47 
```


### Possible hardcoded password: 'blerg'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
49 # Severity: Low   Confidence: Medium
50 password = "blerg"
51 
52 # Possible hardcoded password: 'blerg'
53 # Severity: Low   Confidence: Medium
54 d["password"] = "blerg"
```


### Possible hardcoded password: 'blerg'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
53 # Severity: Low   Confidence: Medium
54 d["password"] = "blerg"
55 
```


### Possible hardcoded password: 'secret'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
57 # Severity: Low   Confidence: Medium
58 EMAIL_PASSWORD = "secret"
59 
60 # Possible hardcoded password: 'emails_secret'
61 # Severity: Low   Confidence: Medium
62 email_pwd = 'emails_secret'
```


### Possible hardcoded password: 'emails_secret'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
61 # Severity: Low   Confidence: Medium
62 email_pwd = 'emails_secret'
63 
64 # Possible hardcoded password: 'd6s$f9g!j8mg7hw?n&2'
65 # Severity: Low   Confidence: Medium
66 my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'
```


### Possible hardcoded password: 'd6s$f9g!j8mg7hw?n&2'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
65 # Severity: Low   Confidence: Medium
66 my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'
67 
68 # Possible hardcoded password: '1234'
69 # Severity: Low   Confidence: Medium
70 passphrase='1234'
```


### Possible hardcoded password: '1234'

**Test**: hardcoded_password_string (B105)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/hardcoded-passwords.py`

```
69 # Severity: Low   Confidence: Medium
70 passphrase='1234'
```


### Probable insecure usage of temp file/directory.

**Test**: hardcoded_tmp_directory (B108)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/377.html)

`bandit-main/examples/hardcoded-tmp.py`

```
1 with open('/tmp/abc', 'w') as f:
2     f.write('def')
3 
```


### Probable insecure usage of temp file/directory.

**Test**: hardcoded_tmp_directory (B108)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/377.html)

`bandit-main/examples/hardcoded-tmp.py`

```
7 
8 with open('/var/tmp/123', 'w') as f:
9     f.write('def')
```


### Probable insecure usage of temp file/directory.

**Test**: hardcoded_tmp_directory (B108)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/377.html)

`bandit-main/examples/hardcoded-tmp.py`

```
10 
11 with open('/dev/shm/unit/test', 'w') as f:
12     f.write('def')
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
2 
3 hashlib.new('md5')
4 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
4 
5 hashlib.new('md4', b'test')
6 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
6 
7 hashlib.new(name='md5', data=b'test')
8 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
8 
9 hashlib.new('MD4', data=b'test')
10 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
10 
11 hashlib.new('sha1')
12 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
12 
13 hashlib.new('sha1', data=b'test')
14 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
14 
15 hashlib.new('sha', data=b'test')
16 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
16 
17 hashlib.new(name='SHA', data=b'test')
18 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/hashlib_new_insecure_functions.py`

```
19 # usedforsecurity arg only availabe in Python 3.9+
20 hashlib.new('sha1', usedforsecurity=True)
21 
```


### Consider possible security implications associated with wsgiref.handlers.CGIHandler module.

**Test**: blacklist (B412)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/284.html)

`bandit-main/examples/httpoxy_cgihandler.py`

```
9 if __name__ == '__main__':
10     wsgiref.handlers.CGIHandler().run(application)
```


### Consider possible security implications associated with twisted.web.twcgi.CGIDirectory module.

**Test**: blacklist (B412)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/284.html)

`bandit-main/examples/httpoxy_twisted_directory.py`

```
4 root = static.File("/root")
5 root.putChild("cgi-bin", twcgi.CGIDirectory("/var/www/cgi-bin"))
6 reactor.listenTCP(80, server.Site(root))
```


### Consider possible security implications associated with twisted.web.twcgi.CGIScript module.

**Test**: blacklist (B412)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/284.html)

`bandit-main/examples/httpoxy_twisted_script.py`

```
4 root = static.File("/root")
5 root.putChild("login.cgi", twcgi.CGIScript("/var/www/cgi-bin/login.py"))
6 reactor.listenTCP(80, server.Site(root))
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-aliases.py`

```
1 from subprocess import Popen as pop
2 import hashlib as h
3 import hashlib as hh
```


### Consider possible security implications associated with loads module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/imports-aliases.py`

```
5 import hashlib as hhhh
6 from pickle import loads as lp
7 import pickle as p
```


### Consider possible security implications associated with pickle module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/imports-aliases.py`

```
6 from pickle import loads as lp
7 import pickle as p
8 
9 pop('/bin/gcc --version', shell=True)
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-aliases.py`

```
8 
9 pop('/bin/gcc --version', shell=True)
10 
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/imports-aliases.py`

```
10 
11 h.md5('1')
12 hh.md5('2')
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/imports-aliases.py`

```
11 h.md5('1')
12 hh.md5('2')
13 hhh.md5('3').hexdigest()
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/imports-aliases.py`

```
12 hh.md5('2')
13 hhh.md5('3').hexdigest()
14 hhhh.md5('4')
```


### Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

**Test**: hashlib (B324)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/imports-aliases.py`

```
13 hhh.md5('3').hexdigest()
14 hhhh.md5('4')
15 lp({'key': 'value'})
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/imports-aliases.py`

```
14 hhhh.md5('4')
15 lp({'key': 'value'})
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-from.py`

```
1 from subprocess import Popen
2 
3 from ..foo import sys
4 from . import sys
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-from.py`

```
5 from .. import sys
6 from .. import subprocess
7 from ..subprocess import Popen
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-from.py`

```
6 from .. import subprocess
7 from ..subprocess import Popen
```


### Consider possible security implications associated with pickle module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/imports-function.py`

```
1 os = __import__("os")
2 pickle = __import__("pickle")
3 sys = __import__("sys")
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-function.py`

```
3 sys = __import__("sys")
4 subprocess = __import__("subprocess")
5 
```


### Consider possible security implications associated with pickle module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/imports-with-importlib.py`

```
2 a = importlib.import_module('os')
3 b = importlib.import_module('pickle')
4 c = importlib.__import__('sys')
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-with-importlib.py`

```
4 c = importlib.__import__('sys')
5 d = importlib.__import__('subprocess')
6 
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-with-importlib.py`

```
12 g = importlib.import_module(name='sys')
13 h = importlib.__import__(name='subprocess')
14 i = importlib.import_module(name='subprocess', package='bar.baz')
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports-with-importlib.py`

```
13 h = importlib.__import__(name='subprocess')
14 i = importlib.import_module(name='subprocess', package='bar.baz')
15 j = importlib.__import__(name='sys', package='bar.baz')
```


### Consider possible security implications associated with pickle module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/imports.py`

```
1 import os
2 import pickle
3 import sys
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/imports.py`

```
3 import sys
4 import subprocess
```


### Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Ensure autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

**Test**: jinja2_autoescape_false (B701)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/94.html)

`bandit-main/examples/jinja2_templating.py`

```
8         loader=templateLoader )
9 Environment(loader=templateLoader, load=templateLoader, autoescape=something)
10 templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )
```


### Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Use autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

**Test**: jinja2_autoescape_false (B701)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/94.html)

`bandit-main/examples/jinja2_templating.py`

```
9 Environment(loader=templateLoader, load=templateLoader, autoescape=something)
10 templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )
11 Environment(loader=templateLoader,
```


### Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Use autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

**Test**: jinja2_autoescape_false (B701)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/94.html)

`bandit-main/examples/jinja2_templating.py`

```
10 templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )
11 Environment(loader=templateLoader,
12             load=templateLoader,
13             autoescape=False)
14 
```


### By default, jinja2 sets autoescape to False. Consider using autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

**Test**: jinja2_autoescape_false (B701)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/94.html)

`bandit-main/examples/jinja2_templating.py`

```
14 
15 Environment(loader=templateLoader,
16             load=templateLoader)
17 
```


### Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Ensure autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

**Test**: jinja2_autoescape_false (B701)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/94.html)

`bandit-main/examples/jinja2_templating.py`

```
25     return 'foobar'
26 Environment(loader=templateLoader, autoescape=fake_func())
```


### Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.

**Test**: use_of_mako_templates (B702)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mako_templating.py`

```
5 
6 Template("hello")
7 
```


### Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.

**Test**: use_of_mako_templates (B702)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mako_templating.py`

```
9 # in for now so that if it gets fixed inadvertitently we know.
10 mako.template.Template("hern")
11 template.Template("hern")
```


### Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.

**Test**: use_of_mako_templates (B702)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mako_templating.py`

```
10 mako.template.Template("hern")
11 template.Template("hern")
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe.py`

```
3 mystr = '<b>Hello World</b>'
4 mystr = safestring.mark_safe(mystr)
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
9 my_insecure_str = insecure_function('insecure', cls='" onload="alert(\'xss\')')
10 safestring.mark_safe(my_insecure_str)
11 safestring.SafeText(my_insecure_str)
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
9 my_insecure_str = insecure_function('insecure', cls='" onload="alert(\'xss\')')
10 safestring.mark_safe(my_insecure_str)
11 safestring.SafeText(my_insecure_str)
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
10 safestring.mark_safe(my_insecure_str)
11 safestring.SafeText(my_insecure_str)
12 safestring.SafeUnicode(my_insecure_str)
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
11 safestring.SafeText(my_insecure_str)
12 safestring.SafeUnicode(my_insecure_str)
13 safestring.SafeString(my_insecure_str)
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
12 safestring.SafeUnicode(my_insecure_str)
13 safestring.SafeString(my_insecure_str)
14 safestring.SafeBytes(my_insecure_str)
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
13 safestring.SafeString(my_insecure_str)
14 safestring.SafeBytes(my_insecure_str)
15 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
21         my_insecure_str = 'Secure'
22     safestring.mark_safe(my_insecure_str)
23 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
21         my_insecure_str = 'Secure'
22     safestring.mark_safe(my_insecure_str)
23 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
29         my_insecure_str = insecure_function('insecure', cls=cls)
30     safestring.mark_safe(my_insecure_str)
31 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
29         my_insecure_str = insecure_function('insecure', cls=cls)
30     safestring.mark_safe(my_insecure_str)
31 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
40         my_insecure_str = insecure_function('insecure', cls=cls)
41     safestring.mark_safe(my_insecure_str)
42 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
40         my_insecure_str = insecure_function('insecure', cls=cls)
41     safestring.mark_safe(my_insecure_str)
42 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
53         my_insecure_str = insecure_function('insecure', cls=cls)
54     safestring.mark_safe(my_insecure_str)
55 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
53         my_insecure_str = insecure_function('insecure', cls=cls)
54     safestring.mark_safe(my_insecure_str)
55 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
58     my_insecure_str = insecure_function('insecure', cls=cls)
59     safestring.mark_safe('<b>{} {}</b>'.format(my_insecure_str, 'STR'))
60 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
58     my_insecure_str = insecure_function('insecure', cls=cls)
59     safestring.mark_safe('<b>{} {}</b>'.format(my_insecure_str, 'STR'))
60 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
63     my_insecure_str = insecure_function('insecure', cls=cls)
64     safestring.mark_safe('<b>{}</b>'.format(*[my_insecure_str]))
65 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
63     my_insecure_str = insecure_function('insecure', cls=cls)
64     safestring.mark_safe('<b>{}</b>'.format(*[my_insecure_str]))
65 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
68     my_insecure_str = insecure_function('insecure', cls=cls)
69     safestring.mark_safe('<b>{b}</b>'.format(b=my_insecure_str))
70 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
68     my_insecure_str = insecure_function('insecure', cls=cls)
69     safestring.mark_safe('<b>{b}</b>'.format(b=my_insecure_str))
70 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
73     my_insecure_str = insecure_function('insecure', cls=cls)
74     safestring.mark_safe('<b>{b}</b>'.format(**{'b': my_insecure_str}))
75 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
73     my_insecure_str = insecure_function('insecure', cls=cls)
74     safestring.mark_safe('<b>{b}</b>'.format(**{'b': my_insecure_str}))
75 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
78     my_insecure_str = insecure_function('insecure', cls=cls)
79     safestring.mark_safe('<b>%s</b>' % my_insecure_str)
80 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
78     my_insecure_str = insecure_function('insecure', cls=cls)
79     safestring.mark_safe('<b>%s</b>' % my_insecure_str)
80 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
83     my_insecure_str = insecure_function('insecure', cls=cls)
84     safestring.mark_safe('<b>%s %s</b>' % (my_insecure_str, 'b'))
85 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
83     my_insecure_str = insecure_function('insecure', cls=cls)
84     safestring.mark_safe('<b>%s %s</b>' % (my_insecure_str, 'b'))
85 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
88     my_insecure_str = insecure_function('insecure', cls=cls)
89     safestring.mark_safe('<b>%(b)s</b>' % {'b': my_insecure_str})
90 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
88     my_insecure_str = insecure_function('insecure', cls=cls)
89     safestring.mark_safe('<b>%(b)s</b>' % {'b': my_insecure_str})
90 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
93     import sre_constants
94     safestring.mark_safe(sre_constants.ANY)
95 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
93     import sre_constants
94     safestring.mark_safe(sre_constants.ANY)
95 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
98     import sre_constants.ANY as any_str
99     safestring.mark_safe(any_str)
100 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
98     import sre_constants.ANY as any_str
99     safestring.mark_safe(any_str)
100 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
103     from sre_constants import ANY
104     safestring.mark_safe(ANY)
105 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
103     from sre_constants import ANY
104     safestring.mark_safe(ANY)
105 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
108     from sre_constants import ANY as any_str
109     safestring.mark_safe(any_str)
110 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
108     from sre_constants import ANY as any_str
109     safestring.mark_safe(any_str)
110 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
113     with open(path) as f:
114         safestring.mark_safe(f.read())
115 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
113     with open(path) as f:
114         safestring.mark_safe(f.read())
115 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
118     with open(path) as f:
119         safestring.mark_safe(f)
120 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
118     with open(path) as f:
119         safestring.mark_safe(f)
120 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
125         my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
126     safestring.mark_safe(my_secure_str)
127 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
125         my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
126     safestring.mark_safe(my_secure_str)
127 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
132         my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
133     safestring.mark_safe(my_secure_str)
134 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
132         my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
133     safestring.mark_safe(my_secure_str)
134 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
142         my_secure_str = 'Secure'
143     safestring.mark_safe(my_secure_str)
144 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
142         my_secure_str = 'Secure'
143     safestring.mark_safe(my_secure_str)
144 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
148 def test_insecure_shadow():  # var assigned out of scope
149     safestring.mark_safe(mystr)
150 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
148 def test_insecure_shadow():  # var assigned out of scope
149     safestring.mark_safe(mystr)
150 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
152 def test_insecure(str_arg):
153     safestring.mark_safe(str_arg)
154 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
152 def test_insecure(str_arg):
153     safestring.mark_safe(str_arg)
154 
```


### Potential XSS on mark_safe function.

**Test**: django_mark_safe (B703)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/80.html)

`bandit-main/examples/mark_safe_insecure.py`

```
158         str_arg = 'could be insecure'
159     safestring.mark_safe(str_arg)
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_insecure.py`

```
158         str_arg = 'could be insecure'
159     safestring.mark_safe(str_arg)
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
3 
4 safestring.mark_safe('<b>secure</b>')
5 safestring.SafeText('<b>secure</b>')
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
10 my_secure_str = '<b>Hello World</b>'
11 safestring.mark_safe(my_secure_str)
12 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
13 my_secure_str, _ = ('<b>Hello World</b>', '')
14 safestring.mark_safe(my_secure_str)
15 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
16 also_secure_str = my_secure_str
17 safestring.mark_safe(also_secure_str)
18 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
28         my_secure_str = 'Secure'
29     safestring.mark_safe(my_secure_str)
30 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
32 def format_secure():
33     safestring.mark_safe('<b>{}</b>'.format('secure'))
34     my_secure_str = 'secure'
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
34     my_secure_str = 'secure'
35     safestring.mark_safe('<b>{}</b>'.format(my_secure_str))
36     safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
35     safestring.mark_safe('<b>{}</b>'.format(my_secure_str))
36     safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
37     safestring.mark_safe('<b>{} {}</b>'.format(*[my_secure_str, 'a']))
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
36     safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
37     safestring.mark_safe('<b>{} {}</b>'.format(*[my_secure_str, 'a']))
38     safestring.mark_safe('<b>{b}</b>'.format(b=my_secure_str))  # nosec TODO
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
40     my_secure_str = '<b>{}</b>'.format(my_secure_str)
41     safestring.mark_safe(my_secure_str)
42 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
44 def percent_secure():
45     safestring.mark_safe('<b>%s</b>' % 'secure')
46     my_secure_str = 'secure'
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
46     my_secure_str = 'secure'
47     safestring.mark_safe('<b>%s</b>' % my_secure_str)
48     safestring.mark_safe('<b>%s %s</b>' % (my_secure_str, 'a'))
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
47     safestring.mark_safe('<b>%s</b>' % my_secure_str)
48     safestring.mark_safe('<b>%s %s</b>' % (my_secure_str, 'a'))
49     safestring.mark_safe('<b>%(b)s</b>' % {'b': my_secure_str})  # nosec TODO
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
53     with open(path) as f:
54         safestring.mark_safe('Secure')
55 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
61         my_secure_str += ' Secure'
62     safestring.mark_safe(my_secure_str)
63     while ord(os.urandom(1)) % 2 == 0:
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
64         my_secure_str += ' Secure'
65     safestring.mark_safe(my_secure_str)
66 
```


### Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.

**Test**: blacklist (B308)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/79.html)

`bandit-main/examples/mark_safe_secure.py`

```
74         my_secure_str = 'Secure'
75     safestring.mark_safe(my_secure_str)
```


### Deserialization with the marshal module is possibly dangerous.

**Test**: blacklist (B302)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/marshal_deserialize.py`

```
5 serialized = marshal.dumps({'a': 1})
6 print(marshal.loads(serialized))
7 
```


### Deserialization with the marshal module is possibly dangerous.

**Test**: blacklist (B302)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/marshal_deserialize.py`

```
10 file_obj.seek(0)
11 print(marshal.load(file_obj))
12 file_obj.close()
```


### Use of insecure and deprecated function (mktemp).

**Test**: blacklist (B306)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/377.html)

`bandit-main/examples/mktemp.py`

```
6 
7 mktemp(foo)
8 tempfile.mktemp('foo')
```


### Use of insecure and deprecated function (mktemp).

**Test**: blacklist (B306)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/377.html)

`bandit-main/examples/mktemp.py`

```
7 mktemp(foo)
8 tempfile.mktemp('foo')
9 mt(foo)
```


### Use of insecure and deprecated function (mktemp).

**Test**: blacklist (B306)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/377.html)

`bandit-main/examples/mktemp.py`

```
8 tempfile.mktemp('foo')
9 mt(foo)
10 tmp.mktemp(foo)
```


### Use of insecure and deprecated function (mktemp).

**Test**: blacklist (B306)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/377.html)

`bandit-main/examples/mktemp.py`

```
9 mt(foo)
10 tmp.mktemp(foo)
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/multiline_statement.py`

```
1 import subprocess
2 
3 subprocess.check_output("/some_command",
4                         "args",
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/multiline_statement.py`

```
4                         "args",
5                         shell=True,
6                         universal_newlines=True)
7 
8 subprocess.check_output(
9     "/some_command",
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/multiline_statement.py`

```
10     "args",
11     shell=True,
12     universal_newlines=True
13 )
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/new_candidates-all.py`

```
6     # candidate #1
7     subprocess.Popen('/bin/ls *', shell=True)
8     # candidate #2
```


### Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().

**Test**: yaml_load (B506)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/new_candidates-all.py`

```
14     # candidate #3
15     y = yaml.load(temp_str)
16     # candidate #4
```


### Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B317)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/new_candidates-all.py`

```
21     # candidate #5
22     xml.sax.make_parser()
23     # candidate #6
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/new_candidates-some.py`

```
6     # candidate #1
7     subprocess.Popen('/bin/ls *', shell=True)
8     # candidate #2
```


### Paramiko call with policy set to automatically trust the unknown host key.

**Test**: ssh_no_host_key_verification (B507)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/no_host_key_verification.py`

```
3 ssh_client = client.SSHClient()
4 ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
5 ssh_client.set_missing_host_key_policy(client.WarningPolicy)
```


### Paramiko call with policy set to automatically trust the unknown host key.

**Test**: ssh_no_host_key_verification (B507)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/no_host_key_verification.py`

```
4 ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
5 ssh_client.set_missing_host_key_policy(client.WarningPolicy)
```


### Starting a process with a partial executable path

**Test**: start_process_with_partial_path (B607)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/nosec.py`

```
5                  shell=True)  #nosec (on the specific kwarg line)
6 subprocess.Popen('#nosec', shell=True)
7 subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec # noqa: E501 ; pylint: disable=line-too-long
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/nosec.py`

```
5                  shell=True)  #nosec (on the specific kwarg line)
6 subprocess.Popen('#nosec', shell=True)
7 subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec # noqa: E501 ; pylint: disable=line-too-long
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/nosec.py`

```
7 subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec # noqa: E501 ; pylint: disable=line-too-long
8 subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec B607 # noqa: E501 ; pylint: disable=line-too-long
9 subprocess.Popen('/bin/ls *', shell=True)  #nosec subprocess_popen_with_shell_equals_true (on the line)
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/nosec.py`

```
13 subprocess.Popen('/bin/ls *', shell=True) # type: ... # noqa: E501 ; pylint: disable=line-too-long # nosec
14 subprocess.Popen('#nosec', shell=True) # nosec B607, B101
15 subprocess.Popen('#nosec', shell=True) # nosec B602, subprocess_popen_with_shell_equals_true
```


### Starting a process with a partial executable path

**Test**: start_process_with_partial_path (B607)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/nosec.py`

```
14 subprocess.Popen('#nosec', shell=True) # nosec B607, B101
15 subprocess.Popen('#nosec', shell=True) # nosec B602, subprocess_popen_with_shell_equals_true
```


### Chmod setting a permissive mask 0o227 on file (/etc/passwd).

**Test**: set_bad_file_permissions (B103)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
5 
6 os.chmod('/etc/passwd', 0o227)
7 os.chmod('/etc/passwd', 0o7)
```


### Chmod setting a permissive mask 0o7 on file (/etc/passwd).

**Test**: set_bad_file_permissions (B103)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
6 os.chmod('/etc/passwd', 0o227)
7 os.chmod('/etc/passwd', 0o7)
8 os.chmod('/etc/passwd', 0o664)
```


### Chmod setting a permissive mask 0o777 on file (/etc/passwd).

**Test**: set_bad_file_permissions (B103)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
8 os.chmod('/etc/passwd', 0o664)
9 os.chmod('/etc/passwd', 0o777)
10 os.chmod('/etc/passwd', 0o770)
```


### Chmod setting a permissive mask 0o770 on file (/etc/passwd).

**Test**: set_bad_file_permissions (B103)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
9 os.chmod('/etc/passwd', 0o777)
10 os.chmod('/etc/passwd', 0o770)
11 os.chmod('/etc/passwd', 0o776)
```


### Chmod setting a permissive mask 0o776 on file (/etc/passwd).

**Test**: set_bad_file_permissions (B103)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
10 os.chmod('/etc/passwd', 0o770)
11 os.chmod('/etc/passwd', 0o776)
12 os.chmod('/etc/passwd', 0o760)
```


### Chmod setting a permissive mask 0o777 on file (~/.bashrc).

**Test**: set_bad_file_permissions (B103)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
12 os.chmod('/etc/passwd', 0o760)
13 os.chmod('~/.bashrc', 511)
14 os.chmod('/etc/hosts', 0o777)
```


### Chmod setting a permissive mask 0o777 on file (/etc/hosts).

**Test**: set_bad_file_permissions (B103)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
13 os.chmod('~/.bashrc', 511)
14 os.chmod('/etc/hosts', 0o777)
15 os.chmod('/tmp/oh_hai', 0x1ff)
```


### Chmod setting a permissive mask 0o777 on file (/tmp/oh_hai).

**Test**: set_bad_file_permissions (B103)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
14 os.chmod('/etc/hosts', 0o777)
15 os.chmod('/tmp/oh_hai', 0x1ff)
16 os.chmod('/etc/passwd', stat.S_IRWXU)
```


### Probable insecure usage of temp file/directory.

**Test**: hardcoded_tmp_directory (B108)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/377.html)

`bandit-main/examples/os-chmod.py`

```
14 os.chmod('/etc/hosts', 0o777)
15 os.chmod('/tmp/oh_hai', 0x1ff)
16 os.chmod('/etc/passwd', stat.S_IRWXU)
```


### Chmod setting a permissive mask 0o777 on file (key_file).

**Test**: set_bad_file_permissions (B103)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/732.html)

`bandit-main/examples/os-chmod.py`

```
16 os.chmod('/etc/passwd', stat.S_IRWXU)
17 os.chmod(key_file, 0o777)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-exec.py`

```
2 
3 os.execl(path, arg0, arg1)
4 os.execle(path, arg0, arg1, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-exec.py`

```
3 os.execl(path, arg0, arg1)
4 os.execle(path, arg0, arg1, env)
5 os.execlp(file, arg0, arg1)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-exec.py`

```
4 os.execle(path, arg0, arg1, env)
5 os.execlp(file, arg0, arg1)
6 os.execlpe(file, arg0, arg1, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-exec.py`

```
5 os.execlp(file, arg0, arg1)
6 os.execlpe(file, arg0, arg1, env)
7 os.execv(path, args)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-exec.py`

```
6 os.execlpe(file, arg0, arg1, env)
7 os.execv(path, args)
8 os.execve(path, args, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-exec.py`

```
7 os.execv(path, args)
8 os.execve(path, args, env)
9 os.execvp(file, args)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-exec.py`

```
8 os.execve(path, args, env)
9 os.execvp(file, args)
10 os.execvpe(file, args, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-exec.py`

```
9 os.execvp(file, args)
10 os.execvpe(file, args, env)
11 
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
5 
6 os.popen('/bin/uname -av')
7 popen('/bin/uname -av')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
6 os.popen('/bin/uname -av')
7 popen('/bin/uname -av')
8 o.popen('/bin/uname -av')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
7 popen('/bin/uname -av')
8 o.popen('/bin/uname -av')
9 pos('/bin/uname -av')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
8 o.popen('/bin/uname -av')
9 pos('/bin/uname -av')
10 os.popen2('/bin/uname -av')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
9 pos('/bin/uname -av')
10 os.popen2('/bin/uname -av')
11 os.popen3('/bin/uname -av')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
10 os.popen2('/bin/uname -av')
11 os.popen3('/bin/uname -av')
12 os.popen4('/bin/uname -av')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
11 os.popen3('/bin/uname -av')
12 os.popen4('/bin/uname -av')
13 
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
13 
14 os.popen4('/bin/uname -av; rm -rf /')
15 os.popen4(some_var)
```


### Starting a process with a shell, possible injection detected, security issue.

**Test**: start_process_with_a_shell (B605)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-popen.py`

```
14 os.popen4('/bin/uname -av; rm -rf /')
15 os.popen4(some_var)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-spawn.py`

```
2 
3 os.spawnl(mode, path)
4 os.spawnle(mode, path, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-spawn.py`

```
3 os.spawnl(mode, path)
4 os.spawnle(mode, path, env)
5 os.spawnlp(mode, file)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-spawn.py`

```
4 os.spawnle(mode, path, env)
5 os.spawnlp(mode, file)
6 os.spawnlpe(mode, file, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-spawn.py`

```
5 os.spawnlp(mode, file)
6 os.spawnlpe(mode, file, env)
7 os.spawnv(mode, path, args)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-spawn.py`

```
6 os.spawnlpe(mode, file, env)
7 os.spawnv(mode, path, args)
8 os.spawnve(mode, path, args, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-spawn.py`

```
7 os.spawnv(mode, path, args)
8 os.spawnve(mode, path, args, env)
9 os.spawnvp(mode, file, args)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-spawn.py`

```
8 os.spawnve(mode, path, args, env)
9 os.spawnvp(mode, file, args)
10 os.spawnvpe(mode, file, args, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-spawn.py`

```
9 os.spawnvp(mode, file, args)
10 os.spawnvpe(mode, file, args, env)
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-startfile.py`

```
2 
3 os.startfile('/bin/foo.docx')
4 os.startfile('/bin/bad.exe')
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-startfile.py`

```
3 os.startfile('/bin/foo.docx')
4 os.startfile('/bin/bad.exe')
5 os.startfile('/bin/text.txt')
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os-startfile.py`

```
4 os.startfile('/bin/bad.exe')
5 os.startfile('/bin/text.txt')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/os_system.py`

```
2 
3 os.system('/bin/echo hi')
```


### Possible shell injection via Paramiko call, check inputs are properly sanitized.

**Test**: paramiko_calls (B601)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/paramiko_injection.py`

```
6 # this is not safe
7 client.exec_command('something; really; unsafe')
8 
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
1 from subprocess import Popen as pop
2 
3 pop('gcc --version', shell=False)
4 pop('/bin/gcc --version', shell=False)
```


### Starting a process with a partial executable path

**Test**: start_process_with_partial_path (B607)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
2 
3 pop('gcc --version', shell=False)
4 pop('/bin/gcc --version', shell=False)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
2 
3 pop('gcc --version', shell=False)
4 pop('/bin/gcc --version', shell=False)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
3 pop('gcc --version', shell=False)
4 pop('/bin/gcc --version', shell=False)
5 pop(var, shell=False)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
4 pop('/bin/gcc --version', shell=False)
5 pop(var, shell=False)
6 
```


### Starting a process with a partial executable path

**Test**: start_process_with_partial_path (B607)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
6 
7 pop(['ls', '-l'], shell=False)
8 pop(['/bin/ls', '-l'], shell=False)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
6 
7 pop(['ls', '-l'], shell=False)
8 pop(['/bin/ls', '-l'], shell=False)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
7 pop(['ls', '-l'], shell=False)
8 pop(['/bin/ls', '-l'], shell=False)
9 
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
9 
10 pop('../ls -l', shell=False)
11 
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
11 
12 pop('c:\\hello\\something', shell=False)
13 pop('c:/hello/something_else', shell=False)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/partial_path_process.py`

```
12 pop('c:\\hello\\something', shell=False)
13 pop('c:/hello/something_else', shell=False)
```


### Consider possible security implications associated with cPickle module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/pickle_deserialize.py`

```
1 import cPickle
2 import pickle
3 import StringIO
```


### Consider possible security implications associated with pickle module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/pickle_deserialize.py`

```
1 import cPickle
2 import pickle
3 import StringIO
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/pickle_deserialize.py`

```
7 pick = pickle.dumps({'a': 'b', 'c': 'd'})
8 print(pickle.loads(pick))
9 
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/pickle_deserialize.py`

```
12 file_obj.seek(0)
13 print(pickle.load(file_obj))
14 
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/pickle_deserialize.py`

```
15 file_obj.seek(0)
16 print(pickle.Unpickler(file_obj).load())
17 
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/pickle_deserialize.py`

```
19 serialized = cPickle.dumps({(): []})
20 print(cPickle.loads(serialized))
21 
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/pickle_deserialize.py`

```
24 file_obj.seek(0)
25 print(cPickle.load(file_obj))
26 
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/pickle_deserialize.py`

```
27 file_obj.seek(0)
28 print(cPickle.Unpickler(file_obj).load())
29 
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/popen_wrappers.py`

```
4 
5 print(commands.getstatusoutput('/bin/echo / | xargs ls'))
6 print(commands.getoutput('/bin/echo / | xargs ls'))
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/popen_wrappers.py`

```
5 print(commands.getstatusoutput('/bin/echo / | xargs ls'))
6 print(commands.getoutput('/bin/echo / | xargs ls'))
7 
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/popen_wrappers.py`

```
10 
11 print(popen2.popen2('/bin/echo / | xargs ls')[0].read())
12 print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/popen_wrappers.py`

```
11 print(popen2.popen2('/bin/echo / | xargs ls')[0].read())
12 print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
13 print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/popen_wrappers.py`

```
12 print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
13 print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
14 print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/popen_wrappers.py`

```
13 print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
14 print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
15 print(popen2.Popen4('/bin/echo / | xargs ls').fromchild.read())
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/popen_wrappers.py`

```
14 print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
15 print(popen2.Popen4('/bin/echo / | xargs ls').fromchild.read())
```


### The pyCrypto library and its module AES are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/pycrypto.py`

```
1 from Crypto.Cipher import AES
2 from Crypto import Random
3 
```


### The pyCrypto library and its module Random are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/pycrypto.py`

```
1 from Crypto.Cipher import AES
2 from Crypto import Random
3 
4 from . import CryptoMaterialsCacheEntry
```


### An IPMI-related module is being imported. IPMI is considered insecure. Use an encrypted protocol.

**Test**: blacklist (B415)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/319.html)

`bandit-main/examples/pyghmi.py`

```
1 from pyghmi.ipmi import command
2 
3 cmd = command.Command(bmc="bmc",
4                       userid="userid",
```


### Possible hardcoded password: 'ZjE4ZjI0NTE4YmI2NGJjZDliOGY3ZmJiY2UyN2IzODQK'

**Test**: hardcoded_password_funcarg (B106)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/259.html)

`bandit-main/examples/pyghmi.py`

```
2 
3 cmd = command.Command(bmc="bmc",
4                       userid="userid",
5                       password="ZjE4ZjI0NTE4YmI2NGJjZDliOGY3ZmJiY2UyN2IzODQK")
```


### Standard pseudo-random generators are not suitable for security/cryptographic purposes.

**Test**: blacklist (B311)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/330.html)

`bandit-main/examples/random_module.py`

```
4 
5 bad = random.random()
6 bad = random.randrange()
```


### Standard pseudo-random generators are not suitable for security/cryptographic purposes.

**Test**: blacklist (B311)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/330.html)

`bandit-main/examples/random_module.py`

```
5 bad = random.random()
6 bad = random.randrange()
7 bad = random.randint()
```


### Standard pseudo-random generators are not suitable for security/cryptographic purposes.

**Test**: blacklist (B311)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/330.html)

`bandit-main/examples/random_module.py`

```
6 bad = random.randrange()
7 bad = random.randint()
8 bad = random.choice()
```


### Standard pseudo-random generators are not suitable for security/cryptographic purposes.

**Test**: blacklist (B311)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/330.html)

`bandit-main/examples/random_module.py`

```
7 bad = random.randint()
8 bad = random.choice()
9 bad = random.choices()
```


### Standard pseudo-random generators are not suitable for security/cryptographic purposes.

**Test**: blacklist (B311)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/330.html)

`bandit-main/examples/random_module.py`

```
8 bad = random.choice()
9 bad = random.choices()
10 bad = random.uniform()
```


### Standard pseudo-random generators are not suitable for security/cryptographic purposes.

**Test**: blacklist (B311)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/330.html)

`bandit-main/examples/random_module.py`

```
9 bad = random.choices()
10 bad = random.uniform()
11 bad = random.triangular()
```


### Standard pseudo-random generators are not suitable for security/cryptographic purposes.

**Test**: blacklist (B311)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/330.html)

`bandit-main/examples/random_module.py`

```
10 bad = random.uniform()
11 bad = random.triangular()
12 
```


### Requests call with verify=False disabling SSL certificate checks, security issue.

**Test**: request_with_no_cert_validation (B501)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/requests-ssl-verify-disabled.py`

```
4 requests.get('https://gmail.com', timeout=30, verify=True)
5 requests.get('https://gmail.com', timeout=30, verify=False)
6 requests.post('https://gmail.com', timeout=30, verify=True)
```


### Requests call with verify=False disabling SSL certificate checks, security issue.

**Test**: request_with_no_cert_validation (B501)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/requests-ssl-verify-disabled.py`

```
6 requests.post('https://gmail.com', timeout=30, verify=True)
7 requests.post('https://gmail.com', timeout=30, verify=False)
8 requests.put('https://gmail.com', timeout=30, verify=True)
```


### Requests call with verify=False disabling SSL certificate checks, security issue.

**Test**: request_with_no_cert_validation (B501)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/requests-ssl-verify-disabled.py`

```
8 requests.put('https://gmail.com', timeout=30, verify=True)
9 requests.put('https://gmail.com', timeout=30, verify=False)
10 requests.delete('https://gmail.com', timeout=30, verify=True)
```


### Requests call with verify=False disabling SSL certificate checks, security issue.

**Test**: request_with_no_cert_validation (B501)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/requests-ssl-verify-disabled.py`

```
10 requests.delete('https://gmail.com', timeout=30, verify=True)
11 requests.delete('https://gmail.com', timeout=30, verify=False)
12 requests.patch('https://gmail.com', timeout=30, verify=True)
```


### Requests call with verify=False disabling SSL certificate checks, security issue.

**Test**: request_with_no_cert_validation (B501)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/requests-ssl-verify-disabled.py`

```
12 requests.patch('https://gmail.com', timeout=30, verify=True)
13 requests.patch('https://gmail.com', timeout=30, verify=False)
14 requests.options('https://gmail.com', timeout=30, verify=True)
```


### Requests call with verify=False disabling SSL certificate checks, security issue.

**Test**: request_with_no_cert_validation (B501)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/requests-ssl-verify-disabled.py`

```
14 requests.options('https://gmail.com', timeout=30, verify=True)
15 requests.options('https://gmail.com', timeout=30, verify=False)
16 requests.head('https://gmail.com', timeout=30, verify=True)
```


### Requests call with verify=False disabling SSL certificate checks, security issue.

**Test**: request_with_no_cert_validation (B501)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/requests-ssl-verify-disabled.py`

```
16 requests.head('https://gmail.com', timeout=30, verify=True)
17 requests.head('https://gmail.com', timeout=30, verify=False)
18 
```


### Consider possible security implications associated with shelve module.

**Test**: blacklist (B403)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/shelve_open.py`

```
1 import os
2 import shelve
3 import tempfile
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/shelve_open.py`

```
7 
8     with shelve.open(filename) as db:
9         db['spam'] = {'eggs': 'ham'}
```


### Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Test**: blacklist (B301)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/502.html)

`bandit-main/examples/shelve_open.py`

```
10 
11     with shelve.open(filename) as db:
12         print(db['spam'])
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/skip.py`

```
1 subprocess.call(["/bin/ls", "-l"])
2 subprocess.call(["/bin/ls", "-l"]) #noqa
3 subprocess.call(["/bin/ls", "-l"]) # noqa
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/skip.py`

```
1 subprocess.call(["/bin/ls", "-l"])
2 subprocess.call(["/bin/ls", "-l"]) #noqa
3 subprocess.call(["/bin/ls", "-l"]) # noqa
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/skip.py`

```
2 subprocess.call(["/bin/ls", "-l"]) #noqa
3 subprocess.call(["/bin/ls", "-l"]) # noqa
4 subprocess.call(["/bin/ls", "-l"]) # nosec
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/skip.py`

```
4 subprocess.call(["/bin/ls", "-l"]) # nosec
5 subprocess.call(["/bin/ls", "-l"])
6 subprocess.call(["/bin/ls", "-l"]) #nosec
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/skip.py`

```
6 subprocess.call(["/bin/ls", "-l"]) #nosec
7 subprocess.call(["/bin/ls", "-l"])
```


### The use of SNMPv1 and SNMPv2 is insecure. You should use SNMPv3 if able.

**Test**: snmp_insecure_version_check (B508)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/319.html)

`bandit-main/examples/snmp.py`

```
3 # SHOULD FAIL
4 a = CommunityData('public', mpModel=0)
5 # SHOULD FAIL
```


### You should not use SNMPv3 without encryption. noAuthNoPriv & authNoPriv is insecure

**Test**: snmp_crypto_check (B509)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/319.html)

`bandit-main/examples/snmp.py`

```
5 # SHOULD FAIL
6 insecure = UsmUserData("securityName")
7 # SHOULD FAIL
```


### You should not use SNMPv3 without encryption. noAuthNoPriv & authNoPriv is insecure

**Test**: snmp_crypto_check (B509)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/319.html)

`bandit-main/examples/snmp.py`

```
7 # SHOULD FAIL
8 auth_no_priv = UsmUserData("securityName","authName")
9 # SHOULD PASS
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
3 # bad
4 query = "SELECT * FROM foo WHERE id = '%s'" % identifier
5 query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
4 query = "SELECT * FROM foo WHERE id = '%s'" % identifier
5 query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
6 query = "DELETE FROM foo WHERE id = '%s'" % identifier
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
5 query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
6 query = "DELETE FROM foo WHERE id = '%s'" % identifier
7 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
6 query = "DELETE FROM foo WHERE id = '%s'" % identifier
7 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
8 query = """WITH cte AS (SELECT x FROM foo)
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
7 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
8 query = """WITH cte AS (SELECT x FROM foo)
9 SELECT x FROM cte WHERE x = '%s'""" % identifier
10 # bad alternate forms
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
10 # bad alternate forms
11 query = "SELECT * FROM foo WHERE id = '" + identifier + "'"
12 query = "SELECT * FROM foo WHERE id = '{}'".format(identifier)
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
11 query = "SELECT * FROM foo WHERE id = '" + identifier + "'"
12 query = "SELECT * FROM foo WHERE id = '{}'".format(identifier)
13 
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
14 # bad
15 cur.execute("SELECT * FROM foo WHERE id = '%s'" % identifier)
16 cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
15 cur.execute("SELECT * FROM foo WHERE id = '%s'" % identifier)
16 cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
17 cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
16 cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
17 cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
18 cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier)
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
17 cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
18 cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier)
19 # bad alternate forms
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
19 # bad alternate forms
20 cur.execute("SELECT * FROM foo WHERE id = '" + identifier + "'")
21 cur.execute("SELECT * FROM foo WHERE id = '{}'".format(identifier))
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
20 cur.execute("SELECT * FROM foo WHERE id = '" + identifier + "'")
21 cur.execute("SELECT * FROM foo WHERE id = '{}'".format(identifier))
22 
```


### Possible SQL injection vector through string-based query construction.

**Test**: hardcoded_sql_expressions (B608)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/89.html)

`bandit-main/examples/sql_statements.py`

```
34 
35 a()("SELECT %s FROM foo" % val)
36 
```


### ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
3 
4 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)
5 SSL.Context(method=SSL.SSLv2_METHOD)
```


### SSL.Context call with insecure SSL/TLS protocol version identified, security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
4 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)
5 SSL.Context(method=SSL.SSLv2_METHOD)
6 SSL.Context(method=SSL.SSLv23_METHOD)
```


### SSL.Context call with insecure SSL/TLS protocol version identified, security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
5 SSL.Context(method=SSL.SSLv2_METHOD)
6 SSL.Context(method=SSL.SSLv23_METHOD)
7 
```


### Function call with insecure SSL/TLS protocol identified, possible security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
7 
8 herp_derp(ssl_version=ssl.PROTOCOL_SSLv2)
9 herp_derp(method=SSL.SSLv2_METHOD)
```


### Function call with insecure SSL/TLS protocol identified, possible security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
8 herp_derp(ssl_version=ssl.PROTOCOL_SSLv2)
9 herp_derp(method=SSL.SSLv2_METHOD)
10 herp_derp(method=SSL.SSLv23_METHOD)
```


### Function call with insecure SSL/TLS protocol identified, possible security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
9 herp_derp(method=SSL.SSLv2_METHOD)
10 herp_derp(method=SSL.SSLv23_METHOD)
11 
```


### ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
12 # strict tests
13 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
14 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
```


### ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
13 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
14 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
15 SSL.Context(method=SSL.SSLv3_METHOD)
```


### SSL.Context call with insecure SSL/TLS protocol version identified, security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
14 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
15 SSL.Context(method=SSL.SSLv3_METHOD)
16 SSL.Context(method=SSL.TLSv1_METHOD)
```


### SSL.Context call with insecure SSL/TLS protocol version identified, security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
15 SSL.Context(method=SSL.SSLv3_METHOD)
16 SSL.Context(method=SSL.TLSv1_METHOD)
17 
```


### Function call with insecure SSL/TLS protocol identified, possible security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
17 
18 herp_derp(ssl_version=ssl.PROTOCOL_SSLv3)
19 herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
```


### Function call with insecure SSL/TLS protocol identified, possible security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
18 herp_derp(ssl_version=ssl.PROTOCOL_SSLv3)
19 herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
20 herp_derp(method=SSL.SSLv3_METHOD)
```


### Function call with insecure SSL/TLS protocol identified, possible security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
19 herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
20 herp_derp(method=SSL.SSLv3_METHOD)
21 herp_derp(method=SSL.TLSv1_METHOD)
```


### Function call with insecure SSL/TLS protocol identified, possible security issue.

**Test**: ssl_with_bad_version (B502)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
20 herp_derp(method=SSL.SSLv3_METHOD)
21 herp_derp(method=SSL.TLSv1_METHOD)
22 
```


### ssl.wrap_socket call with no SSL/TLS protocol version specified, the default SSLv23 could be insecure, possible security issue.

**Test**: ssl_with_no_version (B504)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
22 
23 ssl.wrap_socket()
24 
```


### Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.

**Test**: ssl_with_bad_defaults (B503)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
24 
25 def open_ssl_socket(version=ssl.PROTOCOL_SSLv2):
26     pass
27 
28 def open_ssl_socket(version=SSL.SSLv2_METHOD):
```


### Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.

**Test**: ssl_with_bad_defaults (B503)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
27 
28 def open_ssl_socket(version=SSL.SSLv2_METHOD):
29     pass
30 
31 def open_ssl_socket(version=SSL.SSLv23_METHOD):
```


### Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.

**Test**: ssl_with_bad_defaults (B503)

**Severity**: MEDIUM

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/ssl-insecure-version.py`

```
30 
31 def open_ssl_socket(version=SSL.SSLv23_METHOD):
32     pass
33 
34 # this one will pass ok
35 def open_ssl_socket(version=SSL.TLSv1_1_METHOD):
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
1 import subprocess
2 from subprocess import Popen as pop
3 
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
1 import subprocess
2 from subprocess import Popen as pop
3 
4 
5 def Popen(*args, **kwargs):
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
10 
11 pop('/bin/gcc --version', shell=True)
12 Popen('/bin/gcc --version', shell=True)
```


### Function call with shell=True parameter identified, possible security issue.

**Test**: any_other_function_with_shell_equals_true (B604)

**Severity**: MEDIUM

**Confidence**: LOW

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
11 pop('/bin/gcc --version', shell=True)
12 Popen('/bin/gcc --version', shell=True)
13 
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
13 
14 subprocess.Popen('/bin/gcc --version', shell=True)
15 subprocess.Popen(['/bin/gcc', '--version'], shell=False)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
14 subprocess.Popen('/bin/gcc --version', shell=True)
15 subprocess.Popen(['/bin/gcc', '--version'], shell=False)
16 subprocess.Popen(['/bin/gcc', '--version'])
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
15 subprocess.Popen(['/bin/gcc', '--version'], shell=False)
16 subprocess.Popen(['/bin/gcc', '--version'])
17 
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
17 
18 subprocess.call(["/bin/ls",
19                  "-l"
20                  ])
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
20                  ])
21 subprocess.call('/bin/ls -l', shell=True)
22 
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
22 
23 subprocess.check_call(['/bin/ls', '-l'], shell=False)
24 subprocess.check_call('/bin/ls -l', shell=True)
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
23 subprocess.check_call(['/bin/ls', '-l'], shell=False)
24 subprocess.check_call('/bin/ls -l', shell=True)
25 
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
25 
26 subprocess.check_output(['/bin/ls', '-l'])
27 subprocess.check_output('/bin/ls -l', shell=True)
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
26 subprocess.check_output(['/bin/ls', '-l'])
27 subprocess.check_output('/bin/ls -l', shell=True)
28 
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
28 
29 subprocess.run(['/bin/ls', '-l'])
30 subprocess.run('/bin/ls -l', shell=True)
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
29 subprocess.run(['/bin/ls', '-l'])
30 subprocess.run('/bin/ls -l', shell=True)
31 
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
31 
32 subprocess.Popen('/bin/ls *', shell=True)
33 subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
32 subprocess.Popen('/bin/ls *', shell=True)
33 subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
34 subprocess.Popen('/bin/ls {}'.format('something'), shell=True)
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
33 subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
34 subprocess.Popen('/bin/ls {}'.format('something'), shell=True)
35 
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
36 command = "/bin/ls" + unknown_function()
37 subprocess.Popen(command, shell=True)
38 
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
38 
39 subprocess.Popen('/bin/ls && cat /etc/passwd', shell=True)
40 
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
41 command = 'pwd'
42 subprocess.call(command, shell='True')
43 subprocess.call(command, shell='False')
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
42 subprocess.call(command, shell='True')
43 subprocess.call(command, shell='False')
44 subprocess.call(command, shell='None')
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
43 subprocess.call(command, shell='False')
44 subprocess.call(command, shell='None')
45 subprocess.call(command, shell=1)
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
44 subprocess.call(command, shell='None')
45 subprocess.call(command, shell=1)
46 
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
46 
47 subprocess.call(command, shell=Popen())
48 subprocess.call(command, shell=[True])
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
47 subprocess.call(command, shell=Popen())
48 subprocess.call(command, shell=[True])
49 subprocess.call(command, shell={'IS': 'True'})
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
48 subprocess.call(command, shell=[True])
49 subprocess.call(command, shell={'IS': 'True'})
50 subprocess.call(command, shell=command)
```


### subprocess call with shell=True identified, security issue.

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
49 subprocess.call(command, shell={'IS': 'True'})
50 subprocess.call(command, shell=command)
51 
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
51 
52 subprocess.call(command, shell=False)
53 subprocess.call(command, shell=0)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
52 subprocess.call(command, shell=False)
53 subprocess.call(command, shell=0)
54 subprocess.call(command, shell=[])
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
53 subprocess.call(command, shell=0)
54 subprocess.call(command, shell=[])
55 subprocess.call(command, shell={})
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
54 subprocess.call(command, shell=[])
55 subprocess.call(command, shell={})
56 subprocess.call(command, shell=None)
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/subprocess_shell.py`

```
55 subprocess.call(command, shell={})
56 subprocess.call(command, shell=None)
```


### A telnet-related module is being imported.  Telnet is considered insecure. Use SSH or some other encrypted protocol.

**Test**: blacklist (B401)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/319.html)

`bandit-main/examples/telnetlib.py`

```
1 import telnetlib
2 import getpass
3 
```


### Telnet-related functions are being called. Telnet is considered insecure. Use SSH or some other encrypted protocol.

**Test**: blacklist (B312)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/319.html)

`bandit-main/examples/telnetlib.py`

```
7 password = getpass.getpass()
8 tn = telnetlib.Telnet(host)
9 
```


### Try, Except, Continue detected.

**Test**: try_except_continue (B112)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/703.html)

`bandit-main/examples/try_except_continue.py`

```
4         a = i
5     except:
6         continue
```


### Try, Except, Continue detected.

**Test**: try_except_continue (B112)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/703.html)

`bandit-main/examples/try_except_continue.py`

```
12         a = 1
13     except Exception:
14         continue
```


### Try, Except, Pass detected.

**Test**: try_except_pass (B110)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/703.html)

`bandit-main/examples/try_except_pass.py`

```
3     a = 1
4 except:
5     pass
```


### Try, Except, Pass detected.

**Test**: try_except_pass (B110)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/703.html)

`bandit-main/examples/try_except_pass.py`

```
10     a = 1
11 except Exception:
12     pass
```


### By default, Python will create a secure, verified ssl context for use in such classes as HTTPSConnection. However, it still allows using an insecure context via the _create_unverified_context that  reverts to the previous behavior that does not validate certificates or perform hostname checks.

**Test**: blacklist (B323)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/295.html)

`bandit-main/examples/unverified_context.py`

```
6 # Incorrect: unverified context
7 context = ssl._create_unverified_context()
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
21     url = urllib.quote('file:///bin/ls')
22     urllib.urlopen(url, 'blah', 32)
23     urllib.urlretrieve('file:///bin/ls', '/bin/ls2')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
22     urllib.urlopen(url, 'blah', 32)
23     urllib.urlretrieve('file:///bin/ls', '/bin/ls2')
24     opener = urllib.URLopener()
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
23     urllib.urlretrieve('file:///bin/ls', '/bin/ls2')
24     opener = urllib.URLopener()
25     opener.open('file:///bin/ls')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
26     opener.retrieve('file:///bin/ls')
27     opener = urllib.FancyURLopener()
28     opener.open('file:///bin/ls')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
37     urllib2.install_opener(opener)
38     urllib2.urlopen('file:///bin/ls')
39     urllib2.Request('file:///bin/ls')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
38     urllib2.urlopen('file:///bin/ls')
39     urllib2.Request('file:///bin/ls')
40 
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
41     # Python 3
42     urllib.request.urlopen('file:///bin/ls')
43     urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
42     urllib.request.urlopen('file:///bin/ls')
43     urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
44     opener = urllib.request.URLopener()
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
43     urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
44     opener = urllib.request.URLopener()
45     opener.open('file:///bin/ls')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
46     opener.retrieve('file:///bin/ls')
47     opener = urllib.request.FancyURLopener()
48     opener.open('file:///bin/ls')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
51     # Six
52     six.moves.urllib.request.urlopen('file:///bin/ls')
53     six.moves.urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
52     six.moves.urllib.request.urlopen('file:///bin/ls')
53     six.moves.urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
54     opener = six.moves.urllib.request.URLopener()
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
53     six.moves.urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
54     opener = six.moves.urllib.request.URLopener()
55     opener.open('file:///bin/ls')
```


### Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Test**: blacklist (B310)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/22.html)

`bandit-main/examples/urlopen.py`

```
56     opener.retrieve('file:///bin/ls')
57     opener = six.moves.urllib.request.FancyURLopener()
58     opener.open('file:///bin/ls')
```


### The pyCrypto library and its module DSA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
4 from cryptography.hazmat.primitives.asymmetric import rsa
5 from Crypto.PublicKey import DSA as pycrypto_dsa
6 from Crypto.PublicKey import RSA as pycrypto_rsa
```


### The pyCrypto library and its module RSA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.

**Test**: blacklist (B413)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/327.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
5 from Crypto.PublicKey import DSA as pycrypto_dsa
6 from Crypto.PublicKey import RSA as pycrypto_rsa
7 from Cryptodome.PublicKey import DSA as pycryptodomex_dsa
```


### DSA key sizes below 2048 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
37 # Incorrect: weak key sizes
38 dsa.generate_private_key(key_size=1024,
39                          backend=backends.default_backend())
40 ec.generate_private_key(curve=ec.SECT163R2,
```


### EC key sizes below 224 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
39                          backend=backends.default_backend())
40 ec.generate_private_key(curve=ec.SECT163R2,
41                         backend=backends.default_backend())
42 rsa.generate_private_key(public_exponent=65537,
```


### RSA key sizes below 2048 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
41                         backend=backends.default_backend())
42 rsa.generate_private_key(public_exponent=65537,
43                          key_size=1024,
44                          backend=backends.default_backend())
45 pycrypto_dsa.generate(bits=1024)
```


### DSA key sizes below 2048 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
44                          backend=backends.default_backend())
45 pycrypto_dsa.generate(bits=1024)
46 pycrypto_rsa.generate(bits=1024)
```


### RSA key sizes below 2048 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
45 pycrypto_dsa.generate(bits=1024)
46 pycrypto_rsa.generate(bits=1024)
47 pycryptodomex_dsa.generate(bits=1024)
```


### DSA key sizes below 2048 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
46 pycrypto_rsa.generate(bits=1024)
47 pycryptodomex_dsa.generate(bits=1024)
48 pycryptodomex_rsa.generate(bits=1024)
```


### RSA key sizes below 2048 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
47 pycryptodomex_dsa.generate(bits=1024)
48 pycryptodomex_rsa.generate(bits=1024)
49 
```


### DSA key sizes below 1024 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
50 # Also incorrect: without keyword args
51 dsa.generate_private_key(512,
52                          backends.default_backend())
53 ec.generate_private_key(ec.SECT163R2,
```


### EC key sizes below 224 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
52                          backends.default_backend())
53 ec.generate_private_key(ec.SECT163R2,
54                         backends.default_backend())
55 rsa.generate_private_key(3,
```


### RSA key sizes below 1024 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
54                         backends.default_backend())
55 rsa.generate_private_key(3,
56                          512,
57                          backends.default_backend())
58 pycrypto_dsa.generate(512)
```


### DSA key sizes below 1024 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
57                          backends.default_backend())
58 pycrypto_dsa.generate(512)
59 pycrypto_rsa.generate(512)
```


### RSA key sizes below 1024 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
58 pycrypto_dsa.generate(512)
59 pycrypto_rsa.generate(512)
60 pycryptodomex_dsa.generate(512)
```


### DSA key sizes below 1024 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
59 pycrypto_rsa.generate(512)
60 pycryptodomex_dsa.generate(512)
61 pycryptodomex_rsa.generate(512)
```


### RSA key sizes below 1024 bits are considered breakable. 

**Test**: weak_cryptographic_key (B505)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/326.html)

`bandit-main/examples/weak_cryptographic_key_sizes.py`

```
60 pycryptodomex_dsa.generate(512)
61 pycryptodomex_rsa.generate(512)
62 
```


### Consider possible security implications associated with the subprocess module.

**Test**: blacklist (B404)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
1 import os as o
2 import subprocess as subp
3 
4 # Vulnerable to wildcard injection
5 o.system("/bin/tar xvzf *")
```


### Possible wildcard injection in call: os.system

**Test**: linux_commands_wildcard_injection (B609)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/155.html)

`bandit-main/examples/wildcard-injection.py`

```
4 # Vulnerable to wildcard injection
5 o.system("/bin/tar xvzf *")
6 o.system('/bin/chown *')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
4 # Vulnerable to wildcard injection
5 o.system("/bin/tar xvzf *")
6 o.system('/bin/chown *')
```


### Possible wildcard injection in call: os.system

**Test**: linux_commands_wildcard_injection (B609)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/155.html)

`bandit-main/examples/wildcard-injection.py`

```
5 o.system("/bin/tar xvzf *")
6 o.system('/bin/chown *')
7 o.popen2('/bin/chmod *')
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
5 o.system("/bin/tar xvzf *")
6 o.system('/bin/chown *')
7 o.popen2('/bin/chmod *')
```


### Possible wildcard injection in call: os.popen2

**Test**: linux_commands_wildcard_injection (B609)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/155.html)

`bandit-main/examples/wildcard-injection.py`

```
6 o.system('/bin/chown *')
7 o.popen2('/bin/chmod *')
8 subp.Popen('/bin/chown *', shell=True)
```


### Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

**Test**: start_process_with_a_shell (B605)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
6 o.system('/bin/chown *')
7 o.popen2('/bin/chmod *')
8 subp.Popen('/bin/chown *', shell=True)
```


### Possible wildcard injection in call: subprocess.Popen

**Test**: linux_commands_wildcard_injection (B609)

**Severity**: HIGH

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/155.html)

`bandit-main/examples/wildcard-injection.py`

```
7 o.popen2('/bin/chmod *')
8 subp.Popen('/bin/chown *', shell=True)
9 
```


### subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

**Test**: subprocess_popen_with_shell_equals_true (B602)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
7 o.popen2('/bin/chmod *')
8 subp.Popen('/bin/chown *', shell=True)
9 
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
10 # Not vulnerable to wildcard injection
11 subp.Popen('/bin/rsync *')
12 subp.Popen("/bin/chmod *")
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
11 subp.Popen('/bin/rsync *')
12 subp.Popen("/bin/chmod *")
13 subp.Popen(['/bin/chown', '*'])
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
12 subp.Popen("/bin/chmod *")
13 subp.Popen(['/bin/chown', '*'])
14 subp.Popen(["/bin/chmod", sys.argv[1], "*"],
```


### subprocess call - check for execution of untrusted input.

**Test**: subprocess_without_shell_equals_true (B603)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
13 subp.Popen(['/bin/chown', '*'])
14 subp.Popen(["/bin/chmod", sys.argv[1], "*"],
15                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
16 o.spawnvp(os.P_WAIT, 'tar', ['tar', 'xvzf', '*'])
```


### Starting a process without a shell.

**Test**: start_process_with_no_shell (B606)

**Severity**: LOW

**Confidence**: MEDIUM

[CWE Details](https://cwe.mitre.org/data/definitions/78.html)

`bandit-main/examples/wildcard-injection.py`

```
15                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
16 o.spawnvp(os.P_WAIT, 'tar', ['tar', 'xvzf', '*'])
```


### Using xml.etree.cElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B405)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_celementtree.py`

```
1 import xml.etree.cElementTree as badET
2 import defusedxml.cElementTree as goodET
3 
```


### Using xml.etree.cElementTree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.fromstring with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B313)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_celementtree.py`

```
6 # unsafe
7 tree = badET.fromstring(xmlString)
8 print(tree)
```


### Using xml.etree.cElementTree.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B313)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_celementtree.py`

```
8 print(tree)
9 badET.parse('filethatdoesntexist.xml')
10 badET.iterparse('filethatdoesntexist.xml')
```


### Using xml.etree.cElementTree.iterparse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.iterparse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B313)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_celementtree.py`

```
9 badET.parse('filethatdoesntexist.xml')
10 badET.iterparse('filethatdoesntexist.xml')
11 a = badET.XMLParser()
```


### Using xml.etree.cElementTree.XMLParser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.XMLParser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B313)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_celementtree.py`

```
10 badET.iterparse('filethatdoesntexist.xml')
11 a = badET.XMLParser()
12 
```


### Using xml.etree.ElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B405)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_elementtree.py`

```
1 import xml.etree.ElementTree as badET
2 import defusedxml.ElementTree as goodET
3 
```


### Using xml.etree.ElementTree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.fromstring with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B314)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_elementtree.py`

```
6 # unsafe
7 tree = badET.fromstring(xmlString)
8 print(tree)
```


### Using xml.etree.ElementTree.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B314)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_elementtree.py`

```
8 print(tree)
9 badET.parse('filethatdoesntexist.xml')
10 badET.iterparse('filethatdoesntexist.xml')
```


### Using xml.etree.ElementTree.iterparse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.iterparse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B314)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_elementtree.py`

```
9 badET.parse('filethatdoesntexist.xml')
10 badET.iterparse('filethatdoesntexist.xml')
11 a = badET.XMLParser()
```


### Using xml.etree.ElementTree.XMLParser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.XMLParser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B314)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_etree_elementtree.py`

```
10 badET.iterparse('filethatdoesntexist.xml')
11 a = badET.XMLParser()
12 
```


### Using xml.dom.expatbuilder to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B407)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_expatbuilder.py`

```
1 import xml.dom.expatbuilder as bad
2 import defusedxml.expatbuilder as good
3 
```


### Using xml.dom.expatbuilder.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B316)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_expatbuilder.py`

```
3 
4 bad.parse('filethatdoesntexist.xml')
5 good.parse('filethatdoesntexist.xml')
```


### Using xml.dom.expatbuilder.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B316)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_expatbuilder.py`

```
8 
9 bad.parseString(xmlString)
10 good.parseString(xmlString)
```


### Using xml.sax.expatreader to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.expatreader with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B406)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_expatreader.py`

```
1 import xml.sax.expatreader as bad
2 import defusedxml.expatreader as good
3 
```


### Using xml.sax.expatreader.create_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.expatreader.create_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B315)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_expatreader.py`

```
3 
4 p = bad.create_parser()
5 b = good.create_parser()
```


### Using lxml.etree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml.etree with the equivalent defusedxml package.

**Test**: blacklist (B410)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_lxml.py`

```
1 import lxml.etree
2 import lxml
3 from lxml import etree
```


### Using lxml to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml with the equivalent defusedxml package.

**Test**: blacklist (B410)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_lxml.py`

```
1 import lxml.etree
2 import lxml
3 from lxml import etree
```


### Using etree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace etree with the equivalent defusedxml package.

**Test**: blacklist (B410)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_lxml.py`

```
2 import lxml
3 from lxml import etree
4 from defusedxml.lxml import fromstring
```


### Using lxml.etree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml.etree.fromstring with its defusedxml equivalent function.

**Test**: blacklist (B320)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_lxml.py`

```
7 xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"
8 root = lxml.etree.fromstring(xmlString)
9 root = fromstring(xmlString)
```


### Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parseString with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B408)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_minidom.py`

```
1 from xml.dom.minidom import parseString as badParseString
2 from defusedxml.minidom import parseString as goodParseString
3 a = badParseString("<myxml>Some data some more data</myxml>")
```


### Using xml.dom.minidom.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.minidom.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B318)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_minidom.py`

```
2 from defusedxml.minidom import parseString as goodParseString
3 a = badParseString("<myxml>Some data some more data</myxml>")
4 print(a)
```


### Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B408)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_minidom.py`

```
8 
9 from xml.dom.minidom import parse as badParse
10 from defusedxml.minidom import parse as goodParse
```


### Using xml.dom.minidom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.minidom.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B318)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_minidom.py`

```
10 from defusedxml.minidom import parse as goodParse
11 a = badParse("somfilethatdoesntexist.xml")
12 print(a)
```


### Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parseString with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B409)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_pulldom.py`

```
1 from xml.dom.pulldom import parseString as badParseString
2 from defusedxml.pulldom import parseString as goodParseString
3 a = badParseString("<myxml>Some data some more data</myxml>")
```


### Using xml.dom.pulldom.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.pulldom.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B319)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_pulldom.py`

```
2 from defusedxml.pulldom import parseString as goodParseString
3 a = badParseString("<myxml>Some data some more data</myxml>")
4 print(a)
```


### Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B409)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_pulldom.py`

```
8 
9 from xml.dom.pulldom import parse as badParse
10 from defusedxml.pulldom import parse as goodParse
```


### Using xml.dom.pulldom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.pulldom.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B319)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_pulldom.py`

```
10 from defusedxml.pulldom import parse as goodParse
11 a = badParse("somfilethatdoesntexist.xml")
12 print(a)
```


### Using xml.sax to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B406)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_sax.py`

```
1 import xml.sax
2 from xml import sax
3 import defusedxml.sax
```


### Using sax to parse untrusted XML data is known to be vulnerable to XML attacks. Replace sax with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Test**: blacklist (B406)

**Severity**: LOW

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_sax.py`

```
1 import xml.sax
2 from xml import sax
3 import defusedxml.sax
```


### Using xml.sax.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B317)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_sax.py`

```
20     # bad
21     xml.sax.parseString(xmlString, ExampleContentHandler())
22     xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())
```


### Using xml.sax.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B317)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_sax.py`

```
21     xml.sax.parseString(xmlString, ExampleContentHandler())
22     xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())
23     sax.parseString(xmlString, ExampleContentHandler())
```


### Using xml.sax.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B317)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_sax.py`

```
22     xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())
23     sax.parseString(xmlString, ExampleContentHandler())
24     sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler)
```


### Using xml.sax.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B317)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_sax.py`

```
23     sax.parseString(xmlString, ExampleContentHandler())
24     sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler)
25 
```


### Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B317)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_sax.py`

```
29     # bad
30     xml.sax.make_parser()
31     sax.make_parser()
```


### Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Test**: blacklist (B317)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_sax.py`

```
30     xml.sax.make_parser()
31     sax.make_parser()
32     print('nothing')
```


### Using xmlrpclib to parse untrusted XML data is known to be vulnerable to XML attacks. Use defused.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.

**Test**: blacklist (B411)

**Severity**: HIGH

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/xml_xmlrpc.py`

```
1 import xmlrpclib
2 from SimpleXMLRPCServer import SimpleXMLRPCServer
3 
```


### Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().

**Test**: yaml_load (B506)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/yaml_load.py`

```
6     ystr = yaml.dump({'a': 1, 'b': 2, 'c': 3})
7     y = yaml.load(ystr)
8     yaml.dump(y)
```


### Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().

**Test**: yaml_load (B506)

**Severity**: MEDIUM

**Confidence**: HIGH

[CWE Details](https://cwe.mitre.org/data/definitions/20.html)

`bandit-main/examples/yaml_load.py`

```
19 
20 yaml.load("{}", Loader=yaml.Loader)
```

