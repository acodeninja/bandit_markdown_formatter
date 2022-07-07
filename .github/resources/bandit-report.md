# Bandit Report

## Summary of Alerts

| Risk Level |        Number of Alerts |
|:-----------|------------------------:|
| High       |                     108 |
| Medium     |                     205 |
| Low        |                     152 |
| Undefined  |                       0 |

| Test | Number of Alerts | Severity |
|:---|---|---:|
| Hashlib | 18 | HIGH |
| Ssl With Bad Version | 14 | HIGH |
| Set Bad File Permissions | 9 | HIGH |
| Request With No Cert Validation | 7 | HIGH |
| Jinja2 Autoescape False | 5 | HIGH |
| Linux Commands Wildcard Injection | 4 | HIGH |
| Ssh No Host Key Verification | 2 | HIGH |
| Flask Debug True | 1 | HIGH |
| Blacklist | 193 | MEDIUM |
| Django Mark Safe | 28 | MEDIUM |
| Hardcoded Sql Expressions | 14 | MEDIUM |
| Weak Cryptographic Key | 14 | MEDIUM |
| Django Extra Used | 11 | MEDIUM |
| Django Rawsql Used | 4 | MEDIUM |
| Hardcoded Tmp Directory | 4 | MEDIUM |
| Use Of Mako Templates | 3 | MEDIUM |
| Yaml Load | 3 | MEDIUM |
| Ssl With Bad Defaults | 3 | MEDIUM |
| Snmp Crypto Check | 2 | MEDIUM |
| Hardcoded Bind All Interfaces | 1 | MEDIUM |
| Exec Used | 1 | MEDIUM |
| Paramiko Calls | 1 | MEDIUM |
| Snmp Insecure Version Check | 1 | MEDIUM |
| Any Other Function With Shell Equals True | 1 | MEDIUM |
| Subprocess Popen With Shell Equals True | 28 | LOW |
| Subprocess Without Shell Equals True | 28 | LOW |
| Start Process With No Shell | 20 | LOW |
| Start Process With A Shell | 20 | LOW |
| Hardcoded Password String | 11 | LOW |
| Start Process With Partial Path | 4 | LOW |
| Hardcoded Password Default | 2 | LOW |
| Hardcoded Password Funcarg | 2 | LOW |
| Try Except Continue | 2 | LOW |
| Try Except Pass | 2 | LOW |
| Assert Used | 1 | LOW |
| Ssl With No Version | 1 | LOW |


## Alert Details

### Hashlib (B324) (HIGH)

Use of weak MD4, MD5, or SHA1 hash for security. Consider usedforsecurity=False

[CWE-327](https://cwe.mitre.org/data/definitions/327.html)

#### Instances

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
11 
12 hashlib.md5(1)
13 hashlib.md5(1).hexdigest()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
12 hashlib.md5(1)
13 hashlib.md5(1).hexdigest()
14 
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
14 
15 abc = str.replace(hashlib.md5("1"), "###")
16 
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
16 
17 print(hashlib.md5("1"))
18 
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
18 
19 hashlib.sha1(1)
20 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
2 
3 hashlib.new('md5')
4 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
4 
5 hashlib.new('md4', b'test')
6 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
6 
7 hashlib.new(name='md5', data=b'test')
8 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
8 
9 hashlib.new('MD4', data=b'test')
10 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
10 
11 hashlib.new('sha1')
12 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
12 
13 hashlib.new('sha1', data=b'test')
14 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
14 
15 hashlib.new('sha', data=b'test')
16 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
16 
17 hashlib.new(name='SHA', data=b'test')
18 
```

`bandit-main/examples/hashlib_new_insecure_functions.py` (With a High confidence)
```python
19 # usedforsecurity arg only availabe in Python 3.9+
20 hashlib.new('sha1', usedforsecurity=True)
21 
```

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
10 
11 h.md5('1')
12 hh.md5('2')
```

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
11 h.md5('1')
12 hh.md5('2')
13 hhh.md5('3').hexdigest()
```

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
12 hh.md5('2')
13 hhh.md5('3').hexdigest()
14 hhhh.md5('4')
```

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
13 hhh.md5('3').hexdigest()
14 hhhh.md5('4')
15 lp({'key': 'value'})
```

### Ssl With Bad Version (B502) (HIGH)

ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue.

[CWE-327](https://cwe.mitre.org/data/definitions/327.html)

#### Instances

`bandit-main/examples/ssl-insecure-version.py` (With a High confidence)
```python
3 
4 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)
5 SSL.Context(method=SSL.SSLv2_METHOD)
```

`bandit-main/examples/ssl-insecure-version.py` (With a High confidence)
```python
4 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)
5 SSL.Context(method=SSL.SSLv2_METHOD)
6 SSL.Context(method=SSL.SSLv23_METHOD)
```

`bandit-main/examples/ssl-insecure-version.py` (With a High confidence)
```python
5 SSL.Context(method=SSL.SSLv2_METHOD)
6 SSL.Context(method=SSL.SSLv23_METHOD)
7 
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
7 
8 herp_derp(ssl_version=ssl.PROTOCOL_SSLv2)
9 herp_derp(method=SSL.SSLv2_METHOD)
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
8 herp_derp(ssl_version=ssl.PROTOCOL_SSLv2)
9 herp_derp(method=SSL.SSLv2_METHOD)
10 herp_derp(method=SSL.SSLv23_METHOD)
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
9 herp_derp(method=SSL.SSLv2_METHOD)
10 herp_derp(method=SSL.SSLv23_METHOD)
11 
```

`bandit-main/examples/ssl-insecure-version.py` (With a High confidence)
```python
12 # strict tests
13 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
14 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
```

`bandit-main/examples/ssl-insecure-version.py` (With a High confidence)
```python
13 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
14 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
15 SSL.Context(method=SSL.SSLv3_METHOD)
```

`bandit-main/examples/ssl-insecure-version.py` (With a High confidence)
```python
14 ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
15 SSL.Context(method=SSL.SSLv3_METHOD)
16 SSL.Context(method=SSL.TLSv1_METHOD)
```

`bandit-main/examples/ssl-insecure-version.py` (With a High confidence)
```python
15 SSL.Context(method=SSL.SSLv3_METHOD)
16 SSL.Context(method=SSL.TLSv1_METHOD)
17 
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
17 
18 herp_derp(ssl_version=ssl.PROTOCOL_SSLv3)
19 herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
18 herp_derp(ssl_version=ssl.PROTOCOL_SSLv3)
19 herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
20 herp_derp(method=SSL.SSLv3_METHOD)
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
19 herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
20 herp_derp(method=SSL.SSLv3_METHOD)
21 herp_derp(method=SSL.TLSv1_METHOD)
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
20 herp_derp(method=SSL.SSLv3_METHOD)
21 herp_derp(method=SSL.TLSv1_METHOD)
22 
```

### Set Bad File Permissions (B103) (HIGH)

Chmod setting a permissive mask 0o227 on file (/etc/passwd).

[CWE-732](https://cwe.mitre.org/data/definitions/732.html)

#### Instances

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
5 
6 os.chmod('/etc/passwd', 0o227)
7 os.chmod('/etc/passwd', 0o7)
```

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
6 os.chmod('/etc/passwd', 0o227)
7 os.chmod('/etc/passwd', 0o7)
8 os.chmod('/etc/passwd', 0o664)
```

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
8 os.chmod('/etc/passwd', 0o664)
9 os.chmod('/etc/passwd', 0o777)
10 os.chmod('/etc/passwd', 0o770)
```

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
9 os.chmod('/etc/passwd', 0o777)
10 os.chmod('/etc/passwd', 0o770)
11 os.chmod('/etc/passwd', 0o776)
```

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
10 os.chmod('/etc/passwd', 0o770)
11 os.chmod('/etc/passwd', 0o776)
12 os.chmod('/etc/passwd', 0o760)
```

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
12 os.chmod('/etc/passwd', 0o760)
13 os.chmod('~/.bashrc', 511)
14 os.chmod('/etc/hosts', 0o777)
```

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
13 os.chmod('~/.bashrc', 511)
14 os.chmod('/etc/hosts', 0o777)
15 os.chmod('/tmp/oh_hai', 0x1ff)
```

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
14 os.chmod('/etc/hosts', 0o777)
15 os.chmod('/tmp/oh_hai', 0x1ff)
16 os.chmod('/etc/passwd', stat.S_IRWXU)
```

`bandit-main/examples/os-chmod.py` (With a High confidence)
```python
16 os.chmod('/etc/passwd', stat.S_IRWXU)
17 os.chmod(key_file, 0o777)
```

### Request With No Cert Validation (B501) (HIGH)

Requests call with verify=False disabling SSL certificate checks, security issue.

[CWE-295](https://cwe.mitre.org/data/definitions/295.html)

#### Instances

`bandit-main/examples/requests-ssl-verify-disabled.py` (With a High confidence)
```python
4 requests.get('https://gmail.com', timeout=30, verify=True)
5 requests.get('https://gmail.com', timeout=30, verify=False)
6 requests.post('https://gmail.com', timeout=30, verify=True)
```

`bandit-main/examples/requests-ssl-verify-disabled.py` (With a High confidence)
```python
6 requests.post('https://gmail.com', timeout=30, verify=True)
7 requests.post('https://gmail.com', timeout=30, verify=False)
8 requests.put('https://gmail.com', timeout=30, verify=True)
```

`bandit-main/examples/requests-ssl-verify-disabled.py` (With a High confidence)
```python
8 requests.put('https://gmail.com', timeout=30, verify=True)
9 requests.put('https://gmail.com', timeout=30, verify=False)
10 requests.delete('https://gmail.com', timeout=30, verify=True)
```

`bandit-main/examples/requests-ssl-verify-disabled.py` (With a High confidence)
```python
10 requests.delete('https://gmail.com', timeout=30, verify=True)
11 requests.delete('https://gmail.com', timeout=30, verify=False)
12 requests.patch('https://gmail.com', timeout=30, verify=True)
```

`bandit-main/examples/requests-ssl-verify-disabled.py` (With a High confidence)
```python
12 requests.patch('https://gmail.com', timeout=30, verify=True)
13 requests.patch('https://gmail.com', timeout=30, verify=False)
14 requests.options('https://gmail.com', timeout=30, verify=True)
```

`bandit-main/examples/requests-ssl-verify-disabled.py` (With a High confidence)
```python
14 requests.options('https://gmail.com', timeout=30, verify=True)
15 requests.options('https://gmail.com', timeout=30, verify=False)
16 requests.head('https://gmail.com', timeout=30, verify=True)
```

`bandit-main/examples/requests-ssl-verify-disabled.py` (With a High confidence)
```python
16 requests.head('https://gmail.com', timeout=30, verify=True)
17 requests.head('https://gmail.com', timeout=30, verify=False)
18 
```

### Jinja2 Autoescape False (B701) (HIGH)

Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Ensure autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.

[CWE-94](https://cwe.mitre.org/data/definitions/94.html)

#### Instances

`bandit-main/examples/jinja2_templating.py` (With a Medium confidence)
```python
8         loader=templateLoader )
9 Environment(loader=templateLoader, load=templateLoader, autoescape=something)
10 templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )
```

`bandit-main/examples/jinja2_templating.py` (With a High confidence)
```python
9 Environment(loader=templateLoader, load=templateLoader, autoescape=something)
10 templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )
11 Environment(loader=templateLoader,
```

`bandit-main/examples/jinja2_templating.py` (With a High confidence)
```python
10 templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )
11 Environment(loader=templateLoader,
12             load=templateLoader,
13             autoescape=False)
14 
```

`bandit-main/examples/jinja2_templating.py` (With a High confidence)
```python
14 
15 Environment(loader=templateLoader,
16             load=templateLoader)
17 
```

`bandit-main/examples/jinja2_templating.py` (With a Medium confidence)
```python
25     return 'foobar'
26 Environment(loader=templateLoader, autoescape=fake_func())
```

### Linux Commands Wildcard Injection (B609) (HIGH)

Possible wildcard injection in call: os.system

[CWE-155](https://cwe.mitre.org/data/definitions/155.html)

#### Instances

`bandit-main/examples/wildcard-injection.py` (With a Medium confidence)
```python
4 # Vulnerable to wildcard injection
5 o.system("/bin/tar xvzf *")
6 o.system('/bin/chown *')
```

`bandit-main/examples/wildcard-injection.py` (With a Medium confidence)
```python
5 o.system("/bin/tar xvzf *")
6 o.system('/bin/chown *')
7 o.popen2('/bin/chmod *')
```

`bandit-main/examples/wildcard-injection.py` (With a Medium confidence)
```python
6 o.system('/bin/chown *')
7 o.popen2('/bin/chmod *')
8 subp.Popen('/bin/chown *', shell=True)
```

`bandit-main/examples/wildcard-injection.py` (With a Medium confidence)
```python
7 o.popen2('/bin/chmod *')
8 subp.Popen('/bin/chown *', shell=True)
9 
```

### Ssh No Host Key Verification (B507) (HIGH)

Paramiko call with policy set to automatically trust the unknown host key.

[CWE-295](https://cwe.mitre.org/data/definitions/295.html)

#### Instances

`bandit-main/examples/no_host_key_verification.py` (With a Medium confidence)
```python
3 ssh_client = client.SSHClient()
4 ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
5 ssh_client.set_missing_host_key_policy(client.WarningPolicy)
```

`bandit-main/examples/no_host_key_verification.py` (With a Medium confidence)
```python
4 ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
5 ssh_client.set_missing_host_key_policy(client.WarningPolicy)
```

### Flask Debug True (B201) (HIGH)

A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.

[CWE-94](https://cwe.mitre.org/data/definitions/94.html)

#### Instances

`bandit-main/examples/flask_debug.py` (With a Medium confidence)
```python
9 #bad
10 app.run(debug=True)
11 
```

### Blacklist (B305) (MEDIUM)

Use of insecure cipher mode cryptography.hazmat.primitives.ciphers.modes.ECB.

[CWE-327](https://cwe.mitre.org/data/definitions/327.html)

#### Instances

`bandit-main/examples/cipher-modes.py` (With a High confidence)
```python
5 # Insecure mode
6 mode = ECB(iv)
7 
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
1 from Crypto.Cipher import ARC2 as pycrypto_arc2
2 from Crypto.Cipher import ARC4 as pycrypto_arc4
3 from Crypto.Cipher import Blowfish as pycrypto_blowfish
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
1 from Crypto.Cipher import ARC2 as pycrypto_arc2
2 from Crypto.Cipher import ARC4 as pycrypto_arc4
3 from Crypto.Cipher import Blowfish as pycrypto_blowfish
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
2 from Crypto.Cipher import ARC4 as pycrypto_arc4
3 from Crypto.Cipher import Blowfish as pycrypto_blowfish
4 from Crypto.Cipher import DES as pycrypto_des
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
3 from Crypto.Cipher import Blowfish as pycrypto_blowfish
4 from Crypto.Cipher import DES as pycrypto_des
5 from Crypto.Cipher import XOR as pycrypto_xor
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
4 from Crypto.Cipher import DES as pycrypto_des
5 from Crypto.Cipher import XOR as pycrypto_xor
6 from Cryptodome.Cipher import ARC2 as pycryptodomex_arc2
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
10 from Cryptodome.Cipher import XOR as pycryptodomex_xor
11 from Crypto.Hash import SHA
12 from Crypto import Random
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
11 from Crypto.Hash import SHA
12 from Crypto import Random
13 from Crypto.Util import Counter
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
12 from Crypto import Random
13 from Crypto.Util import Counter
14 from cryptography.hazmat.primitives.ciphers import Cipher
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
21 iv = Random.new().read(pycrypto_arc2.block_size)
22 cipher = pycrypto_arc2.new(key, pycrypto_arc2.MODE_CFB, iv)
23 msg = iv + cipher.encrypt(b'Attack at dawn')
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
23 msg = iv + cipher.encrypt(b'Attack at dawn')
24 cipher = pycryptodomex_arc2.new(key, pycryptodomex_arc2.MODE_CFB, iv)
25 msg = iv + cipher.encrypt(b'Attack at dawn')
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
28 nonce = Random.new().read(16)
29 tempkey = SHA.new(key+nonce).digest()
30 cipher = pycrypto_arc4.new(tempkey)
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
29 tempkey = SHA.new(key+nonce).digest()
30 cipher = pycrypto_arc4.new(tempkey)
31 msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
31 msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')
32 cipher = pycryptodomex_arc4.new(tempkey)
33 msg = nonce + cipher.encrypt(b'Open the pod bay doors, HAL')
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
41 bs = pycrypto_blowfish.block_size
42 cipher = pycrypto_blowfish.new(key, pycrypto_blowfish.MODE_CBC, iv)
43 msg = iv + cipher.encrypt(plaintext + padding)
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
44 bs = pycryptodomex_blowfish.block_size
45 cipher = pycryptodomex_blowfish.new(key, pycryptodomex_blowfish.MODE_CBC, iv)
46 msg = iv + cipher.encrypt(plaintext + padding)
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
51 ctr = Counter.new(pycrypto_des.block_size*8/2, prefix=nonce)
52 cipher = pycrypto_des.new(key, pycrypto_des.MODE_CTR, counter=ctr)
53 msg = nonce + cipher.encrypt(plaintext)
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
55 ctr = Counter.new(pycryptodomex_des.block_size*8/2, prefix=nonce)
56 cipher = pycryptodomex_des.new(key, pycryptodomex_des.MODE_CTR, counter=ctr)
57 msg = nonce + cipher.encrypt(plaintext)
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
60 plaintext = b'Encrypt me'
61 cipher = pycrypto_xor.new(key)
62 msg = cipher.encrypt(plaintext)
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
62 msg = cipher.encrypt(plaintext)
63 cipher = pycryptodomex_xor.new(key)
64 msg = cipher.encrypt(plaintext)
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
65 
66 cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
67 encryptor = cipher.encryptor()
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
69 
70 cipher = Cipher(algorithms.Blowfish(key), mode=None, backend=default_backend())
71 encryptor = cipher.encryptor()
```

`bandit-main/examples/ciphers.py` (With a High confidence)
```python
73 
74 cipher = Cipher(algorithms.IDEA(key), mode=None, backend=default_backend())
75 encryptor = cipher.encryptor()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
1 from cryptography.hazmat.primitives import hashes
2 from Crypto.Hash import MD2 as pycrypto_md2
3 from Crypto.Hash import MD4 as pycrypto_md4
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
2 from Crypto.Hash import MD2 as pycrypto_md2
3 from Crypto.Hash import MD4 as pycrypto_md4
4 from Crypto.Hash import MD5 as pycrypto_md5
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
3 from Crypto.Hash import MD4 as pycrypto_md4
4 from Crypto.Hash import MD5 as pycrypto_md5
5 from Crypto.Hash import SHA as pycrypto_sha
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
4 from Crypto.Hash import MD5 as pycrypto_md5
5 from Crypto.Hash import SHA as pycrypto_sha
6 from Cryptodome.Hash import MD2 as pycryptodomex_md2
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
22 
23 pycrypto_md2.new()
24 pycrypto_md4.new()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
23 pycrypto_md2.new()
24 pycrypto_md4.new()
25 pycrypto_md5.new()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
24 pycrypto_md4.new()
25 pycrypto_md5.new()
26 pycrypto_sha.new()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
25 pycrypto_md5.new()
26 pycrypto_sha.new()
27 
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
27 
28 pycryptodomex_md2.new()
29 pycryptodomex_md4.new()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
28 pycryptodomex_md2.new()
29 pycryptodomex_md4.new()
30 pycryptodomex_md5.new()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
29 pycryptodomex_md4.new()
30 pycryptodomex_md5.new()
31 pycryptodomex_sha.new()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
30 pycryptodomex_md5.new()
31 pycryptodomex_sha.new()
32 
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
32 
33 hashes.MD5()
34 hashes.SHA1()
```

`bandit-main/examples/crypto-md5.py` (With a High confidence)
```python
33 hashes.MD5()
34 hashes.SHA1()
```

`bandit-main/examples/dill.py` (With a High confidence)
```python
1 import dill
2 import StringIO
3 
```

`bandit-main/examples/dill.py` (With a High confidence)
```python
5 pick = dill.dumps({'a': 'b', 'c': 'd'})
6 print(dill.loads(pick))
7 
```

`bandit-main/examples/dill.py` (With a High confidence)
```python
10 file_obj.seek(0)
11 print(dill.load(file_obj))
12 
```

`bandit-main/examples/eval.py` (With a High confidence)
```python
2 
3 print(eval("1+1"))
4 print(eval("os.getcwd()"))
```

`bandit-main/examples/eval.py` (With a High confidence)
```python
3 print(eval("1+1"))
4 print(eval("os.getcwd()"))
5 print(eval("os.chmod('%s', 0777)" % 'test.txt'))
```

`bandit-main/examples/eval.py` (With a High confidence)
```python
4 print(eval("os.getcwd()"))
5 print(eval("os.chmod('%s', 0777)" % 'test.txt'))
6 
```

`bandit-main/examples/ftplib.py` (With a High confidence)
```python
1 from ftplib import FTP
2 
3 ftp = FTP('ftp.debian.org')
4 ftp.login()
```

`bandit-main/examples/ftplib.py` (With a High confidence)
```python
2 
3 ftp = FTP('ftp.debian.org')
4 ftp.login()
```

`bandit-main/examples/httpoxy_cgihandler.py` (With a High confidence)
```python
9 if __name__ == '__main__':
10     wsgiref.handlers.CGIHandler().run(application)
```

`bandit-main/examples/httpoxy_twisted_directory.py` (With a High confidence)
```python
4 root = static.File("/root")
5 root.putChild("cgi-bin", twcgi.CGIDirectory("/var/www/cgi-bin"))
6 reactor.listenTCP(80, server.Site(root))
```

`bandit-main/examples/httpoxy_twisted_script.py` (With a High confidence)
```python
4 root = static.File("/root")
5 root.putChild("login.cgi", twcgi.CGIScript("/var/www/cgi-bin/login.py"))
6 reactor.listenTCP(80, server.Site(root))
```

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
1 from subprocess import Popen as pop
2 import hashlib as h
3 import hashlib as hh
```

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
5 import hashlib as hhhh
6 from pickle import loads as lp
7 import pickle as p
```

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
6 from pickle import loads as lp
7 import pickle as p
8 
9 pop('/bin/gcc --version', shell=True)
```

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
14 hhhh.md5('4')
15 lp({'key': 'value'})
```

`bandit-main/examples/imports-from.py` (With a High confidence)
```python
1 from subprocess import Popen
2 
3 from ..foo import sys
4 from . import sys
```

`bandit-main/examples/imports-from.py` (With a High confidence)
```python
5 from .. import sys
6 from .. import subprocess
7 from ..subprocess import Popen
```

`bandit-main/examples/imports-from.py` (With a High confidence)
```python
6 from .. import subprocess
7 from ..subprocess import Popen
```

`bandit-main/examples/imports-function.py` (With a High confidence)
```python
1 os = __import__("os")
2 pickle = __import__("pickle")
3 sys = __import__("sys")
```

`bandit-main/examples/imports-function.py` (With a High confidence)
```python
3 sys = __import__("sys")
4 subprocess = __import__("subprocess")
5 
```

`bandit-main/examples/imports-with-importlib.py` (With a High confidence)
```python
2 a = importlib.import_module('os')
3 b = importlib.import_module('pickle')
4 c = importlib.__import__('sys')
```

`bandit-main/examples/imports-with-importlib.py` (With a High confidence)
```python
4 c = importlib.__import__('sys')
5 d = importlib.__import__('subprocess')
6 
```

`bandit-main/examples/imports-with-importlib.py` (With a High confidence)
```python
12 g = importlib.import_module(name='sys')
13 h = importlib.__import__(name='subprocess')
14 i = importlib.import_module(name='subprocess', package='bar.baz')
```

`bandit-main/examples/imports-with-importlib.py` (With a High confidence)
```python
13 h = importlib.__import__(name='subprocess')
14 i = importlib.import_module(name='subprocess', package='bar.baz')
15 j = importlib.__import__(name='sys', package='bar.baz')
```

`bandit-main/examples/imports.py` (With a High confidence)
```python
1 import os
2 import pickle
3 import sys
```

`bandit-main/examples/imports.py` (With a High confidence)
```python
3 import sys
4 import subprocess
```

`bandit-main/examples/mark_safe.py` (With a High confidence)
```python
3 mystr = '<b>Hello World</b>'
4 mystr = safestring.mark_safe(mystr)
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
9 my_insecure_str = insecure_function('insecure', cls='" onload="alert(\'xss\')')
10 safestring.mark_safe(my_insecure_str)
11 safestring.SafeText(my_insecure_str)
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
21         my_insecure_str = 'Secure'
22     safestring.mark_safe(my_insecure_str)
23 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
29         my_insecure_str = insecure_function('insecure', cls=cls)
30     safestring.mark_safe(my_insecure_str)
31 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
40         my_insecure_str = insecure_function('insecure', cls=cls)
41     safestring.mark_safe(my_insecure_str)
42 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
53         my_insecure_str = insecure_function('insecure', cls=cls)
54     safestring.mark_safe(my_insecure_str)
55 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
58     my_insecure_str = insecure_function('insecure', cls=cls)
59     safestring.mark_safe('<b>{} {}</b>'.format(my_insecure_str, 'STR'))
60 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
63     my_insecure_str = insecure_function('insecure', cls=cls)
64     safestring.mark_safe('<b>{}</b>'.format(*[my_insecure_str]))
65 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
68     my_insecure_str = insecure_function('insecure', cls=cls)
69     safestring.mark_safe('<b>{b}</b>'.format(b=my_insecure_str))
70 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
73     my_insecure_str = insecure_function('insecure', cls=cls)
74     safestring.mark_safe('<b>{b}</b>'.format(**{'b': my_insecure_str}))
75 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
78     my_insecure_str = insecure_function('insecure', cls=cls)
79     safestring.mark_safe('<b>%s</b>' % my_insecure_str)
80 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
83     my_insecure_str = insecure_function('insecure', cls=cls)
84     safestring.mark_safe('<b>%s %s</b>' % (my_insecure_str, 'b'))
85 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
88     my_insecure_str = insecure_function('insecure', cls=cls)
89     safestring.mark_safe('<b>%(b)s</b>' % {'b': my_insecure_str})
90 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
93     import sre_constants
94     safestring.mark_safe(sre_constants.ANY)
95 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
98     import sre_constants.ANY as any_str
99     safestring.mark_safe(any_str)
100 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
103     from sre_constants import ANY
104     safestring.mark_safe(ANY)
105 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
108     from sre_constants import ANY as any_str
109     safestring.mark_safe(any_str)
110 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
113     with open(path) as f:
114         safestring.mark_safe(f.read())
115 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
118     with open(path) as f:
119         safestring.mark_safe(f)
120 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
125         my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
126     safestring.mark_safe(my_secure_str)
127 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
132         my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
133     safestring.mark_safe(my_secure_str)
134 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
142         my_secure_str = 'Secure'
143     safestring.mark_safe(my_secure_str)
144 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
148 def test_insecure_shadow():  # var assigned out of scope
149     safestring.mark_safe(mystr)
150 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
152 def test_insecure(str_arg):
153     safestring.mark_safe(str_arg)
154 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
158         str_arg = 'could be insecure'
159     safestring.mark_safe(str_arg)
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
3 
4 safestring.mark_safe('<b>secure</b>')
5 safestring.SafeText('<b>secure</b>')
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
10 my_secure_str = '<b>Hello World</b>'
11 safestring.mark_safe(my_secure_str)
12 
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
13 my_secure_str, _ = ('<b>Hello World</b>', '')
14 safestring.mark_safe(my_secure_str)
15 
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
16 also_secure_str = my_secure_str
17 safestring.mark_safe(also_secure_str)
18 
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
28         my_secure_str = 'Secure'
29     safestring.mark_safe(my_secure_str)
30 
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
32 def format_secure():
33     safestring.mark_safe('<b>{}</b>'.format('secure'))
34     my_secure_str = 'secure'
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
34     my_secure_str = 'secure'
35     safestring.mark_safe('<b>{}</b>'.format(my_secure_str))
36     safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
35     safestring.mark_safe('<b>{}</b>'.format(my_secure_str))
36     safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
37     safestring.mark_safe('<b>{} {}</b>'.format(*[my_secure_str, 'a']))
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
36     safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
37     safestring.mark_safe('<b>{} {}</b>'.format(*[my_secure_str, 'a']))
38     safestring.mark_safe('<b>{b}</b>'.format(b=my_secure_str))  # nosec TODO
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
40     my_secure_str = '<b>{}</b>'.format(my_secure_str)
41     safestring.mark_safe(my_secure_str)
42 
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
44 def percent_secure():
45     safestring.mark_safe('<b>%s</b>' % 'secure')
46     my_secure_str = 'secure'
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
46     my_secure_str = 'secure'
47     safestring.mark_safe('<b>%s</b>' % my_secure_str)
48     safestring.mark_safe('<b>%s %s</b>' % (my_secure_str, 'a'))
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
47     safestring.mark_safe('<b>%s</b>' % my_secure_str)
48     safestring.mark_safe('<b>%s %s</b>' % (my_secure_str, 'a'))
49     safestring.mark_safe('<b>%(b)s</b>' % {'b': my_secure_str})  # nosec TODO
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
53     with open(path) as f:
54         safestring.mark_safe('Secure')
55 
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
61         my_secure_str += ' Secure'
62     safestring.mark_safe(my_secure_str)
63     while ord(os.urandom(1)) % 2 == 0:
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
64         my_secure_str += ' Secure'
65     safestring.mark_safe(my_secure_str)
66 
```

`bandit-main/examples/mark_safe_secure.py` (With a High confidence)
```python
74         my_secure_str = 'Secure'
75     safestring.mark_safe(my_secure_str)
```

`bandit-main/examples/marshal_deserialize.py` (With a High confidence)
```python
5 serialized = marshal.dumps({'a': 1})
6 print(marshal.loads(serialized))
7 
```

`bandit-main/examples/marshal_deserialize.py` (With a High confidence)
```python
10 file_obj.seek(0)
11 print(marshal.load(file_obj))
12 file_obj.close()
```

`bandit-main/examples/mktemp.py` (With a High confidence)
```python
6 
7 mktemp(foo)
8 tempfile.mktemp('foo')
```

`bandit-main/examples/mktemp.py` (With a High confidence)
```python
7 mktemp(foo)
8 tempfile.mktemp('foo')
9 mt(foo)
```

`bandit-main/examples/mktemp.py` (With a High confidence)
```python
8 tempfile.mktemp('foo')
9 mt(foo)
10 tmp.mktemp(foo)
```

`bandit-main/examples/mktemp.py` (With a High confidence)
```python
9 mt(foo)
10 tmp.mktemp(foo)
```

`bandit-main/examples/multiline_statement.py` (With a High confidence)
```python
1 import subprocess
2 
3 subprocess.check_output("/some_command",
4                         "args",
```

`bandit-main/examples/new_candidates-all.py` (With a High confidence)
```python
21     # candidate #5
22     xml.sax.make_parser()
23     # candidate #6
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
1 from subprocess import Popen as pop
2 
3 pop('gcc --version', shell=False)
4 pop('/bin/gcc --version', shell=False)
```

`bandit-main/examples/pickle_deserialize.py` (With a High confidence)
```python
1 import cPickle
2 import pickle
3 import StringIO
```

`bandit-main/examples/pickle_deserialize.py` (With a High confidence)
```python
1 import cPickle
2 import pickle
3 import StringIO
```

`bandit-main/examples/pickle_deserialize.py` (With a High confidence)
```python
7 pick = pickle.dumps({'a': 'b', 'c': 'd'})
8 print(pickle.loads(pick))
9 
```

`bandit-main/examples/pickle_deserialize.py` (With a High confidence)
```python
12 file_obj.seek(0)
13 print(pickle.load(file_obj))
14 
```

`bandit-main/examples/pickle_deserialize.py` (With a High confidence)
```python
15 file_obj.seek(0)
16 print(pickle.Unpickler(file_obj).load())
17 
```

`bandit-main/examples/pickle_deserialize.py` (With a High confidence)
```python
19 serialized = cPickle.dumps({(): []})
20 print(cPickle.loads(serialized))
21 
```

`bandit-main/examples/pickle_deserialize.py` (With a High confidence)
```python
24 file_obj.seek(0)
25 print(cPickle.load(file_obj))
26 
```

`bandit-main/examples/pickle_deserialize.py` (With a High confidence)
```python
27 file_obj.seek(0)
28 print(cPickle.Unpickler(file_obj).load())
29 
```

`bandit-main/examples/pycrypto.py` (With a High confidence)
```python
1 from Crypto.Cipher import AES
2 from Crypto import Random
3 
```

`bandit-main/examples/pycrypto.py` (With a High confidence)
```python
1 from Crypto.Cipher import AES
2 from Crypto import Random
3 
4 from . import CryptoMaterialsCacheEntry
```

`bandit-main/examples/pyghmi.py` (With a High confidence)
```python
1 from pyghmi.ipmi import command
2 
3 cmd = command.Command(bmc="bmc",
4                       userid="userid",
```

`bandit-main/examples/random_module.py` (With a High confidence)
```python
4 
5 bad = random.random()
6 bad = random.randrange()
```

`bandit-main/examples/random_module.py` (With a High confidence)
```python
5 bad = random.random()
6 bad = random.randrange()
7 bad = random.randint()
```

`bandit-main/examples/random_module.py` (With a High confidence)
```python
6 bad = random.randrange()
7 bad = random.randint()
8 bad = random.choice()
```

`bandit-main/examples/random_module.py` (With a High confidence)
```python
7 bad = random.randint()
8 bad = random.choice()
9 bad = random.choices()
```

`bandit-main/examples/random_module.py` (With a High confidence)
```python
8 bad = random.choice()
9 bad = random.choices()
10 bad = random.uniform()
```

`bandit-main/examples/random_module.py` (With a High confidence)
```python
9 bad = random.choices()
10 bad = random.uniform()
11 bad = random.triangular()
```

`bandit-main/examples/random_module.py` (With a High confidence)
```python
10 bad = random.uniform()
11 bad = random.triangular()
12 
```

`bandit-main/examples/shelve_open.py` (With a High confidence)
```python
1 import os
2 import shelve
3 import tempfile
```

`bandit-main/examples/shelve_open.py` (With a High confidence)
```python
7 
8     with shelve.open(filename) as db:
9         db['spam'] = {'eggs': 'ham'}
```

`bandit-main/examples/shelve_open.py` (With a High confidence)
```python
10 
11     with shelve.open(filename) as db:
12         print(db['spam'])
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
1 import subprocess
2 from subprocess import Popen as pop
3 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
1 import subprocess
2 from subprocess import Popen as pop
3 
4 
5 def Popen(*args, **kwargs):
```

`bandit-main/examples/telnetlib.py` (With a High confidence)
```python
1 import telnetlib
2 import getpass
3 
```

`bandit-main/examples/telnetlib.py` (With a High confidence)
```python
7 password = getpass.getpass()
8 tn = telnetlib.Telnet(host)
9 
```

`bandit-main/examples/unverified_context.py` (With a High confidence)
```python
6 # Incorrect: unverified context
7 context = ssl._create_unverified_context()
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
21     url = urllib.quote('file:///bin/ls')
22     urllib.urlopen(url, 'blah', 32)
23     urllib.urlretrieve('file:///bin/ls', '/bin/ls2')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
22     urllib.urlopen(url, 'blah', 32)
23     urllib.urlretrieve('file:///bin/ls', '/bin/ls2')
24     opener = urllib.URLopener()
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
23     urllib.urlretrieve('file:///bin/ls', '/bin/ls2')
24     opener = urllib.URLopener()
25     opener.open('file:///bin/ls')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
26     opener.retrieve('file:///bin/ls')
27     opener = urllib.FancyURLopener()
28     opener.open('file:///bin/ls')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
37     urllib2.install_opener(opener)
38     urllib2.urlopen('file:///bin/ls')
39     urllib2.Request('file:///bin/ls')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
38     urllib2.urlopen('file:///bin/ls')
39     urllib2.Request('file:///bin/ls')
40 
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
41     # Python 3
42     urllib.request.urlopen('file:///bin/ls')
43     urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
42     urllib.request.urlopen('file:///bin/ls')
43     urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
44     opener = urllib.request.URLopener()
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
43     urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
44     opener = urllib.request.URLopener()
45     opener.open('file:///bin/ls')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
46     opener.retrieve('file:///bin/ls')
47     opener = urllib.request.FancyURLopener()
48     opener.open('file:///bin/ls')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
51     # Six
52     six.moves.urllib.request.urlopen('file:///bin/ls')
53     six.moves.urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
52     six.moves.urllib.request.urlopen('file:///bin/ls')
53     six.moves.urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
54     opener = six.moves.urllib.request.URLopener()
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
53     six.moves.urllib.request.urlretrieve('file:///bin/ls', '/bin/ls2')
54     opener = six.moves.urllib.request.URLopener()
55     opener.open('file:///bin/ls')
```

`bandit-main/examples/urlopen.py` (With a High confidence)
```python
56     opener.retrieve('file:///bin/ls')
57     opener = six.moves.urllib.request.FancyURLopener()
58     opener.open('file:///bin/ls')
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
4 from cryptography.hazmat.primitives.asymmetric import rsa
5 from Crypto.PublicKey import DSA as pycrypto_dsa
6 from Crypto.PublicKey import RSA as pycrypto_rsa
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
5 from Crypto.PublicKey import DSA as pycrypto_dsa
6 from Crypto.PublicKey import RSA as pycrypto_rsa
7 from Cryptodome.PublicKey import DSA as pycryptodomex_dsa
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
1 import os as o
2 import subprocess as subp
3 
4 # Vulnerable to wildcard injection
5 o.system("/bin/tar xvzf *")
```

`bandit-main/examples/xml_etree_celementtree.py` (With a High confidence)
```python
1 import xml.etree.cElementTree as badET
2 import defusedxml.cElementTree as goodET
3 
```

`bandit-main/examples/xml_etree_celementtree.py` (With a High confidence)
```python
6 # unsafe
7 tree = badET.fromstring(xmlString)
8 print(tree)
```

`bandit-main/examples/xml_etree_celementtree.py` (With a High confidence)
```python
8 print(tree)
9 badET.parse('filethatdoesntexist.xml')
10 badET.iterparse('filethatdoesntexist.xml')
```

`bandit-main/examples/xml_etree_celementtree.py` (With a High confidence)
```python
9 badET.parse('filethatdoesntexist.xml')
10 badET.iterparse('filethatdoesntexist.xml')
11 a = badET.XMLParser()
```

`bandit-main/examples/xml_etree_celementtree.py` (With a High confidence)
```python
10 badET.iterparse('filethatdoesntexist.xml')
11 a = badET.XMLParser()
12 
```

`bandit-main/examples/xml_etree_elementtree.py` (With a High confidence)
```python
1 import xml.etree.ElementTree as badET
2 import defusedxml.ElementTree as goodET
3 
```

`bandit-main/examples/xml_etree_elementtree.py` (With a High confidence)
```python
6 # unsafe
7 tree = badET.fromstring(xmlString)
8 print(tree)
```

`bandit-main/examples/xml_etree_elementtree.py` (With a High confidence)
```python
8 print(tree)
9 badET.parse('filethatdoesntexist.xml')
10 badET.iterparse('filethatdoesntexist.xml')
```

`bandit-main/examples/xml_etree_elementtree.py` (With a High confidence)
```python
9 badET.parse('filethatdoesntexist.xml')
10 badET.iterparse('filethatdoesntexist.xml')
11 a = badET.XMLParser()
```

`bandit-main/examples/xml_etree_elementtree.py` (With a High confidence)
```python
10 badET.iterparse('filethatdoesntexist.xml')
11 a = badET.XMLParser()
12 
```

`bandit-main/examples/xml_expatbuilder.py` (With a High confidence)
```python
1 import xml.dom.expatbuilder as bad
2 import defusedxml.expatbuilder as good
3 
```

`bandit-main/examples/xml_expatbuilder.py` (With a High confidence)
```python
3 
4 bad.parse('filethatdoesntexist.xml')
5 good.parse('filethatdoesntexist.xml')
```

`bandit-main/examples/xml_expatbuilder.py` (With a High confidence)
```python
8 
9 bad.parseString(xmlString)
10 good.parseString(xmlString)
```

`bandit-main/examples/xml_expatreader.py` (With a High confidence)
```python
1 import xml.sax.expatreader as bad
2 import defusedxml.expatreader as good
3 
```

`bandit-main/examples/xml_expatreader.py` (With a High confidence)
```python
3 
4 p = bad.create_parser()
5 b = good.create_parser()
```

`bandit-main/examples/xml_lxml.py` (With a High confidence)
```python
1 import lxml.etree
2 import lxml
3 from lxml import etree
```

`bandit-main/examples/xml_lxml.py` (With a High confidence)
```python
1 import lxml.etree
2 import lxml
3 from lxml import etree
```

`bandit-main/examples/xml_lxml.py` (With a High confidence)
```python
2 import lxml
3 from lxml import etree
4 from defusedxml.lxml import fromstring
```

`bandit-main/examples/xml_lxml.py` (With a High confidence)
```python
7 xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"
8 root = lxml.etree.fromstring(xmlString)
9 root = fromstring(xmlString)
```

`bandit-main/examples/xml_minidom.py` (With a High confidence)
```python
1 from xml.dom.minidom import parseString as badParseString
2 from defusedxml.minidom import parseString as goodParseString
3 a = badParseString("<myxml>Some data some more data</myxml>")
```

`bandit-main/examples/xml_minidom.py` (With a High confidence)
```python
2 from defusedxml.minidom import parseString as goodParseString
3 a = badParseString("<myxml>Some data some more data</myxml>")
4 print(a)
```

`bandit-main/examples/xml_minidom.py` (With a High confidence)
```python
8 
9 from xml.dom.minidom import parse as badParse
10 from defusedxml.minidom import parse as goodParse
```

`bandit-main/examples/xml_minidom.py` (With a High confidence)
```python
10 from defusedxml.minidom import parse as goodParse
11 a = badParse("somfilethatdoesntexist.xml")
12 print(a)
```

`bandit-main/examples/xml_pulldom.py` (With a High confidence)
```python
1 from xml.dom.pulldom import parseString as badParseString
2 from defusedxml.pulldom import parseString as goodParseString
3 a = badParseString("<myxml>Some data some more data</myxml>")
```

`bandit-main/examples/xml_pulldom.py` (With a High confidence)
```python
2 from defusedxml.pulldom import parseString as goodParseString
3 a = badParseString("<myxml>Some data some more data</myxml>")
4 print(a)
```

`bandit-main/examples/xml_pulldom.py` (With a High confidence)
```python
8 
9 from xml.dom.pulldom import parse as badParse
10 from defusedxml.pulldom import parse as goodParse
```

`bandit-main/examples/xml_pulldom.py` (With a High confidence)
```python
10 from defusedxml.pulldom import parse as goodParse
11 a = badParse("somfilethatdoesntexist.xml")
12 print(a)
```

`bandit-main/examples/xml_sax.py` (With a High confidence)
```python
1 import xml.sax
2 from xml import sax
3 import defusedxml.sax
```

`bandit-main/examples/xml_sax.py` (With a High confidence)
```python
1 import xml.sax
2 from xml import sax
3 import defusedxml.sax
```

`bandit-main/examples/xml_sax.py` (With a High confidence)
```python
20     # bad
21     xml.sax.parseString(xmlString, ExampleContentHandler())
22     xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())
```

`bandit-main/examples/xml_sax.py` (With a High confidence)
```python
21     xml.sax.parseString(xmlString, ExampleContentHandler())
22     xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())
23     sax.parseString(xmlString, ExampleContentHandler())
```

`bandit-main/examples/xml_sax.py` (With a High confidence)
```python
22     xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())
23     sax.parseString(xmlString, ExampleContentHandler())
24     sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler)
```

`bandit-main/examples/xml_sax.py` (With a High confidence)
```python
23     sax.parseString(xmlString, ExampleContentHandler())
24     sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler)
25 
```

`bandit-main/examples/xml_sax.py` (With a High confidence)
```python
29     # bad
30     xml.sax.make_parser()
31     sax.make_parser()
```

`bandit-main/examples/xml_sax.py` (With a High confidence)
```python
30     xml.sax.make_parser()
31     sax.make_parser()
32     print('nothing')
```

`bandit-main/examples/xml_xmlrpc.py` (With a High confidence)
```python
1 import xmlrpclib
2 from SimpleXMLRPCServer import SimpleXMLRPCServer
3 
```

### Django Mark Safe (B703) (MEDIUM)

Potential XSS on mark_safe function.

[CWE-80](https://cwe.mitre.org/data/definitions/80.html)

#### Instances

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
9 my_insecure_str = insecure_function('insecure', cls='" onload="alert(\'xss\')')
10 safestring.mark_safe(my_insecure_str)
11 safestring.SafeText(my_insecure_str)
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
10 safestring.mark_safe(my_insecure_str)
11 safestring.SafeText(my_insecure_str)
12 safestring.SafeUnicode(my_insecure_str)
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
11 safestring.SafeText(my_insecure_str)
12 safestring.SafeUnicode(my_insecure_str)
13 safestring.SafeString(my_insecure_str)
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
12 safestring.SafeUnicode(my_insecure_str)
13 safestring.SafeString(my_insecure_str)
14 safestring.SafeBytes(my_insecure_str)
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
13 safestring.SafeString(my_insecure_str)
14 safestring.SafeBytes(my_insecure_str)
15 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
21         my_insecure_str = 'Secure'
22     safestring.mark_safe(my_insecure_str)
23 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
29         my_insecure_str = insecure_function('insecure', cls=cls)
30     safestring.mark_safe(my_insecure_str)
31 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
40         my_insecure_str = insecure_function('insecure', cls=cls)
41     safestring.mark_safe(my_insecure_str)
42 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
53         my_insecure_str = insecure_function('insecure', cls=cls)
54     safestring.mark_safe(my_insecure_str)
55 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
58     my_insecure_str = insecure_function('insecure', cls=cls)
59     safestring.mark_safe('<b>{} {}</b>'.format(my_insecure_str, 'STR'))
60 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
63     my_insecure_str = insecure_function('insecure', cls=cls)
64     safestring.mark_safe('<b>{}</b>'.format(*[my_insecure_str]))
65 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
68     my_insecure_str = insecure_function('insecure', cls=cls)
69     safestring.mark_safe('<b>{b}</b>'.format(b=my_insecure_str))
70 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
73     my_insecure_str = insecure_function('insecure', cls=cls)
74     safestring.mark_safe('<b>{b}</b>'.format(**{'b': my_insecure_str}))
75 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
78     my_insecure_str = insecure_function('insecure', cls=cls)
79     safestring.mark_safe('<b>%s</b>' % my_insecure_str)
80 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
83     my_insecure_str = insecure_function('insecure', cls=cls)
84     safestring.mark_safe('<b>%s %s</b>' % (my_insecure_str, 'b'))
85 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
88     my_insecure_str = insecure_function('insecure', cls=cls)
89     safestring.mark_safe('<b>%(b)s</b>' % {'b': my_insecure_str})
90 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
93     import sre_constants
94     safestring.mark_safe(sre_constants.ANY)
95 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
98     import sre_constants.ANY as any_str
99     safestring.mark_safe(any_str)
100 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
103     from sre_constants import ANY
104     safestring.mark_safe(ANY)
105 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
108     from sre_constants import ANY as any_str
109     safestring.mark_safe(any_str)
110 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
113     with open(path) as f:
114         safestring.mark_safe(f.read())
115 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
118     with open(path) as f:
119         safestring.mark_safe(f)
120 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
125         my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
126     safestring.mark_safe(my_secure_str)
127 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
132         my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
133     safestring.mark_safe(my_secure_str)
134 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
142         my_secure_str = 'Secure'
143     safestring.mark_safe(my_secure_str)
144 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
148 def test_insecure_shadow():  # var assigned out of scope
149     safestring.mark_safe(mystr)
150 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
152 def test_insecure(str_arg):
153     safestring.mark_safe(str_arg)
154 
```

`bandit-main/examples/mark_safe_insecure.py` (With a High confidence)
```python
158         str_arg = 'could be insecure'
159     safestring.mark_safe(str_arg)
```

### Hardcoded Sql Expressions (B608) (MEDIUM)

Possible SQL injection vector through string-based query construction.

[CWE-89](https://cwe.mitre.org/data/definitions/89.html)

#### Instances

`bandit-main/examples/sql_statements.py` (With a Low confidence)
```python
3 # bad
4 query = "SELECT * FROM foo WHERE id = '%s'" % identifier
5 query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
```

`bandit-main/examples/sql_statements.py` (With a Low confidence)
```python
4 query = "SELECT * FROM foo WHERE id = '%s'" % identifier
5 query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
6 query = "DELETE FROM foo WHERE id = '%s'" % identifier
```

`bandit-main/examples/sql_statements.py` (With a Low confidence)
```python
5 query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
6 query = "DELETE FROM foo WHERE id = '%s'" % identifier
7 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
```

`bandit-main/examples/sql_statements.py` (With a Low confidence)
```python
6 query = "DELETE FROM foo WHERE id = '%s'" % identifier
7 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
8 query = """WITH cte AS (SELECT x FROM foo)
```

`bandit-main/examples/sql_statements.py` (With a Low confidence)
```python
7 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
8 query = """WITH cte AS (SELECT x FROM foo)
9 SELECT x FROM cte WHERE x = '%s'""" % identifier
10 # bad alternate forms
```

`bandit-main/examples/sql_statements.py` (With a Low confidence)
```python
10 # bad alternate forms
11 query = "SELECT * FROM foo WHERE id = '" + identifier + "'"
12 query = "SELECT * FROM foo WHERE id = '{}'".format(identifier)
```

`bandit-main/examples/sql_statements.py` (With a Low confidence)
```python
11 query = "SELECT * FROM foo WHERE id = '" + identifier + "'"
12 query = "SELECT * FROM foo WHERE id = '{}'".format(identifier)
13 
```

`bandit-main/examples/sql_statements.py` (With a Medium confidence)
```python
14 # bad
15 cur.execute("SELECT * FROM foo WHERE id = '%s'" % identifier)
16 cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
```

`bandit-main/examples/sql_statements.py` (With a Medium confidence)
```python
15 cur.execute("SELECT * FROM foo WHERE id = '%s'" % identifier)
16 cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
17 cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
```

`bandit-main/examples/sql_statements.py` (With a Medium confidence)
```python
16 cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
17 cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
18 cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier)
```

`bandit-main/examples/sql_statements.py` (With a Medium confidence)
```python
17 cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
18 cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier)
19 # bad alternate forms
```

`bandit-main/examples/sql_statements.py` (With a Medium confidence)
```python
19 # bad alternate forms
20 cur.execute("SELECT * FROM foo WHERE id = '" + identifier + "'")
21 cur.execute("SELECT * FROM foo WHERE id = '{}'".format(identifier))
```

`bandit-main/examples/sql_statements.py` (With a Medium confidence)
```python
20 cur.execute("SELECT * FROM foo WHERE id = '" + identifier + "'")
21 cur.execute("SELECT * FROM foo WHERE id = '{}'".format(identifier))
22 
```

`bandit-main/examples/sql_statements.py` (With a Low confidence)
```python
34 
35 a()("SELECT %s FROM foo" % val)
36 
```

### Weak Cryptographic Key (B505) (MEDIUM)

DSA key sizes below 2048 bits are considered breakable. 

[CWE-326](https://cwe.mitre.org/data/definitions/326.html)

#### Instances

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
37 # Incorrect: weak key sizes
38 dsa.generate_private_key(key_size=1024,
39                          backend=backends.default_backend())
40 ec.generate_private_key(curve=ec.SECT163R2,
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
39                          backend=backends.default_backend())
40 ec.generate_private_key(curve=ec.SECT163R2,
41                         backend=backends.default_backend())
42 rsa.generate_private_key(public_exponent=65537,
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
41                         backend=backends.default_backend())
42 rsa.generate_private_key(public_exponent=65537,
43                          key_size=1024,
44                          backend=backends.default_backend())
45 pycrypto_dsa.generate(bits=1024)
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
44                          backend=backends.default_backend())
45 pycrypto_dsa.generate(bits=1024)
46 pycrypto_rsa.generate(bits=1024)
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
45 pycrypto_dsa.generate(bits=1024)
46 pycrypto_rsa.generate(bits=1024)
47 pycryptodomex_dsa.generate(bits=1024)
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
46 pycrypto_rsa.generate(bits=1024)
47 pycryptodomex_dsa.generate(bits=1024)
48 pycryptodomex_rsa.generate(bits=1024)
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
47 pycryptodomex_dsa.generate(bits=1024)
48 pycryptodomex_rsa.generate(bits=1024)
49 
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
50 # Also incorrect: without keyword args
51 dsa.generate_private_key(512,
52                          backends.default_backend())
53 ec.generate_private_key(ec.SECT163R2,
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
52                          backends.default_backend())
53 ec.generate_private_key(ec.SECT163R2,
54                         backends.default_backend())
55 rsa.generate_private_key(3,
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
54                         backends.default_backend())
55 rsa.generate_private_key(3,
56                          512,
57                          backends.default_backend())
58 pycrypto_dsa.generate(512)
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
57                          backends.default_backend())
58 pycrypto_dsa.generate(512)
59 pycrypto_rsa.generate(512)
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
58 pycrypto_dsa.generate(512)
59 pycrypto_rsa.generate(512)
60 pycryptodomex_dsa.generate(512)
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
59 pycrypto_rsa.generate(512)
60 pycryptodomex_dsa.generate(512)
61 pycryptodomex_rsa.generate(512)
```

`bandit-main/examples/weak_cryptographic_key_sizes.py` (With a High confidence)
```python
60 pycryptodomex_dsa.generate(512)
61 pycryptodomex_rsa.generate(512)
62 
```

### Django Extra Used (B610) (MEDIUM)

Use of extra potential SQL attack vector.

[CWE-89](https://cwe.mitre.org/data/definitions/89.html)

#### Instances

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
11 
12 User.objects.filter(username='admin').extra(dict(could_be='insecure'))
13 User.objects.filter(username='admin').extra(select=dict(could_be='insecure'))
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
12 User.objects.filter(username='admin').extra(dict(could_be='insecure'))
13 User.objects.filter(username='admin').extra(select=dict(could_be='insecure'))
14 query = '"username") AS "username", * FROM "auth_user" WHERE 1=1 OR "username"=? --'
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
14 query = '"username") AS "username", * FROM "auth_user" WHERE 1=1 OR "username"=? --'
15 User.objects.filter(username='admin').extra(select={'test': query})
16 User.objects.filter(username='admin').extra(select={'test': '%secure' % 'nos'})
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
15 User.objects.filter(username='admin').extra(select={'test': query})
16 User.objects.filter(username='admin').extra(select={'test': '%secure' % 'nos'})
17 User.objects.filter(username='admin').extra(select={'test': '{}secure'.format('nos')})
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
16 User.objects.filter(username='admin').extra(select={'test': '%secure' % 'nos'})
17 User.objects.filter(username='admin').extra(select={'test': '{}secure'.format('nos')})
18 
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
19 where_var = ['1=1) OR 1=1 AND (1=1']
20 User.objects.filter(username='admin').extra(where=where_var)
21 where_str = '1=1) OR 1=1 AND (1=1'
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
21 where_str = '1=1) OR 1=1 AND (1=1'
22 User.objects.filter(username='admin').extra(where=[where_str])
23 User.objects.filter(username='admin').extra(where=['%secure' % 'nos'])
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
22 User.objects.filter(username='admin').extra(where=[where_str])
23 User.objects.filter(username='admin').extra(where=['%secure' % 'nos'])
24 User.objects.filter(username='admin').extra(where=['{}secure'.format('no')])
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
23 User.objects.filter(username='admin').extra(where=['%secure' % 'nos'])
24 User.objects.filter(username='admin').extra(where=['{}secure'.format('no')])
25 
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
26 tables_var = ['django_content_type" WHERE "auth_user"."username"="admin']
27 User.objects.all().extra(tables=tables_var).distinct()
28 tables_str = 'django_content_type" WHERE "auth_user"."username"="admin'
```

`bandit-main/examples/django_sql_injection_extra.py` (With a Medium confidence)
```python
28 tables_str = 'django_content_type" WHERE "auth_user"."username"="admin'
29 User.objects.all().extra(tables=[tables_str]).distinct()
```

### Django Rawsql Used (B611) (MEDIUM)

Use of RawSQL potential SQL attack vector.

[CWE-89](https://cwe.mitre.org/data/definitions/89.html)

#### Instances

`bandit-main/examples/django_sql_injection_raw.py` (With a Medium confidence)
```python
4 User.objects.annotate(val=RawSQL('secure', []))
5 User.objects.annotate(val=RawSQL('%secure' % 'nos', []))
6 User.objects.annotate(val=RawSQL('{}secure'.format('no'), []))
```

`bandit-main/examples/django_sql_injection_raw.py` (With a Medium confidence)
```python
5 User.objects.annotate(val=RawSQL('%secure' % 'nos', []))
6 User.objects.annotate(val=RawSQL('{}secure'.format('no'), []))
7 raw = '"username") AS "val" FROM "auth_user" WHERE "username"="admin" --'
```

`bandit-main/examples/django_sql_injection_raw.py` (With a Medium confidence)
```python
7 raw = '"username") AS "val" FROM "auth_user" WHERE "username"="admin" --'
8 User.objects.annotate(val=RawSQL(raw, []))
9 raw = '"username") AS "val" FROM "auth_user"' \
```

`bandit-main/examples/django_sql_injection_raw.py` (With a Medium confidence)
```python
10       ' WHERE "username"="admin" OR 1=%s --'
11 User.objects.annotate(val=RawSQL(raw, [0]))
```

### Hardcoded Tmp Directory (B108) (MEDIUM)

Probable insecure usage of temp file/directory.

[CWE-377](https://cwe.mitre.org/data/definitions/377.html)

#### Instances

`bandit-main/examples/hardcoded-tmp.py` (With a Medium confidence)
```python
1 with open('/tmp/abc', 'w') as f:
2     f.write('def')
3 
```

`bandit-main/examples/hardcoded-tmp.py` (With a Medium confidence)
```python
7 
8 with open('/var/tmp/123', 'w') as f:
9     f.write('def')
```

`bandit-main/examples/hardcoded-tmp.py` (With a Medium confidence)
```python
10 
11 with open('/dev/shm/unit/test', 'w') as f:
12     f.write('def')
```

`bandit-main/examples/os-chmod.py` (With a Medium confidence)
```python
14 os.chmod('/etc/hosts', 0o777)
15 os.chmod('/tmp/oh_hai', 0x1ff)
16 os.chmod('/etc/passwd', stat.S_IRWXU)
```

### Use Of Mako Templates (B702) (MEDIUM)

Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.

[CWE-80](https://cwe.mitre.org/data/definitions/80.html)

#### Instances

`bandit-main/examples/mako_templating.py` (With a High confidence)
```python
5 
6 Template("hello")
7 
```

`bandit-main/examples/mako_templating.py` (With a High confidence)
```python
9 # in for now so that if it gets fixed inadvertitently we know.
10 mako.template.Template("hern")
11 template.Template("hern")
```

`bandit-main/examples/mako_templating.py` (With a High confidence)
```python
10 mako.template.Template("hern")
11 template.Template("hern")
```

### Yaml Load (B506) (MEDIUM)

Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().

[CWE-20](https://cwe.mitre.org/data/definitions/20.html)

#### Instances

`bandit-main/examples/new_candidates-all.py` (With a High confidence)
```python
14     # candidate #3
15     y = yaml.load(temp_str)
16     # candidate #4
```

`bandit-main/examples/yaml_load.py` (With a High confidence)
```python
6     ystr = yaml.dump({'a': 1, 'b': 2, 'c': 3})
7     y = yaml.load(ystr)
8     yaml.dump(y)
```

`bandit-main/examples/yaml_load.py` (With a High confidence)
```python
19 
20 yaml.load("{}", Loader=yaml.Loader)
```

### Ssl With Bad Defaults (B503) (MEDIUM)

Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.

[CWE-327](https://cwe.mitre.org/data/definitions/327.html)

#### Instances

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
24 
25 def open_ssl_socket(version=ssl.PROTOCOL_SSLv2):
26     pass
27 
28 def open_ssl_socket(version=SSL.SSLv2_METHOD):
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
27 
28 def open_ssl_socket(version=SSL.SSLv2_METHOD):
29     pass
30 
31 def open_ssl_socket(version=SSL.SSLv23_METHOD):
```

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
30 
31 def open_ssl_socket(version=SSL.SSLv23_METHOD):
32     pass
33 
34 # this one will pass ok
35 def open_ssl_socket(version=SSL.TLSv1_1_METHOD):
```

### Snmp Crypto Check (B509) (MEDIUM)

You should not use SNMPv3 without encryption. noAuthNoPriv & authNoPriv is insecure

[CWE-319](https://cwe.mitre.org/data/definitions/319.html)

#### Instances

`bandit-main/examples/snmp.py` (With a High confidence)
```python
5 # SHOULD FAIL
6 insecure = UsmUserData("securityName")
7 # SHOULD FAIL
```

`bandit-main/examples/snmp.py` (With a High confidence)
```python
7 # SHOULD FAIL
8 auth_no_priv = UsmUserData("securityName","authName")
9 # SHOULD PASS
```

### Hardcoded Bind All Interfaces (B104) (MEDIUM)

Possible binding to all interfaces.

[CWE-605](https://cwe.mitre.org/data/definitions/605.html)

#### Instances

`bandit-main/examples/binding.py` (With a Medium confidence)
```python
3 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
4 s.bind(('0.0.0.0', 31137))
5 s.bind(('192.168.0.1', 8080))
```

### Exec Used (B102) (MEDIUM)

Use of exec detected.

[CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### Instances

`bandit-main/examples/exec.py` (With a High confidence)
```python
1 exec("do evil")
```

### Paramiko Calls (B601) (MEDIUM)

Possible shell injection via Paramiko call, check inputs are properly sanitized.

[CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### Instances

`bandit-main/examples/paramiko_injection.py` (With a Medium confidence)
```python
6 # this is not safe
7 client.exec_command('something; really; unsafe')
8 
```

### Snmp Insecure Version Check (B508) (MEDIUM)

The use of SNMPv1 and SNMPv2 is insecure. You should use SNMPv3 if able.

[CWE-319](https://cwe.mitre.org/data/definitions/319.html)

#### Instances

`bandit-main/examples/snmp.py` (With a High confidence)
```python
3 # SHOULD FAIL
4 a = CommunityData('public', mpModel=0)
5 # SHOULD FAIL
```

### Any Other Function With Shell Equals True (B604) (MEDIUM)

Function call with shell=True parameter identified, possible security issue.

[CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### Instances

`bandit-main/examples/subprocess_shell.py` (With a Low confidence)
```python
11 pop('/bin/gcc --version', shell=True)
12 Popen('/bin/gcc --version', shell=True)
13 
```

### Subprocess Popen With Shell Equals True (B602) (LOW)

subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell

[CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### Instances

`bandit-main/examples/imports-aliases.py` (With a High confidence)
```python
8 
9 pop('/bin/gcc --version', shell=True)
10 
```

`bandit-main/examples/multiline_statement.py` (With a High confidence)
```python
4                         "args",
5                         shell=True,
6                         universal_newlines=True)
7 
8 subprocess.check_output(
9     "/some_command",
```

`bandit-main/examples/multiline_statement.py` (With a High confidence)
```python
10     "args",
11     shell=True,
12     universal_newlines=True
13 )
```

`bandit-main/examples/new_candidates-all.py` (With a High confidence)
```python
6     # candidate #1
7     subprocess.Popen('/bin/ls *', shell=True)
8     # candidate #2
```

`bandit-main/examples/new_candidates-some.py` (With a High confidence)
```python
6     # candidate #1
7     subprocess.Popen('/bin/ls *', shell=True)
8     # candidate #2
```

`bandit-main/examples/nosec.py` (With a High confidence)
```python
5                  shell=True)  #nosec (on the specific kwarg line)
6 subprocess.Popen('#nosec', shell=True)
7 subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec # noqa: E501 ; pylint: disable=line-too-long
```

`bandit-main/examples/nosec.py` (With a High confidence)
```python
7 subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec # noqa: E501 ; pylint: disable=line-too-long
8 subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec B607 # noqa: E501 ; pylint: disable=line-too-long
9 subprocess.Popen('/bin/ls *', shell=True)  #nosec subprocess_popen_with_shell_equals_true (on the line)
```

`bandit-main/examples/nosec.py` (With a High confidence)
```python
13 subprocess.Popen('/bin/ls *', shell=True) # type: ... # noqa: E501 ; pylint: disable=line-too-long # nosec
14 subprocess.Popen('#nosec', shell=True) # nosec B607, B101
15 subprocess.Popen('#nosec', shell=True) # nosec B602, subprocess_popen_with_shell_equals_true
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
10 
11 pop('/bin/gcc --version', shell=True)
12 Popen('/bin/gcc --version', shell=True)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
13 
14 subprocess.Popen('/bin/gcc --version', shell=True)
15 subprocess.Popen(['/bin/gcc', '--version'], shell=False)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
20                  ])
21 subprocess.call('/bin/ls -l', shell=True)
22 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
23 subprocess.check_call(['/bin/ls', '-l'], shell=False)
24 subprocess.check_call('/bin/ls -l', shell=True)
25 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
26 subprocess.check_output(['/bin/ls', '-l'])
27 subprocess.check_output('/bin/ls -l', shell=True)
28 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
29 subprocess.run(['/bin/ls', '-l'])
30 subprocess.run('/bin/ls -l', shell=True)
31 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
31 
32 subprocess.Popen('/bin/ls *', shell=True)
33 subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
32 subprocess.Popen('/bin/ls *', shell=True)
33 subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
34 subprocess.Popen('/bin/ls {}'.format('something'), shell=True)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
33 subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
34 subprocess.Popen('/bin/ls {}'.format('something'), shell=True)
35 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
36 command = "/bin/ls" + unknown_function()
37 subprocess.Popen(command, shell=True)
38 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
38 
39 subprocess.Popen('/bin/ls && cat /etc/passwd', shell=True)
40 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
41 command = 'pwd'
42 subprocess.call(command, shell='True')
43 subprocess.call(command, shell='False')
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
42 subprocess.call(command, shell='True')
43 subprocess.call(command, shell='False')
44 subprocess.call(command, shell='None')
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
43 subprocess.call(command, shell='False')
44 subprocess.call(command, shell='None')
45 subprocess.call(command, shell=1)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
44 subprocess.call(command, shell='None')
45 subprocess.call(command, shell=1)
46 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
46 
47 subprocess.call(command, shell=Popen())
48 subprocess.call(command, shell=[True])
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
47 subprocess.call(command, shell=Popen())
48 subprocess.call(command, shell=[True])
49 subprocess.call(command, shell={'IS': 'True'})
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
48 subprocess.call(command, shell=[True])
49 subprocess.call(command, shell={'IS': 'True'})
50 subprocess.call(command, shell=command)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
49 subprocess.call(command, shell={'IS': 'True'})
50 subprocess.call(command, shell=command)
51 
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
7 o.popen2('/bin/chmod *')
8 subp.Popen('/bin/chown *', shell=True)
9 
```

### Subprocess Without Shell Equals True (B603) (LOW)

subprocess call - check for execution of untrusted input.

[CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### Instances

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
2 
3 pop('gcc --version', shell=False)
4 pop('/bin/gcc --version', shell=False)
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
3 pop('gcc --version', shell=False)
4 pop('/bin/gcc --version', shell=False)
5 pop(var, shell=False)
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
4 pop('/bin/gcc --version', shell=False)
5 pop(var, shell=False)
6 
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
6 
7 pop(['ls', '-l'], shell=False)
8 pop(['/bin/ls', '-l'], shell=False)
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
7 pop(['ls', '-l'], shell=False)
8 pop(['/bin/ls', '-l'], shell=False)
9 
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
9 
10 pop('../ls -l', shell=False)
11 
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
11 
12 pop('c:\\hello\\something', shell=False)
13 pop('c:/hello/something_else', shell=False)
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
12 pop('c:\\hello\\something', shell=False)
13 pop('c:/hello/something_else', shell=False)
```

`bandit-main/examples/skip.py` (With a High confidence)
```python
1 subprocess.call(["/bin/ls", "-l"])
2 subprocess.call(["/bin/ls", "-l"]) #noqa
3 subprocess.call(["/bin/ls", "-l"]) # noqa
```

`bandit-main/examples/skip.py` (With a High confidence)
```python
1 subprocess.call(["/bin/ls", "-l"])
2 subprocess.call(["/bin/ls", "-l"]) #noqa
3 subprocess.call(["/bin/ls", "-l"]) # noqa
```

`bandit-main/examples/skip.py` (With a High confidence)
```python
2 subprocess.call(["/bin/ls", "-l"]) #noqa
3 subprocess.call(["/bin/ls", "-l"]) # noqa
4 subprocess.call(["/bin/ls", "-l"]) # nosec
```

`bandit-main/examples/skip.py` (With a High confidence)
```python
4 subprocess.call(["/bin/ls", "-l"]) # nosec
5 subprocess.call(["/bin/ls", "-l"])
6 subprocess.call(["/bin/ls", "-l"]) #nosec
```

`bandit-main/examples/skip.py` (With a High confidence)
```python
6 subprocess.call(["/bin/ls", "-l"]) #nosec
7 subprocess.call(["/bin/ls", "-l"])
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
14 subprocess.Popen('/bin/gcc --version', shell=True)
15 subprocess.Popen(['/bin/gcc', '--version'], shell=False)
16 subprocess.Popen(['/bin/gcc', '--version'])
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
15 subprocess.Popen(['/bin/gcc', '--version'], shell=False)
16 subprocess.Popen(['/bin/gcc', '--version'])
17 
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
17 
18 subprocess.call(["/bin/ls",
19                  "-l"
20                  ])
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
22 
23 subprocess.check_call(['/bin/ls', '-l'], shell=False)
24 subprocess.check_call('/bin/ls -l', shell=True)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
25 
26 subprocess.check_output(['/bin/ls', '-l'])
27 subprocess.check_output('/bin/ls -l', shell=True)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
28 
29 subprocess.run(['/bin/ls', '-l'])
30 subprocess.run('/bin/ls -l', shell=True)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
51 
52 subprocess.call(command, shell=False)
53 subprocess.call(command, shell=0)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
52 subprocess.call(command, shell=False)
53 subprocess.call(command, shell=0)
54 subprocess.call(command, shell=[])
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
53 subprocess.call(command, shell=0)
54 subprocess.call(command, shell=[])
55 subprocess.call(command, shell={})
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
54 subprocess.call(command, shell=[])
55 subprocess.call(command, shell={})
56 subprocess.call(command, shell=None)
```

`bandit-main/examples/subprocess_shell.py` (With a High confidence)
```python
55 subprocess.call(command, shell={})
56 subprocess.call(command, shell=None)
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
10 # Not vulnerable to wildcard injection
11 subp.Popen('/bin/rsync *')
12 subp.Popen("/bin/chmod *")
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
11 subp.Popen('/bin/rsync *')
12 subp.Popen("/bin/chmod *")
13 subp.Popen(['/bin/chown', '*'])
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
12 subp.Popen("/bin/chmod *")
13 subp.Popen(['/bin/chown', '*'])
14 subp.Popen(["/bin/chmod", sys.argv[1], "*"],
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
13 subp.Popen(['/bin/chown', '*'])
14 subp.Popen(["/bin/chmod", sys.argv[1], "*"],
15                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
16 o.spawnvp(os.P_WAIT, 'tar', ['tar', 'xvzf', '*'])
```

### Start Process With No Shell (B606) (LOW)

Starting a process without a shell.

[CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### Instances

`bandit-main/examples/os-exec.py` (With a Medium confidence)
```python
2 
3 os.execl(path, arg0, arg1)
4 os.execle(path, arg0, arg1, env)
```

`bandit-main/examples/os-exec.py` (With a Medium confidence)
```python
3 os.execl(path, arg0, arg1)
4 os.execle(path, arg0, arg1, env)
5 os.execlp(file, arg0, arg1)
```

`bandit-main/examples/os-exec.py` (With a Medium confidence)
```python
4 os.execle(path, arg0, arg1, env)
5 os.execlp(file, arg0, arg1)
6 os.execlpe(file, arg0, arg1, env)
```

`bandit-main/examples/os-exec.py` (With a Medium confidence)
```python
5 os.execlp(file, arg0, arg1)
6 os.execlpe(file, arg0, arg1, env)
7 os.execv(path, args)
```

`bandit-main/examples/os-exec.py` (With a Medium confidence)
```python
6 os.execlpe(file, arg0, arg1, env)
7 os.execv(path, args)
8 os.execve(path, args, env)
```

`bandit-main/examples/os-exec.py` (With a Medium confidence)
```python
7 os.execv(path, args)
8 os.execve(path, args, env)
9 os.execvp(file, args)
```

`bandit-main/examples/os-exec.py` (With a Medium confidence)
```python
8 os.execve(path, args, env)
9 os.execvp(file, args)
10 os.execvpe(file, args, env)
```

`bandit-main/examples/os-exec.py` (With a Medium confidence)
```python
9 os.execvp(file, args)
10 os.execvpe(file, args, env)
11 
```

`bandit-main/examples/os-spawn.py` (With a Medium confidence)
```python
2 
3 os.spawnl(mode, path)
4 os.spawnle(mode, path, env)
```

`bandit-main/examples/os-spawn.py` (With a Medium confidence)
```python
3 os.spawnl(mode, path)
4 os.spawnle(mode, path, env)
5 os.spawnlp(mode, file)
```

`bandit-main/examples/os-spawn.py` (With a Medium confidence)
```python
4 os.spawnle(mode, path, env)
5 os.spawnlp(mode, file)
6 os.spawnlpe(mode, file, env)
```

`bandit-main/examples/os-spawn.py` (With a Medium confidence)
```python
5 os.spawnlp(mode, file)
6 os.spawnlpe(mode, file, env)
7 os.spawnv(mode, path, args)
```

`bandit-main/examples/os-spawn.py` (With a Medium confidence)
```python
6 os.spawnlpe(mode, file, env)
7 os.spawnv(mode, path, args)
8 os.spawnve(mode, path, args, env)
```

`bandit-main/examples/os-spawn.py` (With a Medium confidence)
```python
7 os.spawnv(mode, path, args)
8 os.spawnve(mode, path, args, env)
9 os.spawnvp(mode, file, args)
```

`bandit-main/examples/os-spawn.py` (With a Medium confidence)
```python
8 os.spawnve(mode, path, args, env)
9 os.spawnvp(mode, file, args)
10 os.spawnvpe(mode, file, args, env)
```

`bandit-main/examples/os-spawn.py` (With a Medium confidence)
```python
9 os.spawnvp(mode, file, args)
10 os.spawnvpe(mode, file, args, env)
```

`bandit-main/examples/os-startfile.py` (With a Medium confidence)
```python
2 
3 os.startfile('/bin/foo.docx')
4 os.startfile('/bin/bad.exe')
```

`bandit-main/examples/os-startfile.py` (With a Medium confidence)
```python
3 os.startfile('/bin/foo.docx')
4 os.startfile('/bin/bad.exe')
5 os.startfile('/bin/text.txt')
```

`bandit-main/examples/os-startfile.py` (With a Medium confidence)
```python
4 os.startfile('/bin/bad.exe')
5 os.startfile('/bin/text.txt')
```

`bandit-main/examples/wildcard-injection.py` (With a Medium confidence)
```python
15                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
16 o.spawnvp(os.P_WAIT, 'tar', ['tar', 'xvzf', '*'])
```

### Start Process With A Shell (B605) (LOW)

Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell

[CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### Instances

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
5 
6 os.popen('/bin/uname -av')
7 popen('/bin/uname -av')
```

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
6 os.popen('/bin/uname -av')
7 popen('/bin/uname -av')
8 o.popen('/bin/uname -av')
```

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
7 popen('/bin/uname -av')
8 o.popen('/bin/uname -av')
9 pos('/bin/uname -av')
```

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
8 o.popen('/bin/uname -av')
9 pos('/bin/uname -av')
10 os.popen2('/bin/uname -av')
```

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
9 pos('/bin/uname -av')
10 os.popen2('/bin/uname -av')
11 os.popen3('/bin/uname -av')
```

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
10 os.popen2('/bin/uname -av')
11 os.popen3('/bin/uname -av')
12 os.popen4('/bin/uname -av')
```

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
11 os.popen3('/bin/uname -av')
12 os.popen4('/bin/uname -av')
13 
```

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
13 
14 os.popen4('/bin/uname -av; rm -rf /')
15 os.popen4(some_var)
```

`bandit-main/examples/os-popen.py` (With a High confidence)
```python
14 os.popen4('/bin/uname -av; rm -rf /')
15 os.popen4(some_var)
```

`bandit-main/examples/os_system.py` (With a High confidence)
```python
2 
3 os.system('/bin/echo hi')
```

`bandit-main/examples/popen_wrappers.py` (With a High confidence)
```python
4 
5 print(commands.getstatusoutput('/bin/echo / | xargs ls'))
6 print(commands.getoutput('/bin/echo / | xargs ls'))
```

`bandit-main/examples/popen_wrappers.py` (With a High confidence)
```python
5 print(commands.getstatusoutput('/bin/echo / | xargs ls'))
6 print(commands.getoutput('/bin/echo / | xargs ls'))
7 
```

`bandit-main/examples/popen_wrappers.py` (With a High confidence)
```python
10 
11 print(popen2.popen2('/bin/echo / | xargs ls')[0].read())
12 print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
```

`bandit-main/examples/popen_wrappers.py` (With a High confidence)
```python
11 print(popen2.popen2('/bin/echo / | xargs ls')[0].read())
12 print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
13 print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
```

`bandit-main/examples/popen_wrappers.py` (With a High confidence)
```python
12 print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
13 print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
14 print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
```

`bandit-main/examples/popen_wrappers.py` (With a High confidence)
```python
13 print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
14 print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
15 print(popen2.Popen4('/bin/echo / | xargs ls').fromchild.read())
```

`bandit-main/examples/popen_wrappers.py` (With a High confidence)
```python
14 print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
15 print(popen2.Popen4('/bin/echo / | xargs ls').fromchild.read())
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
4 # Vulnerable to wildcard injection
5 o.system("/bin/tar xvzf *")
6 o.system('/bin/chown *')
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
5 o.system("/bin/tar xvzf *")
6 o.system('/bin/chown *')
7 o.popen2('/bin/chmod *')
```

`bandit-main/examples/wildcard-injection.py` (With a High confidence)
```python
6 o.system('/bin/chown *')
7 o.popen2('/bin/chmod *')
8 subp.Popen('/bin/chown *', shell=True)
```

### Hardcoded Password String (B105) (LOW)

Possible hardcoded password: 'class_password'

[CWE-259](https://cwe.mitre.org/data/definitions/259.html)

#### Instances

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
3 class SomeClass:
4     password = "class_password"
5 
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
13     # Severity: Low   Confidence: Medium
14     if password == "root":
15         print("OK, logged in")
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
19     # Severity: Low   Confidence: Medium
20     if password == '':
21         print("No password!")
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
25     # Severity: Low   Confidence: Medium
26     if password == "ajklawejrkl42348swfgkg":
27         print("Nice password!")
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
32     # Severity: Low   Confidence: Medium
33     if obj.password == "this cool password":
34         print(obj.password)
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
49 # Severity: Low   Confidence: Medium
50 password = "blerg"
51 
52 # Possible hardcoded password: 'blerg'
53 # Severity: Low   Confidence: Medium
54 d["password"] = "blerg"
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
53 # Severity: Low   Confidence: Medium
54 d["password"] = "blerg"
55 
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
57 # Severity: Low   Confidence: Medium
58 EMAIL_PASSWORD = "secret"
59 
60 # Possible hardcoded password: 'emails_secret'
61 # Severity: Low   Confidence: Medium
62 email_pwd = 'emails_secret'
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
61 # Severity: Low   Confidence: Medium
62 email_pwd = 'emails_secret'
63 
64 # Possible hardcoded password: 'd6s$f9g!j8mg7hw?n&2'
65 # Severity: Low   Confidence: Medium
66 my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
65 # Severity: Low   Confidence: Medium
66 my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'
67 
68 # Possible hardcoded password: '1234'
69 # Severity: Low   Confidence: Medium
70 passphrase='1234'
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
69 # Severity: Low   Confidence: Medium
70 passphrase='1234'
```

### Start Process With Partial Path (B607) (LOW)

Starting a process with a partial executable path

[CWE-78](https://cwe.mitre.org/data/definitions/78.html)

#### Instances

`bandit-main/examples/nosec.py` (With a High confidence)
```python
5                  shell=True)  #nosec (on the specific kwarg line)
6 subprocess.Popen('#nosec', shell=True)
7 subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec # noqa: E501 ; pylint: disable=line-too-long
```

`bandit-main/examples/nosec.py` (With a High confidence)
```python
14 subprocess.Popen('#nosec', shell=True) # nosec B607, B101
15 subprocess.Popen('#nosec', shell=True) # nosec B602, subprocess_popen_with_shell_equals_true
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
2 
3 pop('gcc --version', shell=False)
4 pop('/bin/gcc --version', shell=False)
```

`bandit-main/examples/partial_path_process.py` (With a High confidence)
```python
6 
7 pop(['ls', '-l'], shell=False)
8 pop(['/bin/ls', '-l'], shell=False)
```

### Hardcoded Password Default (B107) (LOW)

Possible hardcoded password: 'Admin'

[CWE-259](https://cwe.mitre.org/data/definitions/259.html)

#### Instances

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
7 # Severity: Low   Confidence: Medium
8 def someFunction(user, password="Admin"):
9     print("Hi " + user)
10 
11 def someFunction2(password):
```

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
37 # Severity: Low   Confidence: Medium
38 def doLogin(password="blerg"):
39     pass
40 
41 def NoMatch3(a, b):
```

### Hardcoded Password Funcarg (B106) (LOW)

Possible hardcoded password: 'blerg'

[CWE-259](https://cwe.mitre.org/data/definitions/259.html)

#### Instances

`bandit-main/examples/hardcoded-passwords.py` (With a Medium confidence)
```python
45 # Severity: Low   Confidence: Medium
46 doLogin(password="blerg")
47 
```

`bandit-main/examples/pyghmi.py` (With a Medium confidence)
```python
2 
3 cmd = command.Command(bmc="bmc",
4                       userid="userid",
5                       password="ZjE4ZjI0NTE4YmI2NGJjZDliOGY3ZmJiY2UyN2IzODQK")
```

### Try Except Continue (B112) (LOW)

Try, Except, Continue detected.

[CWE-703](https://cwe.mitre.org/data/definitions/703.html)

#### Instances

`bandit-main/examples/try_except_continue.py` (With a High confidence)
```python
4         a = i
5     except:
6         continue
```

`bandit-main/examples/try_except_continue.py` (With a High confidence)
```python
12         a = 1
13     except Exception:
14         continue
```

### Try Except Pass (B110) (LOW)

Try, Except, Pass detected.

[CWE-703](https://cwe.mitre.org/data/definitions/703.html)

#### Instances

`bandit-main/examples/try_except_pass.py` (With a High confidence)
```python
3     a = 1
4 except:
5     pass
```

`bandit-main/examples/try_except_pass.py` (With a High confidence)
```python
10     a = 1
11 except Exception:
12     pass
```

### Assert Used (B101) (LOW)

Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

[CWE-703](https://cwe.mitre.org/data/definitions/703.html)

#### Instances

`bandit-main/examples/assert.py` (With a High confidence)
```python
1 assert True
```

### Ssl With No Version (B504) (LOW)

ssl.wrap_socket call with no SSL/TLS protocol version specified, the default SSLv23 could be insecure, possible security issue.

[CWE-327](https://cwe.mitre.org/data/definitions/327.html)

#### Instances

`bandit-main/examples/ssl-insecure-version.py` (With a Medium confidence)
```python
22 
23 ssl.wrap_socket()
24 
```

