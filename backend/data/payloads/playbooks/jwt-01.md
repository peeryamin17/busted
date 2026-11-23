<!-- source: JSON Web Token/README.md | chunk 1/5 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

# JWT - JSON Web Token

> JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.

## Summary

- [Tools](#tools)
- [JWT Format](#jwt-format)
    - [Header](#header)
    - [Payload](#payload)
- [JWT Signature](#jwt-signature)
    - [JWT Signature - Null Signature Attack (CVE-2020-28042)](#jwt-signature---null-signature-attack-cve-2020-28042)
    - [JWT Signature - Disclosure of a correct signature (CVE-2019-7644)](#jwt-signature---disclosure-of-a-correct-signature-cve-2019-7644)
    - [JWT Signature - None Algorithm (CVE-2015-9235)](#jwt-signature---none-algorithm-cve-2015-9235)
    - [JWT Signature - Key Confusion Attack RS256 to HS256 (CVE-2016-5431)](#jwt-signature---key-confusion-attack-rs256-to-hs256-cve-2016-5431)
    - [JWT Signature - Key Injection Attack (CVE-2018-0114)](#jwt-signature---key-injection-attack-cve-2018-0114)
    - [JWT Signature - Recover Public Key From Signed JWTs](#jwt-signature---recover-public-key-from-signed-jwts)
- [JWT Secret](#jwt-secret)
    - [Encode and Decode JWT with the secret](#encode-and-decode-jwt-with-the-secret)
    - [Break JWT secret](#break-jwt-secret)
- [JWT Claims](#jwt-claims)
    - [JWT kid Claim Misuse](#jwt-kid-claim-misuse)
    - [JWKS - jku header injection](#jwks---jku-header-injection)
- [Labs](#labs)
- [References](#references)

## Tools

- [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) -  🐍 A toolkit for testing, tweaking and cracking JSON Web Tokens
- [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) - JWT brute force cracker written in C
- [PortSwigger/JOSEPH](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61) - JavaScript Object Signing and Encryption Pentesting Helper
- [jwt.io](https://jwt.io/) - Encoder/Decoder

## JWT Format

JSON Web Token : `Base64(Header).Base64(Data).Base64(Signature)`

Example : `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY`

Where we can split it into 3 components separated by a dot.

```powershell
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        # header
eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ        # payload
UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # signature
```

### Header

Registered header parameter names defined in [JSON Web Signature (JWS) RFC](https://www.rfc-editor.org/rfc/rfc7515).
The most basic JWT header is the following JSON.

```json
{
    "typ": "JWT",
    "alg": "HS256"
}
```

Other parameters are registered in the RFC.

| Parameter | Definition                           | Description                                                                                     |
| --------- | ------------------------------------ | ----------------------------------------------------------------------------------------------- |
| alg       | Algorithm                            | Identifies the cryptographic algorithm used to secure the JWS                                   |
| jku       | JWK Set URL                          | Refers to a resource for a set of JSON-encoded public keys                                      |
| jwk       | JSON Web Key                         | The public key used to digitally sign the JWS                                                   |
| kid       | Key ID                               | The key used to secure the JWS                                                                  |
| x5u       | X.509 URL                            | URL for the X.509 public key certificate or certificate chain                                   |
| x5c       | X.509 Certificate Chain              | X.509 public key certificate or certificate chain in PEM-encoded used to digitally sign the JWS |
| x5t       | X.509 Certificate SHA-1 Thumbprint)  | Base64 url-encoded SHA-1 thumbprint (digest) of the DER encoding of the X.509 certificate       |
| x5t#S256  | X.509 Certificate SHA-256 Thumbprint | Base64 url-encoded SHA-256 thumbprint (digest) of the DER encoding of the X.509 certificate     |
| typ       | Type                                 | Media Type. Usually `JWT`                                                                       |
| cty       | Content Type                         | This header parameter is not recommended to use                                                 |
| crit      | Critical                             | Extensions and/or JWA are being used                                                            |

Default algorithm is "HS256" (HMAC SHA256 symmetric encryption).
"RS256" is used for asymmetric purposes (RSA asymmetric encryption and private key signature).

| `alg` Param Value | Digital Signature or MAC Algorithm             | Requirements |
| ----------------- | ---------------------------------------------- | ------------ |
| HS256             | HMAC using SHA-256                             | Required     |
| HS384             | HMAC using SHA-384                             | Optional     |
| HS512             | HMAC using SHA-512                             | Optional     |
| RS256             | RSASSA-PKCS1-v1_5 using SHA-256                | Recommended  |
| RS384             | RSASSA-PKCS1-v1_5 using SHA-384                | Optional     |
| RS512             | RSASSA-PKCS1-v1_5 using SHA-512                | Optional     |
| ES256             | ECDSA using P-256 and SHA-256                  | Recommended  |
| ES384             | ECDSA using P-384 and SHA-384                  | Optional     |
| ES512             | ECDSA using P-521 and SHA-512                  | Optional     |
| PS256             | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 | Optional     |
| PS384             | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 | Optional     |
| PS512             | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 | Optional     |
| none              | No digital signature or MAC performed          | Required     |

Inject headers with [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool): `python3 jwt_tool.py JWT_HERE -I -hc header1 -hv testval1 -hc header2 -hv testval2`

### Payload

```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```

Claims are the predefined keys and their values:

- iss: issuer of the token
- exp: the expiration timestamp (reject tokens which have expired). Note: as defined in the spec, this must be in seconds.
- iat: The time the JWT was issued. Can be used to determine the age of the JWT
- nbf: "not before" is a future time when the token will become active.
- jti: unique identifier for the JWT. Used to prevent the JWT from being re-used or replayed.
- sub: subject of the token (rarely used)
- aud: audience of the token (also rarely used)

Inject payload claims with [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool): `python3 jwt_tool.py JWT_HERE -I -pc payload1 -pv testval3`

## JWT Signature
