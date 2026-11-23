<!-- source: Web Cache Deception/README.md | chunk 2/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

| AVI   | DOC  | GZ   | MKV  | PPT  | TIFF  | ZST  |
| AVIF  | DOCX | ICO  | MP3  | PPTX | TTF   | CSS  |
| APK   | DMG  | ISO  | MP4  | PS   | WEBM  | FLAC |
| BIN   | EJS  | JAR  | OGG  | RAR  | WEBP  | MID  |
| BMP   | EOT  | JPG  | OTF  | SVG  | WOFF  | PLS  |
| BZ2   | EPS  | JPEG | PDF  | SVGZ | WOFF2 | TAR  |
| CLASS | EXE  | JS   | PICT | SWF  | XLS   | XLSX |

Exceptions and bypasses:

* If the returned Content-Type is application/octet-stream, the extension does not matter because that is typically a signal to instruct the browser to save the asset instead of to display it.
* Cloudflare allows .jpg to be served as image/webp or .gif as video/webm and other cases that we think are unlikely to be attacks.
* [Bypassing Cache Deception Armor using .avif extension file - fixed](https://hackerone.com/reports/1391635)

## Labs

* [PortSwigger Labs for Web Cache Deception](https://portswigger.net/web-security/all-labs#web-cache-poisoning)

## References

* [Cache Deception Armor - Cloudflare - May 20, 2023](https://web.archive.org/web/20230520042703/https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/)
* [Exploiting cache design flaws - PortSwigger - May 4, 2020](https://web.archive.org/web/20260117063619/https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
* [Exploiting cache implementation flaws - PortSwigger - May 4, 2020](https://web.archive.org/web/20200919065854/https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)
* [How I Test For Web Cache Vulnerabilities + Tips And Tricks - bombon (0xbxmbn) - July 21, 2022](https://web.archive.org/web/20251213233158/https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)
* [OpenAI Account Takeover - Nagli (@naglinagli) - March 24, 2023](https://web.archive.org/web/20230412113849/https://twitter.com/naglinagli/status/1639343866313601024)
* [Practical Web Cache Poisoning - James Kettle (@albinowax) - August 9, 2018](https://web.archive.org/web/20180810041437/https://portswigger.net/blog/practical-web-cache-poisoning)
* [Shockwave Identifies Web Cache Deception and Account Takeover Vulnerability affecting OpenAI's ChatGPT - Nagli (@naglinagli) - July 15, 2024](https://web.archive.org/web/20251010025345/https://www.shockwave.cloud/blog/shockwave-works-with-openai-to-fix-critical-chatgpt-vulnerability)
* [Web Cache Deception Attack - Omer Gil - February 27, 2017](https://web.archive.org/web/20170308135717/https://omergil.blogspot.fr:80/2017/02/web-cache-deception-attack.html)
* [Web Cache Deception Attack leads to user info disclosure - Kunal Pandey (@kunal94) - February 25, 2019](https://web.archive.org/web/20191217174659/https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29)
* [Web Cache Entanglement: Novel Pathways to Poisoning - James Kettle (@albinowax) - August 5, 2020](https://web.archive.org/web/20200805185253/https://portswigger.net/research/web-cache-entanglement)
* [Web cache poisoning - PortSwigger - May 4, 2020](https://web.archive.org/web/20200416160055/https://portswigger.net/web-security/web-cache-poisoning)
