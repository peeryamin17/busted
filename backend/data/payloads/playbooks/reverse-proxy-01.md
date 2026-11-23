<!-- source: Reverse Proxy Misconfigurations/README.md | chunk 1/2 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

# Reverse Proxy Misconfigurations

> A reverse proxy is a server that sits between clients and backend servers, forwarding client requests to the appropriate server while hiding the backend infrastructure and often providing load balancing or caching. Misconfigurations in a reverse proxy, such as improper access controls, lack of input sanitization in proxy_pass directives, or trusting client-provided headers like X-Forwarded-For, can lead to vulnerabilities like unauthorized access, directory traversal, or exposure of internal resources.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [HTTP Headers](#http-headers)
        * [X-Forwarded-For](#x-forwarded-for)
        * [X-Real-IP](#x-real-ip)
        * [True-Client-IP](#true-client-ip)
    * [Nginx](#nginx)
        * [Off By Slash](#off-by-slash)
        * [Missing Root Location](#missing-root-location)
    * [Caddy](#caddy)
        * [Template Injection](#template-injection)
* [Labs](#labs)
* [References](#references)

## Tools

* [yandex/gixy](https://github.com/yandex/gixy) - Nginx configuration static analyzer.
* [MegaManSec/Gixy-Next](https://github.com/MegaManSec/Gixy-Next) - Actively maintained Python3 fork of gixy.
* [shiblisec/Kyubi](https://github.com/shiblisec/Kyubi) - A tool to discover Nginx alias traversal misconfiguration.
* [laluka/bypass-url-parser](https://github.com/laluka/bypass-url-parser) - Tool that tests MANY url bypasses to reach a 40X protected page.

    ```ps1
    bypass-url-parser -u "http://127.0.0.1/juicy_403_endpoint/" -s 8.8.8.8 -d
    bypass-url-parser -u /path/urls -t 30 -T 5 -H "Cookie: me_iz=admin" -H "User-agent: test"
    bypass-url-parser -R /path/request_file --request-tls -m "mid_paths, end_paths"
    ```

## Methodology

### HTTP Headers

Since headers like `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` are just regular HTTP headers, a client can set or override them if it can control part of the traffic path—especially when directly connecting to the application server, or when reverse proxies are not properly filtering or validating these headers.

#### X-Forwarded-For

`X-Forwarded-For` is an HTTP header used to identify the originating IP address of a client connecting to a web server through an HTTP proxy or a load balancer.

When a client makes a request through a proxy or load balancer, that proxy adds an X-Forwarded-For header containing the client’s real IP address.

If there are multiple proxies (a request passes through several), each proxy adds the address from which it received the request to the header, comma-separated.

```ps1
X-Forwarded-For: 2.21.213.225, 104.16.148.244, 184.25.37.3
```

Nginx can override the header with the client's real IP address.

```ps1
proxy_set_header X-Forwarded-For $remote_addr;
```

#### X-Real-IP

`X-Real-IP` is another custom HTTP header, commonly used by Nginx and some other proxies, to forward the original client IP address. Rather than including a chain of IP addresses like X-Forwarded-For, X-Real-IP contains only a single IP: the address of the client connecting to the first proxy.

#### True-Client-IP

`True-Client-IP` is a header developed and standardized by some providers, particularly by Akamai, to pass the original client’s IP address through their infrastructure.

### Nginx

#### Off By Slash

Nginx matches incoming request URIs against the location blocks defined in your configuration.

* `location /app/` matches requests to `/app/`, `/app/foo`, `/app/bar/123`, etc.
* `location /app` (no trailing slash) matches `/app*` (i.e., `/application`, `/appfile`, etc.),

This means in Nginx, the presence or absence of a slash in a location block changes the matching logic.

```ps1
server {
  location /app/ {
    # Handles /app/ and anything below, e.g., /app/foo
  }
  location /app {
    # Handles only /app with nothing after OR routes like /application, /appzzz
  }
}
```

Example of a vulnerable configuration: An attacker requesting `/styles../secret.txt` resolves to `/path/styles/../secret.txt`

```ps1
location /styles {
  alias /path/css/;
}
```

#### Missing Root Location

The `root /etc/nginx;` directive sets the server's root directory for static files.
The configuration doesn't have a root location `/`, it will be set globally set.
A request to `/nginx.conf` would resolve to `/etc/nginx/nginx.conf`.

```ps1
server {
  root /etc/nginx;

  location /hello.txt {
    try_files $uri $uri/ =404;
    proxy_pass http://127.0.0.1:8080/;
  }
}
```

### Caddy

#### Template Injection

The provided Caddy web server config uses the `templates` directive, which allows dynamic content rendering with Go templates.

```ps1
:80 {
