![cdlogo](https://carefuldata.com/images/cdlogo.png)

# kiamagpie

Kiamagpie is a TLS capable file and web server with built in caching, remote and local content loading,
QUIC protocol support, and hot reloading of certs and keys.

There is a single YAML configuration file, `domains.yaml`, for each instance of kiamagpie.

Kiamagpie can use global listeners or domain specific listeners.
Global listener support was added in version 0.1.3.
The global listeners are especially useful for when there is only one web root
and many/multiple possible domains.

```
---
kiamagpie:
  name: "TEMPLATE_deploy"
  strict_transport_security: True
  ram_limit_percent: 50
  quic: True
  tls: True
  http: True
  cache_age_seconds: 60
  domains_quic:
  - "*":
    - "0.0.0.0:443"
    - cert: /opt/local/TEMPLATE/cert.pem
    - key: /opt/local/TEMPLATE/key.pem
    - web_content: /srv/persist/TEMPLATE/
      rewrites:
        "/": "/index.html"
        "/about": "/about.html"
  domains_tls:
  - "*":
    - "0.0.0.0:443"
    - cert: /opt/local/TEMPLATE/cert.pem
    - key: /opt/local/TEMPLATE/key.pem
    - web_content: /srv/persist/TEMPLATE/
      rewrites:
        "/": "/index.html"
        "/about": "/about.html"
  domains_http:
  - "*":
    - "0.0.0.0:80"
    - web_content: /srv/persist/TEMPLATE/
      rewrites:
        "/": "/index.html"
        "/about": "/about.html"
```

Alternatively to global listeners marked with "*" for the dommain, there can be domain specific listeners.
This example config demonstrates using domain specific listeners and default web content if no domain is matched
for traffic on a given listener.

```
---
kiamagpie:
  name: "TEMPLATE_deploy"
  strict_transport_security: True
  default_web_content: /srv/persist/WHATEVER/
  ram_limit_percent: 50
  quic: True
  tls: True
  http: True
  cache_age_seconds: 60
  domains_quic:
  - example.com:
    - "127.0.0.1:3443"
    - cert: /opt/local/TEMPLATE/cert.pem
    - key: /opt/local/TEMPLATE/key.pem
    - web_content: /srv/persist/TEMPLATE/
      rewrites:
        "/": "/index.html"
  - www.example.com:
    - "127.0.0.1:3243"
    - cert: /opt/local/TEMPLATE/cert.pem
    - key: /opt/local/TEMPLATE/key.pem
    - web_content: https://example.com/example/bucket/
      rewrites:
        "/": "/index.html"
  domains_tls:
  - another.local.thing.localdomain:
    - "127.0.0.1:3244"
    - cert: /opt/local/ANOTHER/cert.pem
    - key: /opt/local/ANOTHER/key.pem
    - web_content: /srv/persist/ANOTHER/
      rewrites:
        "/": "/index.html"
        "/example"; "/api/foo"
  - local.thing.localdomain:
    - "127.0.0.1:3444"
    - cert: /opt/local/ANOTHER/cert.pem
    - key: /opt/local/ANOTHER/key.pem
    - web_content: /srv/persist/ANOTHER/
      rewrites:
        "/": "/index.html"
  - example.com:
    - "127.0.0.1:3443"
    - cert: /opt/local/TEMPLATE/cert.pem
    - key: /opt/local/TEMPLATE/key.pem
    - web_content: /srv/persist/TEMPLATE/
      rewrites:
        "/": "/index.html"
  - www.example.com:
    - "127.0.0.1:3243"
    - cert: /opt/local/TEMPLATE/cert.pem
    - key: /opt/local/TEMPLATE/key.pem
    - web_content: /srv/persist/TEMPLATE/
      rewrites:
        "/": "/index.html"
  domains_http:
  - www.example.com:
    - "127.0.0.1:3203"
    - web_content: /srv/persist/TEMPLATE/
      rewrites:
        "/": "/index.html"
  - example.com:
    - "127.0.0.1:3003"
    - web_content: /srv/persist/TEMPLATE/
      rewrites:
        "/": "/index.html"
  - local.thing.localdomain:
    - "127.0.0.1:3004"
    - web_content: /srv/persist/ANOTHER/
      rewrites:
        "/": "/index.html"
  - another.local.thing.localdomain:
    - "127.0.0.1:3204"
    - web_content: /srv/persist/ANOTHER/
      rewrites:
        "/": "/index.html"

```

That last example config routes different domains to different listeners which kiamagie creates, serving the web content at the web_content path configured.
Note how `https://example.com/example/bucket` is used in that example in one place instead of a filesystem path. Remote content over HTTPS can be used
instead of local files, so content can be loaded from S3 buckets or other websites and cached in kiamagpie.

#### Changelog and version notes

QUIC support is available and adoption of the QUIC protocol is making good progress.

Note that only ECDSA NIST curves, RSA, and ed25519 are the support server identity types. RSA support was added in 0.1.1, 0.1.0 does not have RSA support.

Hybrid PQC with ML-KEM for key exchange is verified and central to the design.

In the 0.1.0 version the route rewrites were not configurable in the YAML and `/` routes to the file `index.html` in the web root of `web_content`. In that version we had to edit the `main.go` and recompile it to configure more routes.
There are some example routes in the 0.1.0 default build for `/art`, `/shows`, `/music`, which each route to art.html and so on. And also `/about`. which routes to index.html as well.

As of 0.1.1 and onward, the route rewrites are configured in the YAML per domain, there are no default route rewrites anymore.

As of 0.1.2 and onward, security headers for all TLS are in place. Further HSTS with a value of "max-age=63072000; includeSubDomains; preload" is available boolean with the `strict_transport_security` config option.

As of 0.1.2 and onward, web content can be loaded from HTTPS network sources instead of from the filesystem. This way the web content of a given domain can be from an S3 bucket or whatnot, and it is stored locally in RAM as much as possible with the cache. To use this feature start the path of web_content with "https", see the example config at the top of this document.

As of 0.1.2 and onward, we can limit the RAM use of the files cache in the config option `ram_limit_percent` as a float. If we set 50, then we use up to 50% of available RAM for the file cache.

As of 0.1.3 and onward, we have "hot reloading" of certificate and key files.

As of 0.1.3 and onward, we have global listeners `"*"` and `default_web_content` features. Note that those features are exclusive - either or neither but not both can be used in the same config, otherwise they would conflict.

Version 0.1.4 is an important fix for 0.1.3 release. The fix is for an HTTP 502 being sent in some valid traffic conditions.

#### Changelog continued - the start of the toad 🐸

As of version 0.1.500, paludification_toad/kiamagpie has diverged from the main [kiamagpie project](https://github.com/jpegleg/kiamagpie/) with the adoption of [Pledge](https://man.openbsd.org/pledge.2).

We can expect more features to come in to this fork than to the main project in the future, expanded to the use case of a small self sufficient OpenBSD server vs the main kiamagpie project is more cloud oriented. Sort of de-cloudifying the magpie a little to make it larger and have more OpenBSD specific security features and other business features. The main project might adopt some of these additions, but more likely this project will be pulling from the main project and rebasing/adjusting regularly for the near future.

