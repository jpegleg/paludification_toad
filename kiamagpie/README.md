![cdlogo](https://carefuldata.com/images/cdlogo.png)

# kiamagpie

Kiamagpie is a TLS capable file and web server that uses a YAML configuration file.

```
---
kiamagpie:
  name: "TEMPLATE_deploy"
  sni_inspection: True
  host_header_inspection: True
  strict_transport_security: True
  redirect_https: False
  quic: False
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
    - web_content: /srv/persist/TEMPLATE/
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

The config routes different domains to different listeners which it creates, serving the web content at the web_content path configured.

QUIC support is available and adoption of the QUIC protocol is making good progress.

Note that only ECDSA NIST curves, RSA, and ed25519 are the support server identity types. RSA support was added in 0.1.1, 0.1.0 does not have RSA support.

Hybrid PQC with ML-KEM for key exchange is verified and central to the design.

In the 0.1.0 version the route rewrites were not configurable in the YAML and `/` routes to the file `index.html` in the web root of `web_content`. In that version we had to edit the `main.go` and recompile it to configure more routes.
There are some example routes in the 0.1.0 default build for `/art`, `/shows`, `/music`, which each route to art.html and so on. And also `/about`. which routes to index.html as well.

As of 0.1.1 and onward, the route rewrites are configured in the YAML per domain, there are no default route rewrites anymore.

## Why use kiamagpie

If you need a compact and purpose built web server for handling multiple websites, kiamagpie is built for that.

If you need an efficient and secure server for general serving of web content such as HTML, CSS, images, videos, audio, and javascript, kiamagpie is built for that.

If you need a server that provides support for QUIC, HTTP, and HTTPS protocols, kiamagpie is built for that.

If you need a server that enables hybrid post-quantum-cryptography (PQC) for TLS key exchange [see more regarding the spec FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), then kiamagpie is for that.

_Note, the Go crypto library is the source of the cryptographic support for PQC, no cryptography is added in this project._

If you need event correlation across logs and web interactions as correlated JSON events, kiamagpie is built for that.

## Installation

Kiamagpie is available on [github](https://github.com/jpegleg/kiamagpie) and [docker hub](https://hub.docker.com/r/carefuldata/kiamagpi).

The container image is very small and hardened, with only a single statically linked Go binary added to a minimized container "scratch" image.

The v0.1.0 version has port 80 and 443 exposed in the docker image, while the v0.1.1 and newer have 80-9999 for both UDP and TCP exposed in the docker image.

It will need mount points or insertions for the web content, config, and the cert and key pairs. The `domains.yaml` specifies these paths.

Here is an example of pulling the image from docker hub and running via Podman or Docker:

```
podman pull docker.io/carefuldata/kiamagpie:latest
podman run -d -it --network=host -v /opt/local/:/opt/local/ \
                                 -v /srv/persist:/srv/persist \
                                 -v /opt/kiamagpie/domains.yaml:/domains.yaml \
                                 carefuldata/kiamagpie
```

The mount points for all of the files are configurable in the YAML, except for `domains.yaml` which must be in the working dorectory of kiamagpie, so in the container version `/`.

Kiamagpie can listen on any TCP or UDP port. UDP is for QUIC protocol only.

Kiagmagpie can be compiled from source or installed from precompiled release binaries via github.

Kiamagpie works well in Kubernetes, too, just specify the YAML config in the manifest or mount it.

Kiamagpie is a great alternative to Kubernetes at small scale, when there isn't the need to have many services.
It doesn't replace Kubernetes, but it does the things we need for the web at small and medium scale:

- serve web content
- use best available network protocols
- simple and reliable operations

Kiamagpie is easier to use and generally more secure and cloud native than traditional web servers like NGINX or Apache HTTPD.

Kiamagpie goes well with [kiagateway](https://github.com/jpegleg/kiagateway) and [kiaproxy](https://github.com/jpegleg/kiaproxy/).

The three services combined are the kiastack, and together they can handle the domain routing, fail over, and transport security,
as well as the optimization and ease of serving various websites, html, video, javascript, and beyond.

Kiagateway and kiaproxy do not support UDP so they do not support QUIC. Varations of those services are likely to be made to support QUIC.
Until then, either use another gateway/lb to support QUIC or expose kiamagpie externally for the QUIC listeners.

## Project promises

This project will never use AI-slop. All code is reviewed, tested, and implemented by a human expert. This repository and the crates.io repository are carefully managed and protected.

This project will be maintained as best as is reasonable.
