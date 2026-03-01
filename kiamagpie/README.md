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
  domains_tls:
  - another.local.thing.localdomain:
    - "127.0.0.1:3244"
    - cert: /opt/local/ANOTHER/cert.pem
    - key: /opt/local/ANOTHER/key.pem
    - web_content: /srv/persist/ANOTHER/
  - local.thing.localdomain:
    - "127.0.0.1:3444"
    - cert: /opt/local/ANOTHER/cert.pem
    - key: /opt/local/ANOTHER/key.pem
    - web_content: /srv/persist/ANOTHER/
  - example.com:
    - "127.0.0.1:3443"
    - cert: /opt/local/TEMPLATE/cert.pem
    - key: /opt/local/TEMPLATE/key.pem
    - web_content: /srv/persist/TEMPLATE/
  - www.example.com:
    - "127.0.0.1:3243"
    - cert: /opt/local/TEMPLATE/cert.pem
    - key: /opt/local/TEMPLATE/key.pem
    - web_content: /srv/persist/TEMPLATE/
  domains_http:
  - www.example.com:
    - "127.0.0.1:3203"
    - web_content: /srv/persist/TEMPLATE/
  - example.com:
    - "127.0.0.1:3003"
    - web_content: /srv/persist/TEMPLATE/
  - local.thing.localdomain:
    - "127.0.0.1:3004"
    - web_content: /srv/persist/ANOTHER/
  - another.local.thing.localdomain:
    - "127.0.0.1:3204"
    - web_content: /srv/persist/ANOTHER/

```

The config routes different domains to different listeners which it creates, serving the web content at the web_content path configured.

QUIC is a work in progress, consider it unverified.

Hybrid PQC with ML-KEM for key exchange is verified and central to the design.

By default `/` routes to the file `index.html` in the web root of `web_content`. To code other routes, edit the `main.go` and recompile it.
There are some example routes in the default build for `/art`, `/shows`, `/music`, which each route to art.html and so on. And also `/about`. which routes to index.html as well. 

## Why use kiamagpie

If you need a compact and purpose built web server for handling multiple websites, kiamagpie is built for that.

If you need an efficient and secure server for general serving of web content such as HTML, CSS, images, videos, audio, and javascript, kiamagpie is built for that.

If you need a server that enables hybrid post-quantum-cryptography (PQC) for TLS key exchange [see more regarding the spec FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), then kiamagpie is for that.

The Go crypto library is the source of the cryptographic support for PQC, no cryptography is added in this project.

## Installation

Kiamagpie is available on [github](https://github.com/jpegleg/kiamagpie) and [docker hub](https://hub.docker.com/r/carefuldata/kiamagpie.

The container image is very small and hardened, with only a single statically linked Go binary added to a minimized container "scratch" image.

It will need mount pounts for the web content, config, and the cert and key pairs. The `domains.yaml` specifies these paths.

Here is an example of pulling the image from docker hub and running via Podman or Docker:

```
podman pull docker.io/carefuldata/kiamagpie:latest
podman run -d -it --network=host -v /opt/local/:/opt/local/ \
                                 -v /srv/persist:/srv/persist \
                                 -v /opt/kiamagpie/domains.yaml:/domains.yaml \
                                 carefuldata/kiamagpie
```

Kiamagpie can listen on any TCP or UDP port. UDP is for QUIC protocol only.

Kiagmagpie can be compiled from source or installed from precompiled release binaries via github.

Kiamagpie works well in Kubernetes, too, just specify the YAML config in the manifest or mount it.

Kiamagpie is a great alternative to Kubernetes at small scale, when there isn't the need to have many services.
It doesn't replace Kubernetes, but it does the things we need for the web at small and medium scale:

- serve web content
- use best available network protocols
- simple and reliable operations

Kiamagpie goes well with [kiagateway](https://github.com/jpegleg/kiagateway) and [kiaproxy](https://github.com/jpegleg/kiaproxy/).

The three services combined are the kiastack, and together they can handle the domain routing, fail over, and transport security,
as well as the optimization and ease of serving various websites, html, video, javascript, and beyond.


## Project promises

This project will never use AI-slop. All code is reviewed, tested, and implemented by a human expert. This repository and the crates.io repository are carefully managed and protected.

This project will be maintained as best as is reasonable.
