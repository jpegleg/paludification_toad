# paludification_toad 🐸

Paludification toad is a template/recipe for an OpenBSD web server that uses Go `kiamagpie` or Actix web servers such as the included `kiabluejaybsd` (morphobsd), Actix leveraging Unveil and Pledge for granular application isolation instead of OCI container isolation. The Actix template also has cookies, kiamagpie does not.

While the concept is that all of this software and configuration is a single host, it can also be split out and distributed easily and effectively. We might scale out horizontally by having 2 kiagatewaybsd2 + kiaproxybsd + redirectrixbsd servers that route traffic to 2 morphobsd servers, for example. There are some anisble playbook references for some of these designs being worked on. But generally when we refer to "a toad" we are referring to one of these OpenBSD servers with the OpenBSD kiastack and some additional support tools and designs.

The toad also uses the in-kernel pf firewall and a version of the `kiagateway` service.

The purpose of paludification_toad is to make the smallest, lightest, most secure, self contained, durable web server that still has a complete unix-based operating system administrated with the SSH protocol.

__paludification__ is a geomorphology term for the build up of plant matter and the correct conditions to create peat bogs on previously dry land.

## Current state of the project

The material is being synthesized between [project bobcat](https://github.com/jpegleg/project-bobcat/), [kiabluejay](github.com/jpegleg/kiabluejay/), and [serotinous cone](https://github.com/jpegleg/serotinous-cone/).

The creation of this project was based on some undesirable results in the latest generation of serotinous cones,
as well as the breakthroughs of [kiagateway](https://github.com/jpegleg/kiagateway).

This project forks both kiagateway and project-bobcat, customizing for a single server build, and with some more up to date software versions.

The use of [Actix](https://github.com/jpegleg/paludification_toad/tree/main/morphobsd) has become primary default web server while [kiamagpie](https://github.com/jpegleg/kiamagpie/) remains in use for QUIC support, multi-domain support, and remote content caching. The latest style uses `kiabluejaybsd` for each domain instead of relying on kiamagpie for multiple domains, and leverages LibreSSL cryptography instead of Go crypto like `kiamagpie`. The `kiamagpie` app has adopted QUIC capbilities as well, which is the latest and greatest protocol for web HTTP3. The use of QUIC is not supported from kiagateway or kiaproxy, so any use of QUIC must be exposed directly or with a different gateway that supports UDP.

Many of the examples and templates focus on kiamagpie, because it is more simple than kiabluejaybsd setups, but they are fundamentally the same - kiabluejaybsd just requires a service for each domain (another daemon, and so it can be properly isolated).

The Actix template is useful and is better performing than kiamagpie, and even lighter on RAM. It has insecure cookies available (session trackers) that can be utilized, removed, or enhanced to be secure cookies etc. Currently the `kiabluejaybsd` requires multiple copies to be run to manage multiple domains compared to `kiamagpie`. We can allocation kiabluejaybsd instances to different ports and use `kiagateway` to balance between them.

The entire OpenBSD system and all it's apps including kiagateway and kiamagpie running uses 17MB of RAM passive and 50MB of RAM under moderate load. This is incredibly low compared to most modern systems, which gives us all that much more RAM to do other things, scale, and keep costs down by needing less RAM. Kiamagpie has a cache built in, so the RAM usage is partially configurable and can use a lot of RAM to cache video files and such.

## The flow of the toad

```
develop app, use template is you like
terraform
create config files
ansible
part 1 validation of app
DNS cutover to paludification_toad public IP
PKI adoption (certbot, etc)
part 2 validation of app
live your life for 6+ months
repeat
```

## Event reporting

```
python3 event_report.py /var/log/magpie.log > magpie_report_$(date +%Y%m%d%H%M%S).json
```

This provides a snapshot of statistics from the web data event JSON lines.

Each report is a count of all keys and the counts of them in the JSON. This sample script reads the entire provided log file. It can be run on the live log to summarize current runtime for the kiamagpie instance.

```
{
    "file_path": "/var/log/magpie.log",
    "generated_at_utc": "2026-03-05T03:16:51.018664+00:00",
    "total_lines_read": 142,
    "total_valid_json_objects": 142,
    "key_counts": {
        "event": 132,
        "interaction_id": 142,
        "ram_avail_bytes": 1,
        "ram_limit_bytes": 1,
        "ram_percent": 1,
        "timestamp": 142,
        "version": 1,
        "file_count": 12,
        "host": 38,
        "web_root": 12,
        "file": 48,
        "op": 48,
        "cert": 48,
        "listen_addr": 8,
        "local": 23,
        "protocol": 23,
        "remote": 23,
        "http_proto": 10,
        "listen_host": 10,
        "method": 10,
        "path": 10,
        "sni": 17,
        "src_ip": 10,
        "status": 10,
        "transport": 10,
        "wait_duration_ms": 10
    },
    "value_counts_by_key": {
        "event": {
            "server_start": 1,
            "disk_site_loaded": 12,
...(and so on, truncating here)...
```

The example is truncated because the output can be larger than I want to put in this README.

This report JSON is automatically generated based on your web events, and useful for analyzing large amounts of web events faster.

I really like the summary of the wait duration on web/file requests:

```
        "wait_duration_ms": {
            "6": 1,
            "0": 8,
            "1": 1
        }
```

So we can learn that we had a wait of 6 miliseconds one time, a wait of 0 miliseconds (less than 1) 8 times, and 1 milisecond 1 time.

From there we can identify the 6 milisecond wait time, and evaluate the interaction. Commonly larger image files or larger media files will have longer wait times.

We also get HTTP status stats:

```
        "status": {
            "200": 10
        },
```
