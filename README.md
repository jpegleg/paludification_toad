# paludification_toad 🐸

Paludification toad is a template/recipe for an OpenBSD web server that uses Actix web servers, leveraging Unveil and Pledge for granular application isolation instead of OCI container isolation.
The toad also uses the in-kernel pf firewall and a version of the `kiagateway` service.

The purpose of paludification_toad is to make the smallest, lightest, most secure, self contained, internet exposed web server that still has a complete unix-based operating system administrated with the SSH protocol.

__paludification__ is a geomorphology term for the build up of plant matter and the correct conditions to create peat bogs on previously dry land.

## Current state of the project

The material is being synthesized between [project bobcat](https://github.com/jpegleg/project-bobcat/) and [serotinous cone](https://github.com/jpegleg/serotinous-cone/).

The creation of this project was based on some undesirable results in the latest generation of serotinous cones,
as well as the breakthroughs of [kiagateway](https://github.com/jpegleg/kiagateway).

This project forks both kiagateway and project-bobcat, customizing for a single server build, and with some more up to date software versions.

## The flow of the toad

```
develop app starting from morphobsd template 
terraform
create config files
ansible
part 1 validation of app
DNS cutover to paludification_toad public IP
PKI adoption (certbot, etc)
ansible
part 2 validation of app
live your life for 6+ months
repeat
```
