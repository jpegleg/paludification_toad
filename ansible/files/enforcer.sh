#!/bin/sh
pgrep TEMPLATEbluejay || rcctl start TEMPLATEweb

pgrep re3 || rcctl start re3
pgrep kiagateway || rcctl start gate
pgrep timbsd || rcctl start tim
