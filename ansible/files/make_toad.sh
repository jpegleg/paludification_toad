#!/bin/sh
tar czvf toad.tgz \
  /root/disk_report.py \
  /root/proc_report.py \
  /root/net_report.py \
  /root/timbsd \
  /etc/rc.d/tim \
  /etc/tim \
  /etc/rc.d/gate \
  /etc/rc.d/*web \
  /etc/rc.d/re3 \
  /etc/pf.conf \
  /etc/ssh/sshd_config \
  /srv \
  /opt/local \
  /opt/kiagateway \
  /opt/*bluejay/ \
  /usr/local/bin/*bluejay \
  /root/*wrap \
  /root/certbot* \
  /root/enforcer.sh \
  /root/make_toad.sh
