#!/bin/bash

IP=$1

odin build server
ssh root@$IP systemctl stop gam2
#ssh root@$IP rm -rf /root/gam/config
#scp -r config root@$IP:/root/gam
scp server.bin root@$IP:/root/gam
ssh root@$IP systemctl start gam2
