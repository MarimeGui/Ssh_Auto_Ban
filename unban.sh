#! /bin/bash

# Run as Root
# Simple script to unban an IP from iptables (for ip6tables, just replace the command)
read -r
iptables -w -D SSHBAN -s $REPLY -j DROP
