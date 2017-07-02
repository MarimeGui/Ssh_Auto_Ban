#! /bin/bash

# Run as root, of course

iptables -w -N SSHBAN  # Create the new chain
iptables -w -A SSHBAN -j RETURN  # Add the return instruction
iptables -w -A INPUT -j SSHBAN  # Add the chain to the INPUT chain

# Do the same for ip6tables
ip6tables -w -N SSHBAN
ip6tables -w -A SSHBAN -j RETURN
ip6tables -w -A INPUT -j SSHBAN

echo "Do not forget to change the name in the script if you do not use the default name !"
