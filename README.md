#Ssh_Auto_Banning

A simple Python script that automatically detects Ssh password bruteforce attempts through analysis of sshd logs provided by Systemd's log system.

You can think of it as a stripped-down version of fail2ban.

It requires the python systemd module, it probably is in your package manager

To install:
 - Download the script
 - Add a new chain both in iptables and ip6tables
 - Configure the script by changing the user definable variables (what chain to use)
 - Add a systemd service to make this script run on boot
