# Ssh Auto Ban

A simple Python script that automatically detects Ssh password bruteforce attempts through analysis of sshd logs provided by Systemd's log system.

It bans bad IPv4 and IPv6 adresses by adding a simple "drop all incoming connections from this IP" for each new IP to iptables for IPv4 addresses and ip6tables for IPv6 addresses.

You can think of it as a stripped-down version of fail2ban.

It requires the python systemd module, it probably is in your package manager if not already installed.

To install:
 - Download the script
 - Configure the script by making a settings.ini file (example provided)
 - Add a systemd service to make this script run on boot (example provided) in (at least under Arch) /etc/systemd/system/

Make sure that the WorkingDirectory option in the unit file points to a writable folder with the settings.ini file in it.

If you do not give a valid settings.ini file, it will use defaults that do not add new rules for each ban.
