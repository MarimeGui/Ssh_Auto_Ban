#! /usr/bin/python3
# -*- coding: utf-8 -*-
"""Ssh_Auto_Banning. The simple way to prevent bruteforce attackers.
By default, this script will ban every ip that fails to login 6 times.
Although, if an ip logs in properly, we add it to the whitelist.
Bans with the help of iptables"""

from systemd import journal as sysdj
import threading
import signal
import pickle
import subprocess
import os
import requests
import ipaddress

# User definable variables
user_whitelist = []  # Add IP addresses you do not want to ban here
use_auto_whitelist = True  # Enables the auto whitelist, adds IPs that connected successfully to the whitelist
retry_count = 6  # How many times an IP can try to guess the password
more_messages = False  # Prints extra info
active = True  # Actually adds the entries to iptables
report = False  # If active, report to badips.com
use_direct_journal = True  # Writes logs directly to the systemd journal, disable when testing
chain_name = "SSHBAN"  # Name of the iptables chain you want to use, needs to exist
auto_whitelist_path = "auto_whitelist.data"
rising_threats_path = "rising_threats.data"
bans_file_path = "bans.data"


# Codes for extract_info
FAILED = 0
ACCEPTED = 1
NON_RELEVANT = 2


def on_signal(signal_number, stack_frame):
    """Runs when a signal is received, shuts down properly"""
    my_print("{} received, shutting down properly".format(signal.Signals(signal_number).name))
    if active:
        shutdown_commands = [["iptables", "-D", "INPUT", "-j", chain_name],
                             ["iptables", "-F", chain_name],
                             ["iptables", "-X", chain_name],
                             ["ip6tables", "-D", "INPUT", "-j", chain_name],
                             ["ip6tables", "-F", chain_name],
                             ["ip6tables", "-X", chain_name]]
        for shutdown_command in shutdown_commands:
            subprocess.call(shutdown_command, stdout=open(os.devnull, 'wb'))
    exit(0)


def my_print(msg: str):
    """Prints to the console or to the journal, depending on the configuration"""
    if use_direct_journal:
        sysdj.send(msg)
    else:
        print(msg)


def print_extra(msg: str):
    """Prints only if necessary"""
    if more_messages:
        my_print(msg)


def process_line(msg: str):
    """Process an incoming log entry"""
    # Extract the info
    info = extract_info(msg)
    # If the login failed
    if info[0] == FAILED:
        print_extra("Failed login from {} ! → {}".format(info[1], msg))
        manage_failed(info[1])
    # If the login passed
    elif info[0] == ACCEPTED:
        print_extra("Accepted login from {} ! → {}".format(info[1], msg))
        manage_accepted(info[1])
    # If it is non relevant
    else:
        print_extra("Non relevant message → {}".format(msg))


def extract_info(msg: str) -> list:
    """Extracts useful info out of a log line"""
    msg_words = msg.split()
    if msg_words[0] == "Failed":
        if msg_words[3] == "invalid" and msg_words[4] == "user":
            # Failed on invalid user
            return [FAILED, msg_words[7].split("%")[0]]  # Split at % for IPv6 addresses
        else:
            # Failed on existing user
            return [FAILED, msg_words[5].split("%")[0]]
    elif msg_words[0] == "Accepted":
        # Accepted login
        return [ACCEPTED, msg_words[5].split("%")[0]]
    else:
        # Everything else
        return [NON_RELEVANT]


def complete_whitelist() -> list:
    """Returns the combination of the auto whitelist and the user whitelist"""
    return user_whitelist + auto_whitelist


def manage_failed(ip: str):
    """What to do when some ip fails to login"""
    if ip not in complete_whitelist():
        if ip not in bans:  # Sometimes take a little bit of time for iptables to update
            try:
                rising_threats[ip] += 1
            except KeyError:
                rising_threats[ip] = 1
            my_print("{} → {} fails".format(ip, rising_threats[ip]))
            if rising_threats[ip] >= retry_count:
                my_print("{} → BAN !".format(ip))
                del(rising_threats[ip])
                bans.append(ip)
                pickle.dump(bans, open(bans_file_path, 'wb'))
                ban(ip)
            pickle.dump(rising_threats, open(rising_threats_path, 'wb'))
        else:
            print_extra("{} → Fail but already banned".format(ip))
    else:
        my_print("{} → Fail but Whitelisted".format(ip))


def ban(ip: str):
    """Bans an IP address"""
    address_type = ipaddress.ip_address(ip).version
    if address_type == 4:
        command = ["iptables", "-w", "-I", chain_name, "1", "-s", ip, "-j", "DROP"]
    else:
        command = ["ip6tables", "-w", "-I", chain_name, "1", "-s", ip, "-j", "DROP"]
    if active:
        if address_type == 4:
            subprocess.call(command, stdout=open(os.devnull, 'wb'))
            if report:
                requests.get("https://www.badips.com/add/ssh/{}".format(ip))
        elif address_type == 6:
            subprocess.call(command, stdout=open(os.devnull, 'wb'))
    else:
        text = ""
        for part in command:
            text += part + " "
        print_extra("Command to run: {}".format(text))


def manage_accepted(ip: str):
    """What to do when some ip logs in"""
    if (ip not in complete_whitelist()) and use_auto_whitelist:
        auto_whitelist.append(ip)
        try:
            del(rising_threats[ip])
        except KeyError:
            pass
        my_print("{} → Add to Auto whitelist".format(ip))
        pickle.dump(auto_whitelist, open(auto_whitelist_path, 'wb'))


class NewEntryJournalExtLock(threading.Thread):
    """Unlocks the Lock object when a new line is available"""

    def __init__(self):
        super().__init__()
        self.daemon = True
        self.rel_lock = main_lock
        self.acq_lock = second_lock
        self.journal = journal
        self.start()

    def run(self):
        """Runs the things"""
        while True:
            self.acq_lock.acquire()
            self.journal.wait()
            self.rel_lock.release()


if __name__ == '__main__':
    my_print("Initializing...")

    # Make the journal object for reading the logs
    journal = sysdj.Reader()
    journal.log_level(sysdj.LOG_INFO)
    journal.add_match(_SYSTEMD_UNIT="sshd.service")
    journal.seek_tail()
    journal.get_previous()

    # Sets up the external locking system
    main_lock = threading.Lock()
    main_lock.acquire()
    second_lock = threading.Lock()
    second_lock.acquire()
    ext_locker = NewEntryJournalExtLock()

    # Sets up shutdown related things
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    # Loads the auto_whitelist file
    try:
        auto_whitelist = pickle.load(open(auto_whitelist_path, 'rb'))
    except FileNotFoundError:
        auto_whitelist = []

    # Loads the rising threats file
    try:
        rising_threats = pickle.load(open(rising_threats_path, 'rb'))
    except FileNotFoundError:
        rising_threats = {}

    # Loads the bans file
    try:
        bans = pickle.load(open(bans_file_path, 'rb'))
    except FileNotFoundError:
        bans = []

    # Add iptables chains
    if active:
        startup_commands = [["iptables", "-w", "-N", chain_name],
                            ["iptables", "-w", "-A", chain_name, "-j", "RETURN"],
                            ["iptables", "-w", "-A", "INPUT", "-j", chain_name],
                            ["ip6tables", "-w", "-N", chain_name],
                            ["ip6tables", "-w", "-A", chain_name, "-j", "RETURN"],
                            ["ip6tables", "-w", "-A", "INPUT", "-j", chain_name]]
        for startup_command in startup_commands:
            subprocess.call(startup_command, stdout=open(os.devnull, 'wb'))

    # Adds all the previous bans back in the table
    for startup_ip in bans:
        ban(startup_ip)
    my_print("Loaded {} banned IPs".format(len(bans)))

    if active:
        my_print("Banning is active")
        if report:
            my_print("Reporting to badips.com")
    else:
        my_print("Banning is NOT active")

    my_print("Ssh_Auto_Banning starts !")
    while True:
        second_lock.release()
        main_lock.acquire()
        for entry in journal:
            if entry['MESSAGE'] != "":
                process_line(entry['MESSAGE'])
