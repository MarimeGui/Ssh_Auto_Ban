#! /usr/bin/python3
# -*- coding: utf-8 -*-
"""Ssh_Auto_Banning. The simple way to prevent bruteforce attackers"""
# https://stackoverflow.com/questions/26331116/reading-systemd-journal-from-python-script

from systemd import journal as sysdj
import threading
import signal


# Codes for extract_info
FAILED = 0
ACCEPTED = 1
NON_RELEVANT = 2


def on_signal(signal_number, stack_frame):
    """Runs when a signal is received, shuts down properly"""
    print("{} received, shutting down properly".format(signal.Signals(signal_number).name))
    exit(0)


def extract_info(msg: str) -> list:
    """Extracts useful info out of a log line"""
    msg_splitted = msg.split()
    if msg_splitted[0] == "Failed":
        if msg_splitted[3] == "invalid" and msg_splitted[4] == "user":
            return [FAILED, msg_splitted[7]]
        else:
            return [FAILED, msg_splitted[5]]
    elif msg_splitted[0] == "Accepted":
        return [ACCEPTED, msg_splitted[5]]
    else:
        return [NON_RELEVANT]


class NewLineLogUnlocker(threading.Thread):
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
ext_locker = NewLineLogUnlocker()

# Sets up shutdown related things
shutdown = False
signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)

print("Ssh_Auto_Banning is now active !")

while True:
    second_lock.release()
    main_lock.acquire()
    for entry in journal:
        message = entry['MESSAGE']
        if message != "":
            info = extract_info(message)
            if info[0] == FAILED:
                print("Failed login from {} ! -> {}".format(info[1], message))
            elif info[0] == ACCEPTED:
                print("Accepted login from {} ! -> {}".format(info[1], message))
            else:
                print("Non relevant message -> {}".format(message))
