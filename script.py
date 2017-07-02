#! /usr/bin/python3
# -*- coding: utf-8 -*-
"""Ssh_Auto_Banning. The simple way to prevent bruteforce attackers"""
# https://stackoverflow.com/questions/26331116/reading-systemd-journal-from-python-script

from systemd import journal as sysdj
# import select
import threading
import signal


def on_signal(signal_number, stack_frame):
    """Runs when a signal is received, shuts down properly"""
    global shutdown, main_lock
    shutdown = True
    main_lock.release()
    print("Proper shutdown")


class NewLineLogUnlocker(threading.Thread):
    """Unlocks the Lock object when a new line is available"""
    def __init__(self, rel_lock: threading.Lock, acq_lock: threading.Lock, jrnl: sysdj.Reader):
        super().__init__()
        self.daemon = True
        self.acq_lock = acq_lock
        self.rel_lock = rel_lock
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
ext_locker = NewLineLogUnlocker(main_lock, second_lock, journal)

# Sets up shutdown related things
shutdown = False
signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)

while True:
    second_lock.release()
    main_lock.acquire()
    if shutdown:
        exit(0)
    for entry in journal:
        if entry['MESSAGE'] != "":
            print(str(entry['MESSAGE']))
