# -*- coding: utf-8 -*-

#    Copyright 2014 Mark Brand - c01db33f (at) gmail.com
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


import threading

import argparse
import functools
import os
import random
import shlex
import struct
import subprocess
import time

from termcolor import colored

from concolica import emulator
from concolica import interlocked
from concolica import serialisation
from concolica import state
from concolica.vulnerabilities import *


max_threads = 24
active_threads = threading.BoundedSemaphore(max_threads)
available_states = threading.Semaphore(0)
exit_event = threading.Event()


def run_single_threaded(initial_states, x86_64):

    states = list(initial_states)

    while len(states) > 0:
        try:
            s = states.pop(random.randint(0, len(states) - 1))
            ns = emulator.single_step(s, x86_64)
            for n in ns:
                states.append(n)
        except StateException, v:
            print v


def run_threaded(initial_states, x86_64, scoring_function=None):
    global active_threads
    global available_states

    states = interlocked.List(initial_states)

    for s in initial_states:
        available_states.release()

    def run(states):
        while not exit_event.is_set():
            active_threads.acquire()

            while available_states.acquire(blocking=False):
                try:
                    s = states.pop()
                    ns = emulator.single_step(s, x86_64)
                    for n in ns:
                        if scoring_function is not None:
                            n.score = scoring_function(n)
                            states.append(n)
                            states.sort(key=lambda x:x.score)
                        else:
                            states.append(n)

                        available_states.release()
                except StateException, v:
                    print colored(v, 'white', 'on_red', attrs=['bold'])
                    print 'saving vuln state {}'.format(v.state.id)
                    serialisation.save('vuln_state_{}'.format(v.state.id), v)

            active_threads.release()
            time.sleep(1.0)


    workers = []
    for i in range(0, max_threads):
        t = threading.Thread(target=run, args=(states,))
        t.start()
        workers.append(t)

    all_idle_count = 0
    try:
        while not exit_event.is_set():
            time.sleep(1)
            idle_count = active_threads._Semaphore__value
            print 'idle threads: {}'.format(idle_count)
            if idle_count == max_threads:
                all_idle_count += 1
                if all_idle_count == 3:
                    exit_event.set()
            else:
                all_idle_count = 0
    except KeyboardInterrupt:
        exit_event.set()

    for t in workers:
        t.join()
