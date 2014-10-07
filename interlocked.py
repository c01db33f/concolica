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


class Counter(object):

    def __init__(self):
        self._lock = threading.RLock()
        self._counter = 0

    def __enter__(self, *args, **kwargs):
        self.acquire()

    def __exit__(self, *args, **kwargs):
        self.release()

    def acquire(self, blocking=1):
        self._lock.acquire(blocking)

    def release(self):
        self._lock.release()

    def value(self):
        return self._counter

    def decrement(self):
        with self._lock:
            self._counter -= 1
            return self._counter

    def increment(self):
        with self._lock:
            self._counter += 1
            return self._counter



class List(object):

    def __init__(self, contents=[]):
        self._lock = threading.RLock()
        self._list = list(contents)

    def __enter__(self, *args, **kwargs):
        self.acquire()

    def __exit__(self, *args, **kwargs):
        self.release()

    def __len__(self):
        with self._lock:
            return len(self._list)

    def acquire(self, blocking=1):
        self._lock.acquire(blocking)

    def release(self):
        self._lock.release()

    def append(self, x):
        with self._lock:
            return self._list.append(x)

    def extend(self, l):
        with self._lock:
            return self._list.extend(l)

    def insert(self, i, x):
        with self._lock:
            return self._list.insert(i, x)

    def remove(self, x):
        with self._lock:
            return self._list.remove(x)

    def pop(self, i=0):
        with self._lock:
            return self._list.pop(i)

    def index(self, x):
        with self._lock:
            return self._list.index(x)

    def count(self, x):
        with self._lock:
            return self._list.count(x)

    def sort(self, cmp=None, key=None, reverse=False):
        with self._lock:
            return self._list.sort(cmp, key, reverse)

    def reverse(self):
        with self._lock:
            return self._list.reverse()