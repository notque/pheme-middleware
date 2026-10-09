# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Unpatched stdlib modules, even when eventlet has monkey-patched.

Neutron's API (both the eventlet server and the uwsgi ``neutron-api``
script) calls ``eventlet.monkey_patch()``. A patched ``threading.Thread`` is
a greenthread, which under uwsgi only runs while a request yields to the
hub, so the publisher would starve between requests. The publisher therefore
runs on a real OS thread with its own asyncio loop on a real selector, and
the lock shared with the request thread is a real OS lock (green locks are
not safe across OS threads). The hand-off buffer needs no lock at all, see
``BoundedBuffer``.
"""

import collections
import selectors as _selectors
import socket as _socket
import threading as _threading


def _patched():
    try:
        from eventlet import patcher
    except ImportError:
        return None
    if patcher.is_monkey_patched('thread'):
        return patcher
    return None


_patcher = _patched()

if _patcher is not None:
    threading = _patcher.original('threading')
    socket = _patcher.original('socket')
    # original() only swaps the named module; selectors would still bind
    # the green select module, so import it with the real one injected.
    selectors = _patcher.inject('selectors', None,
                                ('select', _patcher.original('select')))
else:
    threading = _threading
    socket = _socket
    selectors = _selectors


def is_monkey_patched():
    """Return True if eventlet patched threading in this process."""
    return _patcher is not None


class Full(Exception):
    """The buffer is full."""


class Empty(Exception):
    """The buffer is empty."""


class BoundedBuffer(object):
    """A bounded FIFO with non-blocking put and get, and no locks.

    ``deque.append`` and ``deque.popleft`` are atomic in CPython, so this is
    safe between a greenthread and an OS thread whether or not eventlet is
    active. The size check is not atomic with the append; concurrent
    producers can overshoot ``maxsize`` by at most the number of producer
    threads, which is fine for a drop-when-full buffer.
    """

    def __init__(self, maxsize):
        """Create an empty buffer holding at most ``maxsize`` items."""
        self.maxsize = maxsize
        self._items = collections.deque()

    def put_nowait(self, item):
        """Append an item or raise Full."""
        if len(self._items) >= self.maxsize:
            raise Full()
        self._items.append(item)

    def get_nowait(self):
        """Pop the oldest item or raise Empty."""
        try:
            return self._items.popleft()
        except IndexError:
            raise Empty()

    def qsize(self):
        """Return the number of buffered items."""
        return len(self._items)
