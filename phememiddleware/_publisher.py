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

"""Bounded hand-off queue plus a background NATS JetStream publisher.

The request thread only calls ``submit``, which never blocks: it is a
``put_nowait`` on a bounded queue. A daemon OS thread runs its own asyncio
loop with a nats-py client, builds the CloudEvents and publishes them with a
short timeout. Anything that goes wrong there is dropped and counted.
"""

import asyncio
import os
import time
import urllib.parse

import nats
from nats import errors as nats_errors

from phememiddleware import _compat
from phememiddleware import _metrics

_NATS_ERRORS = (nats_errors.Error, asyncio.TimeoutError, OSError)


def resolve_server(url, sock=_compat.socket):
    """Replace a hostname in a NATS URL with an IP address.

    asyncio resolves names in its default executor. Under eventlet that
    executor may run green threads that never get scheduled in this OS
    thread, so names are resolved here with the unpatched resolver and
    asyncio's IP fast path is used instead.
    """
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    port = parts.port or 4222
    if not host:
        return url
    infos = sock.getaddrinfo(host, port, 0, sock.SOCK_STREAM)
    infos.sort(key=lambda i: i[0] != sock.AF_INET)
    family, _type, _proto, _name, addr = infos[0]
    ip = addr[0]
    if family == sock.AF_INET6:
        ip = '[%s]' % ip
    return '%s://%s:%d' % (parts.scheme or 'nats', ip, port)


class Publisher(object):
    """Own the hand-off queue and the publisher thread."""

    def __init__(self, build, servers, user, password, publish_timeout,
                 queue_size, counters, log, connect_timeout=2.0,
                 reconnect_wait=2.0, poll_interval=0.02,
                 flush_interval=10.0, resolve_after=10.0,
                 stats_interval=1.0):
        """Configure the publisher. The thread starts on first submit."""
        self._build = build
        self._servers = servers
        self._user = user or None
        self._password = password or None
        self._publish_timeout = publish_timeout
        self._queue_size = queue_size
        self._counters = counters
        self._log = log
        self._connect_timeout = connect_timeout
        self._reconnect_wait = reconnect_wait
        self._poll_interval = poll_interval
        self._flush_interval = flush_interval
        self._resolve_after = resolve_after
        self._stats_interval = stats_interval

        self._start_lock = _compat.threading.Lock()
        self._pid = None
        self._queue = None
        self._thread = None
        self._stopping = False
        # only touched on the publisher thread
        self._nc = None
        self._js = None
        self._last_error_log = -60.0

    # -- request thread -------------------------------------------------

    def submit(self, facts):
        """Hand facts to the publisher. Never blocks, never raises Full."""
        q = self._ensure_started()
        try:
            q.put_nowait(facts)
        except _compat.Full:
            self._counters.inc(_metrics.DROPPED, 'buffer_full')
            return False
        return True

    def _ensure_started(self):
        # Fast path. The pid check restarts the thread in a forked worker
        # (uwsgi loads the app in the master and forks unless lazy-apps).
        thread = self._thread
        if (self._pid == os.getpid() and thread is not None and
                thread.is_alive()):
            return self._queue
        with self._start_lock:
            thread = self._thread
            if (self._pid != os.getpid() or thread is None or
                    not thread.is_alive()):
                self._queue = _compat.BoundedBuffer(self._queue_size)
                self._stopping = False
                self._nc = None
                self._js = None
                self._thread = _compat.threading.Thread(
                    target=self._run, name='pheme-publisher', daemon=True)
                self._thread.start()
                self._pid = os.getpid()
            return self._queue

    def stop(self, timeout=5.0):
        """Stop the publisher thread (used by tests)."""
        self._stopping = True
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    @property
    def connected(self):
        """Return True while the NATS client is connected."""
        nc = self._nc
        return nc is not None and nc.is_connected

    # -- publisher thread -----------------------------------------------

    def _run(self):
        loop = asyncio.SelectorEventLoop(_compat.selectors.DefaultSelector())
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._main())
        except Exception:
            self._log.exception("pheme: publisher thread crashed")
        finally:
            loop.close()

    async def _main(self):
        connector = asyncio.ensure_future(self._connect_loop())
        last_flush = last_stats = time.monotonic()
        self._counters.write_file()
        try:
            while not self._stopping:
                now = time.monotonic()
                if now - last_flush >= self._flush_interval:
                    last_flush = now
                    self._counters.flush()
                if now - last_stats >= self._stats_interval:
                    last_stats = now
                    self._counters.write_file()
                try:
                    facts = self._queue.get_nowait()
                except _compat.Empty:
                    await asyncio.sleep(self._poll_interval)
                    continue
                await self._handle(facts)
        finally:
            connector.cancel()
            self._counters.flush()
            self._counters.write_file()
            if self._nc is not None:
                try:
                    await asyncio.wait_for(self._nc.close(), 1.0)
                except _NATS_ERRORS:
                    pass

    async def _handle(self, facts):
        try:
            events = self._build(facts)
        except Exception:
            # the worker must survive anything a request can produce
            self._log.exception("pheme: failed to build event for %s %s",
                                facts.method, facts.path)
            self._counters.inc(_metrics.DROPPED, 'build_failed')
            return
        for ev in events:
            await self._publish(ev)

    async def _publish(self, ev):
        if not self.connected:
            # Give a (re)connect in progress up to publish_timeout. Only this
            # thread waits; requests keep queueing or drop on buffer_full.
            deadline = time.monotonic() + self._publish_timeout
            while (not self.connected and not self._stopping and
                   time.monotonic() < deadline):
                await asyncio.sleep(0.05)
            if not self.connected:
                self._counters.inc(_metrics.DROPPED, 'publish_failed')
                return
        try:
            await self._js.publish(ev.subject, ev.body,
                                   timeout=self._publish_timeout,
                                   headers=ev.headers)
        except _NATS_ERRORS as e:
            self._log.warning("pheme: publish of %(type)s %(path)s failed: "
                              "%(err)r",
                              {'type': ev.ce_type, 'path': ev.path, 'err': e})
            self._counters.inc(_metrics.DROPPED, 'publish_failed')
        else:
            self._counters.inc(_metrics.PUBLISHED)
            self._log.debug("pheme: published %(type)s %(path)s",
                            {'type': ev.ce_type, 'path': ev.path})

    async def _connect_loop(self):
        # Names are resolved to IPs here (see resolve_server), and nats-py
        # retries the same IP forever. If NATS comes back on a new IP (a
        # recreated container), only a fresh resolve finds it, so a connect
        # attempt is bounded and a client that stays disconnected for
        # ``resolve_after`` seconds is closed and rebuilt.
        resolve_after = self._resolve_after
        disconnected_since = None
        while not self._stopping:
            nc = self._nc
            if nc is not None and not nc.is_closed:
                if nc.is_connected:
                    disconnected_since = None
                elif disconnected_since is None:
                    disconnected_since = time.monotonic()
                elif time.monotonic() - disconnected_since > resolve_after:
                    self._log.warning("pheme: NATS unreachable for %ss, "
                                      "resolving %s again",
                                      resolve_after, self._servers)
                    disconnected_since = None
                    try:
                        await asyncio.wait_for(nc.close(), 2.0)
                    except _NATS_ERRORS:
                        pass
                    self._nc = None
                await asyncio.sleep(1.0)
                continue
            try:
                servers = [resolve_server(s) for s in self._servers]
                nc = await asyncio.wait_for(nats.connect(
                    servers,
                    user=self._user,
                    password=self._password,
                    name='pheme-middleware',
                    connect_timeout=self._connect_timeout,
                    allow_reconnect=True,
                    max_reconnect_attempts=-1,
                    reconnect_time_wait=self._reconnect_wait,
                    error_cb=self._on_error,
                    disconnected_cb=self._on_disconnected,
                    reconnected_cb=self._on_reconnected), resolve_after)
            except _NATS_ERRORS as e:
                self._log.warning("pheme: cannot connect to NATS "
                                  "%(servers)s: %(err)r",
                                  {'servers': self._servers, 'err': e})
                await asyncio.sleep(self._reconnect_wait)
                continue
            self._nc = nc
            self._js = nc.jetstream()
            self._log.info("pheme: connected to NATS %s",
                           nc.connected_url.netloc)

    async def _on_error(self, e):
        # nats-py retries forever and reports every failed attempt here;
        # log at most once a minute.
        now = time.monotonic()
        if now - self._last_error_log >= 60.0:
            self._last_error_log = now
            self._log.warning("pheme: NATS error (servers %(servers)s): "
                              "%(err)r", {'servers': self._servers, 'err': e})
        else:
            self._log.debug("pheme: NATS error: %r", e)

    async def _on_disconnected(self):
        self._log.warning("pheme: disconnected from NATS, reconnecting")

    async def _on_reconnected(self):
        self._log.info("pheme: reconnected to NATS")
