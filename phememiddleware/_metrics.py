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

"""In-process counters, flushed to statsd and the log by the worker."""

import collections
import json
import os
import time

from phememiddleware import _compat

PUBLISHED = 'published'
BY_ID = 'by_id_delete'
DROPPED = 'dropped'


class Counters(object):
    """Thread-safe counters.

    ``inc`` is called from the request thread (``dropped/buffer_full``) and
    the worker thread. Only the worker thread calls ``flush``, so the statsd
    client is never shared between OS threads.
    """

    def __init__(self, log, statsd=None, stats_file=None):
        """Create empty counters with an optional statsd client.

        ``stats_file`` is a path template; ``{pid}`` is replaced by the
        worker's pid, so each uwsgi worker writes its own file.
        """
        self._log = log
        self._statsd = statsd
        self._stats_file = stats_file
        self._lock = _compat.threading.Lock()
        self._counts = collections.Counter()
        self._flushed = collections.Counter()

    def inc(self, name, reason=None):
        """Increment counter ``name`` (optionally with a reason)."""
        key = name if reason is None else '%s.%s' % (name, reason)
        with self._lock:
            self._counts[key] += 1

    def get(self, name, reason=None):
        """Return the current value of one counter."""
        key = name if reason is None else '%s.%s' % (name, reason)
        with self._lock:
            return self._counts[key]

    def snapshot(self):
        """Return a copy of all counters as a plain dict."""
        with self._lock:
            return dict(self._counts)

    def flush(self):
        """Send deltas since the last flush to statsd and log drops."""
        current = self.snapshot()
        for key, value in sorted(current.items()):
            delta = value - self._flushed[key]
            if delta <= 0:
                continue
            self._flushed[key] = value
            name, _sep, reason = key.partition('.')
            if self._statsd:
                tags = ['reason:%s' % reason] if reason else None
                self._statsd.increment('events_' + name, delta, tags=tags)
            if name == DROPPED:
                self._log.warning("pheme: dropped %(delta)d events "
                                  "(reason=%(reason)s, total=%(total)d)",
                                  {'delta': delta, 'reason': reason,
                                   'total': value})

    def write_file(self):
        """Write all counters as JSON to the stats file, if one is set.

        The file is replaced atomically, so a reader never sees a partial
        write. Only the publisher thread calls this. Errors are logged at
        debug level and never raised: the stats file is a demo aid.
        """
        if not self._stats_file:
            return
        pid = os.getpid()
        path = self._stats_file.replace('{pid}', str(pid))
        tmp = '%s.tmp' % path
        data = {'pid': pid, 'time': time.time(), 'counters': self.snapshot()}
        try:
            with open(tmp, 'w') as f:
                json.dump(data, f, sort_keys=True)
            os.replace(tmp, path)
        except OSError:
            self._log.debug("pheme: writing %s failed", path, exc_info=True)


def create_statsd_client(service_type, log):
    """Create a datadog statsd client like auditmiddleware does."""
    try:
        import datadog
    except ImportError:
        log.warning("Python datadog package not installed. No "
                    "openstack_pheme_* metrics will be produced.")
        return None
    return datadog.dogstatsd.DogStatsd(
        host=os.getenv('STATSD_HOST', 'localhost'),
        port=int(os.getenv('STATSD_PORT', '8125')),
        namespace='openstack_pheme',
        constant_tags=['service:{0}'.format(service_type)])
