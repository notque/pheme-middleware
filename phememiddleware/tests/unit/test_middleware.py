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

"""The request-thread side: capture, skip, hand-off and drops."""

import json
import os
import threading
import time
from unittest import mock

import fixtures
import webob
import webob.dec

import phememiddleware
from phememiddleware import _metrics
from phememiddleware import _publisher
from phememiddleware.tests.unit import base


def _app(status=201, body=None):
    @webob.dec.wsgify
    def app(req):
        resp = webob.Response(status=status)
        if body is not None:
            resp.content_type = 'application/json'
            resp.body = json.dumps(body).encode('utf-8')
        return resp
    return app


def _environ(method):
    return {'REQUEST_METHOD': method,
            'HTTP_X_PROJECT_ID': base.PROJECT,
            'HTTP_X_PROJECT_DOMAIN_ID': base.DOMAIN,
            'HTTP_X_USER_ID': base.USER,
            'HTTP_X_ROLES': 'member',
            'openstack.request_id': base.REQUEST_ID}


def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


class TestMiddleware(base.TestCase):
    """PhemeMiddleware on the request thread."""

    def make(self, app=None, **conf):
        """Create a middleware pointed at a closed NATS port."""
        conf.setdefault('audit_map_file', base.NEUTRON_AUDIT_MAP)
        conf.setdefault('nats_url', 'nats://127.0.0.1:%d' % base.free_port())
        mw = phememiddleware.PhemeMiddleware(
            app or _app(body={'router': base.router()}), **conf)
        if mw.publisher is not None:
            self.addCleanup(mw.publisher.stop)
        return mw

    def call(self, mw, method, path='/v2.0/routers'):
        """Send one request through the middleware."""
        req = webob.Request.blank(path, environ=_environ(method))
        return req.get_response(mw)

    def test_reads_are_skipped(self):
        """GET, HEAD and OPTIONS never reach the publisher."""
        mw = self.make()
        with mock.patch.object(mw.publisher, 'submit') as submit:
            for method in ('GET', 'HEAD', 'OPTIONS'):
                self.assertEqual(201, self.call(mw, method).status_int)
        submit.assert_not_called()
        self.assertEqual({}, mw.get_counters())

    def test_mutations_capture_raw_facts(self):
        """A successful POST hands raw facts to the publisher."""
        mw = self.make()
        with mock.patch.object(mw.publisher, 'submit') as submit:
            resp = self.call(mw, 'POST')
        self.assertEqual(201, resp.status_int)
        facts = submit.call_args[0][0]
        self.assertEqual('POST', facts.method)
        self.assertEqual('/v2.0/routers', facts.path)
        self.assertEqual(201, facts.status)
        self.assertEqual(base.PROJECT, facts.token_project_id)
        self.assertEqual(base.DOMAIN, facts.token_domain_id)
        self.assertEqual(base.USER, facts.user_id)
        self.assertEqual(base.REQUEST_ID, facts.request_id)
        self.assertIsInstance(facts.body, bytes)
        self.assertEqual({'router': base.router()}, json.loads(facts.body))

    def test_delete_captures_no_body(self):
        """A 204 DELETE hands over facts without a body."""
        mw = self.make(_app(status=204))
        with mock.patch.object(mw.publisher, 'submit') as submit:
            self.call(mw, 'DELETE', '/v2.0/routers/' + base.ROUTER)
        facts = submit.call_args[0][0]
        self.assertEqual('DELETE', facts.method)
        self.assertIsNone(facts.body)
        self.assertEqual('member', facts.roles)

    def test_failed_requests_are_skipped(self):
        """Non-2xx responses produce no event."""
        for status in (400, 403, 404, 409, 500):
            mw = self.make(_app(status=status))
            with mock.patch.object(mw.publisher, 'submit') as submit:
                self.assertEqual(status, self.call(mw, 'POST').status_int)
            submit.assert_not_called()

    def test_disabled(self):
        """enabled=false passes requests through without a publisher."""
        mw = self.make(enabled='false')
        self.assertIsNone(mw.publisher)
        self.assertEqual(201, self.call(mw, 'POST').status_int)

    def test_capture_errors_never_reach_the_request(self):
        """An unexpected error in the hand-off is counted, not raised."""
        mw = self.make()
        with mock.patch.object(mw.publisher, 'submit',
                               side_effect=RuntimeError('boom')):
            self.assertEqual(201, self.call(mw, 'POST').status_int)
        self.assertEqual(1, mw.counters.get(_metrics.DROPPED,
                                            'capture_failed'))

    def test_app_errors_propagate_unchanged(self):
        """Exceptions from the application are not swallowed."""
        @webob.dec.wsgify
        def app(req):
            raise ValueError('app failure')

        mw = self.make(app)
        self.assertRaises(ValueError, self.call, mw, 'POST')

    def test_env_fallback(self):
        """Options missing in paste config come from PHEME_* env vars."""
        url = 'nats://127.0.0.1:%d' % base.free_port()
        self.useFixture(fixtures.EnvironmentVariable('PHEME_NATS_URL', url))
        self.useFixture(fixtures.EnvironmentVariable('PHEME_REGION', 'eu1'))
        mw = phememiddleware.PhemeMiddleware(
            _app(), audit_map_file=base.NEUTRON_AUDIT_MAP)
        self.assertEqual([url], mw.publisher._servers)
        self.assertEqual('openstack/neutron/eu1', mw.builder.source)

    def test_filter_factory(self):
        """The paste filter factory wraps an app."""
        factory = phememiddleware.filter_factory(
            {}, audit_map_file=base.NEUTRON_AUDIT_MAP, enabled='false')
        mw = factory(_app())
        self.assertIsInstance(mw, phememiddleware.PhemeMiddleware)


class TestNonBlocking(base.TestCase):
    """The request thread never waits for the publisher or the broker."""

    def blocked_publisher(self, queue_size):
        """Return a publisher whose worker is stuck in build()."""
        release = threading.Event()
        started = threading.Event()

        def build(facts):
            started.set()
            release.wait(30)
            return []

        pub = _publisher.Publisher(
            build, ['nats://127.0.0.1:%d' % base.free_port()], None, None,
            0.5, queue_size, self.counters, self.log)
        self.addCleanup(pub.stop)
        self.addCleanup(release.set)
        return pub, started

    def test_put_nowait_drop_path(self):
        """A full queue drops with reason=buffer_full and returns at once."""
        pub, started = self.blocked_publisher(queue_size=1)
        facts = base.make_facts('POST', '/v2.0/routers')
        self.assertTrue(pub.submit(facts))      # taken by the worker
        self.assertTrue(started.wait(5))
        self.assertTrue(pub.submit(facts))      # fills the queue
        self.assertFalse(pub.submit(facts))     # dropped
        self.assertFalse(pub.submit(facts))     # dropped
        self.assertEqual(2, self.counters.get(_metrics.DROPPED,
                                              'buffer_full'))

    def test_call_latency_with_unreachable_broker_and_full_queue(self):
        """__call__ returns without waiting when NATS is down and full."""
        mw = phememiddleware.PhemeMiddleware(
            _app(body={'router': base.router()}),
            audit_map_file=base.NEUTRON_AUDIT_MAP,
            nats_url='nats://127.0.0.1:%d' % base.free_port(),
            queue_size='2', publish_timeout='5')
        self.addCleanup(mw.publisher.stop)
        release = threading.Event()
        self.addCleanup(release.set)
        real_build = mw.publisher._build

        def slow_build(facts):
            release.wait(30)
            return real_build(facts)

        mw.publisher._build = slow_build
        req_env = _environ('POST')
        latencies = []
        for _ in range(200):
            req = webob.Request.blank('/v2.0/routers', environ=dict(req_env))
            t0 = time.perf_counter()
            resp = req.get_response(mw)
            latencies.append(time.perf_counter() - t0)
            self.assertEqual(201, resp.status_int)

        self.assertFalse(mw.publisher.connected)
        # 1 held by the worker, 2 in the queue, the rest dropped.
        self.assertGreaterEqual(
            mw.counters.get(_metrics.DROPPED, 'buffer_full'), 197)
        # Generous bounds for slow CI; a blocking publish would take the
        # 5 s publish_timeout or the 2 s connect timeout per call.
        self.assertLess(max(latencies), 0.25, max(latencies))
        self.assertLess(sum(latencies), 2.0, sum(latencies))

    def test_unreachable_broker_counts_publish_failed(self):
        """With NATS down the worker drops with reason=publish_failed."""
        mw = phememiddleware.PhemeMiddleware(
            _app(body={'router': base.router()}),
            audit_map_file=base.NEUTRON_AUDIT_MAP,
            nats_url='nats://127.0.0.1:%d' % base.free_port(),
            publish_timeout='0.1')
        self.addCleanup(mw.publisher.stop)
        t0 = time.perf_counter()
        for _ in range(5):
            req = webob.Request.blank('/v2.0/routers',
                                      environ=_environ('POST'))
            self.assertEqual(201, req.get_response(mw).status_int)
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertTrue(_wait_for(
            lambda: mw.counters.get(_metrics.DROPPED, 'publish_failed') == 5))
        self.assertEqual(0, mw.counters.get(_metrics.PUBLISHED))

    def test_thread_restarts_after_fork(self):
        """A pid change (forked uwsgi worker) starts a fresh thread."""
        pub, started = self.blocked_publisher(queue_size=10)
        pub.submit(base.make_facts('POST', '/v2.0/routers'))
        first = pub._thread
        pub._pid = -1
        pub.submit(base.make_facts('POST', '/v2.0/routers'))
        self.assertIsNot(first, pub._thread)
        self.assertTrue(pub._thread.is_alive())


class TestCounters(base.TestCase):
    """Counter flush goes to statsd and the log."""

    def test_flush_sends_deltas(self):
        """Only increases since the last flush are sent."""
        statsd = mock.Mock()
        counters = _metrics.Counters(self.log, statsd)
        counters.inc(_metrics.PUBLISHED)
        counters.inc(_metrics.DROPPED, 'buffer_full')
        counters.inc(_metrics.DROPPED, 'buffer_full')
        counters.flush()
        counters.flush()
        statsd.increment.assert_has_calls([
            mock.call('events_dropped', 2, tags=['reason:buffer_full']),
            mock.call('events_published', 1, tags=None)])
        self.assertEqual(2, statsd.increment.call_count)
        self.assertEqual({'published': 1, 'dropped.buffer_full': 2},
                         counters.snapshot())

    def test_write_file_per_pid(self):
        """The stats file holds every counter, one file per pid."""
        tmp = self.useFixture(fixtures.TempDir()).path
        counters = _metrics.Counters(
            self.log, stats_file=os.path.join(tmp, 'neutron-{pid}.json'))
        counters.inc(_metrics.PUBLISHED)
        counters.inc(_metrics.DROPPED, 'publish_failed')
        counters.write_file()
        path = os.path.join(tmp, 'neutron-%d.json' % os.getpid())
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(os.getpid(), data['pid'])
        self.assertEqual({'published': 1, 'dropped.publish_failed': 1},
                         data['counters'])
        self.assertEqual([os.path.basename(path)], os.listdir(tmp))

    def test_write_file_disabled_or_failing(self):
        """No path writes nothing; an unwritable path never raises."""
        _metrics.Counters(self.log).write_file()
        _metrics.Counters(
            self.log, stats_file='/nonexistent/dir/{pid}.json').write_file()
