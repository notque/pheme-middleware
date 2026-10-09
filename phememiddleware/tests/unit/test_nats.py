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

"""Publish against a real nats-server with JetStream.

The server comes from, in order: ``PHEME_TEST_NATS_URL`` (must accept user
``neutron``/``neutron-local``), a ``nats-server`` binary on PATH, or the
``nats:2.10-alpine`` docker image. The tests skip if none is available.
"""

import asyncio
import json
import os
import shutil
import subprocess  # nosec
import sys
import tempfile
import textwrap
import time

import fixtures
import nats
import testtools
import webob
import webob.dec

import phememiddleware
from phememiddleware import _events
from phememiddleware import _metrics
from phememiddleware import _publisher
from phememiddleware.tests.unit import base

USER = 'neutron'
PASSWORD = 'neutron-local'
STREAM = 'PHEME_TEST'


class NatsServer(fixtures.Fixture):
    """A throwaway JetStream-enabled nats-server."""

    def _setUp(self):
        url = os.environ.get('PHEME_TEST_NATS_URL')
        if url:
            self.url = url
            return
        port = base.free_port()
        args = ['-js', '--user', USER, '--pass', PASSWORD]
        binary = shutil.which('nats-server')
        docker = shutil.which('docker')
        if binary:
            store = self.useFixture(fixtures.TempDir()).path
            proc = subprocess.Popen(  # nosec
                [binary, '-a', '127.0.0.1', '-p', str(port), '-sd', store] +
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.addCleanup(proc.wait)
            self.addCleanup(proc.terminate)
        elif docker:
            try:
                cid = subprocess.check_output(  # nosec
                    [docker, 'run', '-d', '--rm', '-p',
                     '127.0.0.1:%d:4222' % port, 'nats:2.10-alpine'] + args,
                    stderr=subprocess.DEVNULL, timeout=120).decode().strip()
            except (subprocess.CalledProcessError,
                    subprocess.TimeoutExpired, OSError) as e:
                raise testtools.TestCase.skipException(
                    'cannot start nats docker container: %s' % e)
            self.addCleanup(subprocess.call,  # nosec
                            [docker, 'rm', '-f', cid],
                            stdout=subprocess.DEVNULL)
        else:
            raise testtools.TestCase.skipException(
                'no nats-server binary or docker available')
        self.url = 'nats://127.0.0.1:%d' % port
        if not self._wait_ready():
            raise testtools.TestCase.skipException(
                'nats-server did not come up at %s' % self.url)

    def _wait_ready(self, timeout=30.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                asyncio.run(self._ping())
                return True
            except (OSError, nats.errors.Error, asyncio.TimeoutError):
                time.sleep(0.2)
        return False

    async def _ping(self):
        nc = await nats.connect(self.url, user=USER, password=PASSWORD,
                                connect_timeout=1, allow_reconnect=False)
        await nc.close()


async def _with_js(url, fn):
    nc = await nats.connect(url, user=USER, password=PASSWORD,
                            connect_timeout=2, allow_reconnect=False)
    try:
        return await fn(nc.jetstream())
    finally:
        await nc.close()


def _reset_stream(url):
    async def reset(js):
        try:
            await js.delete_stream(STREAM)
        except nats.js.errors.NotFoundError:
            pass
        await js.add_stream(name=STREAM, subjects=['pheme.events.>'])
    asyncio.run(_with_js(url, reset))


def _fetch_all(url):
    async def fetch(js):
        info = await js.stream_info(STREAM)
        msgs = []
        for seq in range(1, info.state.last_seq + 1):
            msg = await js.get_msg(STREAM, seq)
            msgs.append(msg)
        return msgs
    return asyncio.run(_with_js(url, fetch))


def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _environ(method):
    return {'REQUEST_METHOD': method,
            'HTTP_X_PROJECT_ID': base.PROJECT,
            'HTTP_X_PROJECT_DOMAIN_ID': base.DOMAIN,
            'HTTP_X_USER_ID': base.USER,
            'HTTP_X_ROLES': 'member',
            'openstack.request_id': base.REQUEST_ID}


class TestNatsPublish(base.TestCase):
    """End to end: request in, CloudEvent in a JetStream stream."""

    def setUp(self):
        """Start nats-server and create the test stream."""
        super(TestNatsPublish, self).setUp()
        self.server = self.useFixture(NatsServer())
        _reset_stream(self.server.url)

    def make(self, app):
        """Create a middleware publishing to the test server."""
        mw = phememiddleware.PhemeMiddleware(
            app, audit_map_file=base.NEUTRON_AUDIT_MAP,
            nats_url=self.server.url, nats_user=USER, nats_password=PASSWORD,
            publish_timeout='2')
        self.addCleanup(mw.publisher.stop)
        return mw

    def test_router_lifecycle_and_gets(self):
        """POST/DELETE publish events; GETs publish nothing."""
        @webob.dec.wsgify
        def app(req):
            if req.method == 'DELETE':
                return webob.Response(status=204)
            resp = webob.Response(status=201 if req.method == 'POST' else 200)
            resp.content_type = 'application/json'
            resp.body = json.dumps({'router': base.router()}).encode()
            return resp

        mw = self.make(app)
        for method, path in [
                ('GET', '/v2.0/routers'),
                ('POST', '/v2.0/routers'),
                ('GET', '/v2.0/routers/' + base.ROUTER),
                ('HEAD', '/v2.0/routers/' + base.ROUTER),
                ('DELETE', '/v2.0/routers/' + base.ROUTER)]:
            req = webob.Request.blank(path, environ=_environ(method))
            req.get_response(mw)

        self.assertTrue(_wait_for(
            lambda: mw.counters.get(_metrics.PUBLISHED) == 2),
            mw.get_counters())
        msgs = _fetch_all(self.server.url)
        self.assertEqual(2, len(msgs))
        added, deleted = [json.loads(m.data) for m in msgs]
        path = '/domains/%s/projects/%s/network/routers/%s' % (
            base.DOMAIN, base.PROJECT, base.ROUTER)
        self.assertEqual('pheme.events.network.router', msgs[0].subject)
        self.assertEqual('network.router.added', added['type'])
        self.assertEqual(path, added['subject'])
        self.assertEqual(base.router(), added['data'])
        self.assertEqual('network.router.deleted', deleted['type'])
        self.assertEqual(base.router(), deleted['data'])
        self.assertEqual(added['id'], msgs[0].headers['Nats-Msg-Id'])
        self.assertEqual('application/cloudevents+json',
                         msgs[0].headers['Content-Type'])
        self.assertEqual({'published': 2}, mw.get_counters())

    def test_duplicate_msg_id_is_deduplicated(self):
        """Nats-Msg-Id is the CloudEvent id, so JetStream dedupes it."""
        @webob.dec.wsgify
        def app(req):
            resp = webob.Response(status=201)
            resp.content_type = 'application/json'
            resp.body = json.dumps({'bgpvpn': base.bgpvpn()}).encode()
            return resp

        mw = self.make(app)
        events = []
        real_build = mw.publisher._build

        def build_twice(facts):
            evs = real_build(facts)
            events.extend(evs)
            return evs + evs

        mw.publisher._build = build_twice
        req = webob.Request.blank('/v2.0/bgpvpn/bgpvpns',
                                  environ=_environ('POST'))
        req.get_response(mw)
        self.assertTrue(_wait_for(
            lambda: mw.counters.get(_metrics.PUBLISHED) == 2))
        msgs = _fetch_all(self.server.url)
        self.assertEqual(1, len(msgs))
        self.assertEqual('pheme.events.network.bgpvpn', msgs[0].subject)
        self.assertEqual(events[0].msg_id, json.loads(msgs[0].data)['id'])

    def test_resolves_again_after_outage(self):
        """A dead address is dropped and the name resolved again."""
        dead = 'nats://127.0.0.1:%d' % base.free_port()
        answers = [dead]

        def resolve(url):
            # first resolve points at a dead port, later ones at the server
            return answers.pop() if answers else self.server.url

        self.useFixture(fixtures.MockPatchObject(
            _publisher, 'resolve_server', side_effect=resolve))

        def build(facts):
            return [_events.Event(
                'pheme.events.network.router', 'id-1',
                {'Nats-Msg-Id': 'id-1'}, b'{}', 'network.router.added', '/x')]

        pub = _publisher.Publisher(
            build, ['nats://nats.invalid:4222'], USER, PASSWORD, 0.5, 10,
            self.counters, self.log, connect_timeout=0.5,
            reconnect_wait=0.2, resolve_after=1.0)
        self.addCleanup(pub.stop)
        pub.submit(base.make_facts('POST', '/v2.0/routers'))
        self.assertTrue(_wait_for(lambda: pub.connected, timeout=15))
        pub.submit(base.make_facts('POST', '/v2.0/routers'))
        self.assertTrue(_wait_for(
            lambda: self.counters.get(_metrics.PUBLISHED) == 1, timeout=5))
        self.assertEqual(1, len(_fetch_all(self.server.url)))

    def test_publisher_thread_runs_under_eventlet(self):
        """Under eventlet.monkey_patch the publisher is a real OS thread.

        The main thread blocks in an unpatched sleep after the request, as
        a uwsgi worker blocks in C between requests. A greenthread publisher
        would never run; the OS thread publishes anyway.
        """
        script = textwrap.dedent("""
            import eventlet
            eventlet.monkey_patch()
            import json, sys
            import webob, webob.dec
            from eventlet import patcher
            real_time = patcher.original('time')
            import phememiddleware
            from phememiddleware import _compat
            assert _compat.is_monkey_patched()

            @webob.dec.wsgify
            def app(req):
                resp = webob.Response(status=201)
                resp.content_type = 'application/json'
                resp.body = json.dumps({'router': {
                    'id': sys.argv[3], 'project_id': sys.argv[4]}}).encode()
                return resp

            mw = phememiddleware.PhemeMiddleware(
                app, audit_map_file=sys.argv[2], nats_url=sys.argv[1],
                nats_user='neutron', nats_password='neutron-local')
            env = {'REQUEST_METHOD': 'POST', 'HTTP_X_PROJECT_ID': sys.argv[4],
                   'HTTP_X_PROJECT_DOMAIN_ID': sys.argv[5]}
            webob.Request.blank('/v2.0/routers', environ=env).get_response(mw)
            for _ in range(200):
                if mw.get_counters().get('published'):
                    break
                real_time.sleep(0.05)
            print(json.dumps(mw.get_counters()))
            """)
        tmp = self.useFixture(fixtures.TempDir()).path
        path = os.path.join(tmp, 'eventlet_check.py')
        with open(path, 'w') as f:
            f.write(script)
        try:
            import eventlet  # noqa: F401
        except ImportError:
            self.skipTest('eventlet not installed')
        root = os.path.dirname(os.path.dirname(phememiddleware.__file__))
        env = dict(os.environ)
        env['PYTHONPATH'] = os.pathsep.join(
            p for p in (root, env.get('PYTHONPATH')) if p)
        proc = subprocess.run(  # nosec
            [sys.executable, path, self.server.url, base.NEUTRON_AUDIT_MAP,
             base.ROUTER, base.PROJECT, base.DOMAIN],
            timeout=60, cwd=tempfile.gettempdir(), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(0, proc.returncode, proc.stderr.decode()[-3000:])
        counters = json.loads(proc.stdout.decode().strip().splitlines()[-1])
        self.assertEqual({'published': 1}, counters)
        msgs = _fetch_all(self.server.url)
        self.assertEqual(1, len(msgs))
        self.assertEqual('network.router.added',
                         json.loads(msgs[0].data)['type'])
