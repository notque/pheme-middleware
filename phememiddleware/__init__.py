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

"""Publish Pheme CloudEvents for mutating OpenStack API calls.

Place the ``pheme`` filter after ``keystonecontext`` (or ``authtoken``) in
the paste pipeline. On the request thread it only records raw facts about
successful POST/PUT/PATCH/DELETE requests and hands them to a bounded queue
with ``put_nowait``. Resolving the target with the audit map, building the
CloudEvent and publishing to NATS JetStream all happen on a background
thread. If the queue is full or NATS is unavailable, events are dropped and
counted. The request is never delayed or failed because of Pheme.

Every option can be set in the paste filter section or, if absent there,
through an environment variable ``PHEME_<OPTION>`` (for example
``PHEME_NATS_PASSWORD``).
"""

import datetime
import os

from oslo_log import log as logging
from oslo_utils import strutils
import webob.dec

from phememiddleware import _events
from phememiddleware import _keystone
from phememiddleware import _metrics
from phememiddleware import _publisher

SKIP_METHODS = frozenset(['GET', 'HEAD', 'OPTIONS'])

DEFAULTS = {
    'enabled': 'true',
    'nats_url': 'nats://localhost:4222',
    'region': 'local',
    'queue_size': '1000',
    'publish_timeout': '2.0',
    'metrics_enabled': 'false',
    'keystone_user_domain_name': 'Default',
    'keystone_project_domain_name': 'Default',
}


def _option(conf, name):
    value = conf.get(name)
    if value is None or value == '':
        value = os.environ.get('PHEME_' + name.upper())
    if value is None or value == '':
        value = DEFAULTS.get(name)
    return value


class PhemeMiddleware(object):
    """WSGI filter that hands mutating requests to the Pheme publisher."""

    def __init__(self, app, **conf):
        """Configure from the paste filter section (plus env fallbacks)."""
        self._application = app
        self._log = logging.getLogger(conf.get('log_name', __name__))
        self.enabled = strutils.bool_from_string(_option(conf, 'enabled'))
        statsd = None
        if strutils.bool_from_string(_option(conf, 'metrics_enabled')):
            statsd = _metrics.create_statsd_client(
                _option(conf, 'service_type') or 'unknown', self._log)
        self.counters = _metrics.Counters(self._log, statsd)
        self.publisher = None
        if not self.enabled:
            self._log.info("pheme middleware disabled")
            return

        domain_lookup = _keystone.create_lookup(
            _option(conf, 'keystone_auth_url'),
            _option(conf, 'keystone_username'),
            _option(conf, 'keystone_password'),
            _option(conf, 'keystone_project_name'),
            _option(conf, 'keystone_user_domain_name'),
            _option(conf, 'keystone_project_domain_name'),
            self._log)
        self.builder = _events.EventBuilder(
            _option(conf, 'audit_map_file'),
            _option(conf, 'region'),
            self.counters, self._log,
            service_type=_option(conf, 'service_type'),
            domain_lookup=domain_lookup)
        servers = [s.strip() for s in _option(conf, 'nats_url').split(',')
                   if s.strip()]
        self.publisher = _publisher.Publisher(
            self.builder.build, servers,
            _option(conf, 'nats_user'), _option(conf, 'nats_password'),
            float(_option(conf, 'publish_timeout')),
            int(_option(conf, 'queue_size')),
            self.counters, self._log)
        self._log.info("pheme middleware publishing %(service)s events to "
                       "%(servers)s as %(source)s",
                       {'service': self.builder.service_type,
                        'servers': servers, 'source': self.builder.source})

    def get_counters(self):
        """Return a snapshot of the published/dropped counters."""
        return self.counters.snapshot()

    @webob.dec.wsgify
    def __call__(self, req):
        """Call the application, then hand the facts off without waiting."""
        response = req.get_response(self._application)
        if self.publisher is not None and req.method not in SKIP_METHODS:
            self._capture(req, response)
        return response

    def _capture(self, req, response):
        # Runs on the request thread: raw facts only, no parsing, no I/O.
        try:
            if not 200 <= response.status_int < 300:
                return
            env = req.environ
            body = None
            if (response.content_length != 0 and
                    response.content_type == 'application/json'):
                body = response.body
            original = None
            context = env.get('webob.adhoc_attrs', {}).get('context')
            if isinstance(context, dict):
                original = context.get('original_resources')
            facts = _events.Facts(
                method=req.method,
                path=req.path,
                status=response.status_int,
                time=datetime.datetime.now(datetime.timezone.utc),
                token_project_id=env.get('HTTP_X_PROJECT_ID'),
                token_domain_id=env.get('HTTP_X_PROJECT_DOMAIN_ID'),
                user_id=env.get('HTTP_X_USER_ID'),
                request_id=env.get('openstack.request_id'),
                body=body,
                original=original)
            self.publisher.submit(facts)
        except Exception:
            # Pheme must never fail a request that the service handled.
            self.counters.inc(_metrics.DROPPED, 'capture_failed')
            self._log.debug("pheme: capture failed", exc_info=True)


def filter_factory(global_conf, **local_conf):
    """Return a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def pheme_filter(app):
        return PhemeMiddleware(app, **conf)

    return pheme_filter
