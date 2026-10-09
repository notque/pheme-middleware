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

"""Shared fixtures for the phememiddleware tests."""

import datetime
import json
import logging
import os
import socket

import fixtures
import oslotest.base as oslotest

from phememiddleware import _events
from phememiddleware import _metrics

# The neutron audit map from sapcc/helm-charts
# (openstack/neutron/templates/etc/_neutron_audit_map.yaml).
NEUTRON_AUDIT_MAP = os.path.join(os.path.dirname(__file__),
                                 'neutron_audit_map.yaml')

DOMAIN = 'd1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1'
PROJECT = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'
OTHER_PROJECT = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2'
OTHER_DOMAIN = 'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2'
ADMIN_PROJECT = 'e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5'
ADMIN_DOMAIN = 'default'
USER = 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3'
ROUTER = '11111111-1111-1111-1111-111111111111'
BGPVPN = '22222222-2222-2222-2222-222222222222'
ASSOC = '33333333-3333-3333-3333-333333333333'
REQUEST_ID = 'req-44444444-4444-4444-4444-444444444444'
NOW = datetime.datetime(2026, 10, 9, 10, 0, 0, 123456,
                        tzinfo=datetime.timezone.utc)


def router(**kw):
    """Return a router object as Neutron returns it."""
    obj = {'id': ROUTER, 'name': 'r1', 'project_id': PROJECT,
           'tenant_id': PROJECT, 'status': 'ACTIVE',
           'admin_state_up': True, 'external_gateway_info': None,
           'routes': []}
    obj.update(kw)
    return obj


def bgpvpn(**kw):
    """Return a BGPVPN object as networking-bgpvpn returns it."""
    obj = {'id': BGPVPN, 'name': 'vpn1', 'project_id': PROJECT,
           'tenant_id': PROJECT, 'type': 'l3',
           'route_targets': ['64512:1'], 'routers': []}
    obj.update(kw)
    return obj


def router_association(**kw):
    """Return a BGPVPN router association object."""
    obj = {'id': ASSOC, 'router_id': ROUTER, 'project_id': PROJECT,
           'tenant_id': PROJECT, 'advertise_extra_routes': True}
    obj.update(kw)
    return obj


def make_facts(method, path, body=None, status=200, roles='member',
               token_project_id=PROJECT, token_domain_id=DOMAIN):
    """Build request facts as the middleware captures them."""
    if body is not None and not isinstance(body, bytes):
        body = json.dumps(body).encode('utf-8')
    return _events.Facts(method=method, path=path, status=status, time=NOW,
                         token_project_id=token_project_id,
                         token_domain_id=token_domain_id, user_id=USER,
                         roles=roles, request_id=REQUEST_ID, body=body)


def free_port():
    """Return a TCP port on localhost that nothing listens on."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestCase(oslotest.BaseTestCase):
    """Base class with a logger and counters."""

    def setUp(self):
        """Set up logging capture and fresh counters."""
        super(TestCase, self).setUp()
        self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))
        self.log = logging.getLogger('phememiddleware.tests')
        self.counters = _metrics.Counters(self.log)
