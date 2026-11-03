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

"""_auditmap resolves upstream's audit maps the way upstream's parser does.

The fixtures in upstream/ are etc/neutron_audit_map.yaml,
etc/cinder_audit_map.yaml and etc/nova_audit_map.yaml from
sapcc/openstack-audit-middleware at UPSTREAM_COMMIT. The CASES below are
what upstream's own parser (auditmiddleware/_api.py at that commit)
returns for each path.

To refresh:

1. In a clone of upstream, run
   ``git log <UPSTREAM_COMMIT>..<new> -- auditmiddleware/_api.py etc/``.
   If it prints nothing, only UPSTREAM_COMMIT needs updating. Otherwise
   copy those three files from upstream at <new> into upstream/ and set
   UPSTREAM_COMMIT.
2. Install upstream master into a scratch venv and resolve every path in
   CASES with it: build OpenStackAuditMiddleware(map_file, False, False),
   replace its _create_events with a function that returns
   (res_spec.type_uri, res_spec.el_type_uri, res_id, res_parent_id,
   suffix, target_project), and call create_events(webob.Request.blank(
   path, method=method)). A None result means the path is not resolved.
3. Update CASES to what upstream returns. If upstream's _api.py parser
   changed, port the change into _auditmap.py so this test passes again.
"""

import os

import oslotest.base as oslotest
import webob

from phememiddleware import _auditmap
from phememiddleware import _events

UPSTREAM_COMMIT = 'd87988b9877ac722671f1e73cbeeed4055199326'
UPSTREAM = os.path.join(os.path.dirname(__file__), 'upstream')

PROJECT = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'
ROUTER = '11111111-1111-1111-1111-111111111111'
BGPVPN = '22222222-2222-2222-2222-222222222222'
PORT = '33333333-3333-3333-3333-333333333333'
ASSOC = '44444444-4444-4444-4444-444444444444'
VOLUME = '55555555-5555-5555-5555-555555555555'
SERVER = '66666666-6666-6666-6666-666666666666'
SNAPSHOT = '77777777-7777-7777-7777-777777777777'

_BGPVPNS = '/v2.0/bgpvpn/bgpvpns/' + BGPVPN
_RA = ('network/bgpvpn/router-associations',
       'network/bgpvpn/router-association')
_NA = ('network/bgpvpn/network-associations',
       'network/bgpvpn/network-association')
_PA = ('network/bgpvpn/port-associations',
       'network/bgpvpn/port-association')
_ROUTERS = ('network/routers', 'network/router')
_PORTS = ('network/ports', 'network/port')
_VOLUMES = ('storage/volume/volumes', 'storage/volume/volume')
_SERVERS = ('compute/servers', 'compute/server')

# (service, method, path,
#  None or (type_uri, el_type_uri, res_id, parent_id, suffix, project))
CASES = [
    # routers, including by-id deletes and interface add/remove
    ('neutron', 'POST', '/v2.0/routers',
     _ROUTERS + (None, None, None, None)),
    ('neutron', 'PUT', '/v2.0/routers/' + ROUTER,
     _ROUTERS + (ROUTER, None, None, None)),
    ('neutron', 'DELETE', '/v2.0/routers/%s.json' % ROUTER,
     _ROUTERS + (ROUTER, None, None, None)),
    ('neutron', 'PUT', '/v2.0/routers/%s/add_router_interface' % ROUTER,
     _ROUTERS + (ROUTER, None, 'add_router_interface', None)),
    ('neutron', 'PUT', '/v2.0/routers/%s/remove_router_interface' % ROUTER,
     _ROUTERS + (ROUTER, None, 'remove_router_interface', None)),
    # ports
    ('neutron', 'POST', '/v2.0/ports',
     _PORTS + (None, None, None, None)),
    ('neutron', 'PUT', '/v2.0/ports/' + PORT,
     _PORTS + (PORT, None, None, None)),
    ('neutron', 'DELETE', '/v2.0/ports/%s/' % PORT,
     _PORTS + (PORT, None, None, None)),
    ('neutron', 'PUT', '/v2.0/ports/%s/tags/blue' % PORT,
     ('network/port/tags', 'network/port/tag', None, PORT, 'blue', None)),
    # bgpvpns and their associations (children of a singleton namespace)
    ('neutron', 'POST', '/v2.0/bgpvpn/bgpvpns',
     ('network/bgpvpns', 'network/bgpvpn', None, None, None, None)),
    ('neutron', 'DELETE', _BGPVPNS,
     ('network/bgpvpns', 'network/bgpvpn', BGPVPN, None, None, None)),
    ('neutron', 'POST', _BGPVPNS + '/router_associations',
     _RA + (None, BGPVPN, None, None)),
    ('neutron', 'PUT', _BGPVPNS + '/router_associations/' + ASSOC,
     _RA + (ASSOC, BGPVPN, None, None)),
    ('neutron', 'DELETE', _BGPVPNS + '/router_associations/' + ASSOC,
     _RA + (ASSOC, BGPVPN, None, None)),
    ('neutron', 'POST', _BGPVPNS + '/network_associations',
     _NA + (None, BGPVPN, None, None)),
    ('neutron', 'DELETE', _BGPVPNS + '/network_associations/' + ASSOC,
     _NA + (ASSOC, BGPVPN, None, None)),
    ('neutron', 'POST', _BGPVPNS + '/port_associations',
     _PA + (None, BGPVPN, None, None)),
    ('neutron', 'PUT', _BGPVPNS + '/port_associations/' + ASSOC,
     _PA + (ASSOC, BGPVPN, None, None)),
    ('neutron', 'DELETE', _BGPVPNS + '/port_associations/' + ASSOC,
     _PA + (ASSOC, BGPVPN, None, None)),
    # unknown resources are registered on demand; other prefixes are not
    # resolved
    ('neutron', 'POST', '/v2.0/widgets',
     ('network/Xwidgets', 'network/Xwidget', None, None, None, None)),
    ('neutron', 'POST', '/v3/routers', None),
    # the prefix only matches at the start of the path
    ('neutron', 'POST', '/v3/v2.0/routers', None),
    # a trailing slash is stripped
    ('neutron', 'POST', '/v2.0/routers/',
     _ROUTERS + (None, None, None, None)),
    # unknown children below an element keep the element's ID as parent
    ('neutron', 'PUT', '/v2.0/ports/%s/foo/bar/baz' % PORT,
     ('network/port/Xfo/Xbar', 'network/port/Xfo/Xba', None, PORT, 'baz',
      None)),
    # a known child name right after a collection is the child, not an ID
    ('neutron', 'GET', '/v2.0/ports/tags',
     ('network/port/tags', 'network/port/tag', None, None, None, None)),
    # cinder: the prefix captures the target project
    ('cinder', 'POST', '/v3/%s/volumes' % PROJECT,
     _VOLUMES + (None, None, None, PROJECT)),
    ('cinder', 'DELETE', '/v3/%s/volumes/%s' % (PROJECT, VOLUME),
     _VOLUMES + (VOLUME, None, None, PROJECT)),
    ('cinder', 'POST', '/v3/%s/volumes/%s/action' % (PROJECT, VOLUME),
     _VOLUMES + (VOLUME, None, 'action', PROJECT)),
    ('cinder', 'PUT', '/v3/%s/snapshots/%s/metadata/color'
     % (PROJECT, SNAPSHOT),
     ('storage/volume/snapshot/metadata', None, None, SNAPSHOT, 'color',
      PROJECT)),
    ('cinder', 'POST', '/v3/volumes', None),
    # nova: the prefix may hold a project, but not as a named group
    ('nova', 'POST', '/v2.1/servers',
     _SERVERS + (None, None, None, None)),
    ('nova', 'DELETE', '/v2.1/servers/' + SERVER,
     _SERVERS + (SERVER, None, None, None)),
    ('nova', 'POST', '/v2.1/%s/servers/%s/action' % (PROJECT, SERVER),
     _SERVERS + (SERVER, None, 'action', None)),
    ('nova', 'POST', '/v2.1/os-aggregates/7/action',
     ('compute/aggregates', 'compute/aggregate', '7', None, 'action',
      None)),
    # unknown resources lose an os- prefix and get '-' for '_'
    ('nova', 'POST', '/v2.1/os-foo_bar',
     ('compute/Xfoo-bar', 'compute/Xfoo-ba', None, None, None, None)),
]


class TestUpstreamDrift(oslotest.BaseTestCase):
    """The copied parser agrees with upstream on upstream's own maps."""

    def resolve(self, service, method, path):
        """Resolve one path with a fresh Resolver for the service's map."""
        resolver = _auditmap.Resolver(
            os.path.join(UPSTREAM, '%s_audit_map.yaml' % service))
        res = resolver.resolve(webob.Request.blank(path, method=method))
        if res is None:
            return None
        return (res.res_spec.type_uri, res.res_spec.el_type_uri,
                res.res_id, res.parent_id, res.suffix, res.target_project)

    def test_cases_match_upstream(self):
        """Every path resolves to what upstream's parser returns."""
        mismatches = []
        for service, method, path, want in CASES:
            got = self.resolve(service, method, path)
            if got != want:
                mismatches.append((service, method, path, want, got))
        self.assertEqual([], mismatches)

    def test_every_kind_is_covered(self):
        """Each Pheme kind resolves from upstream's neutron map."""
        covered = set(want[1] for service, _m, _p, want in CASES
                      if service == 'neutron' and want is not None)
        self.assertEqual(set(), set(_events.KINDS) - covered)

    def test_service_identity(self):
        """Service type and name come from each map."""
        for service, service_type in (('neutron', 'network'),
                                      ('cinder', 'storage/volume'),
                                      ('nova', 'compute')):
            resolver = _auditmap.Resolver(
                os.path.join(UPSTREAM, '%s_audit_map.yaml' % service))
            self.assertEqual(service_type, resolver.service_type)
            self.assertEqual(service, resolver.service_name)
