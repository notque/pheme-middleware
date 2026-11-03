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

"""The audit map parser (Resolver.resolve)."""

import os

import fixtures
import oslotest.base as oslotest
import webob

from phememiddleware import _auditmap

UPSTREAM = os.path.join(os.path.dirname(__file__), 'upstream')
NEUTRON_MAP = os.path.join(UPSTREAM, 'neutron_audit_map.yaml')
R = '11111111-1111-1111-1111-111111111111'
B = '22222222-2222-2222-2222-222222222222'


class TestResolver(oslotest.BaseTestCase):
    """Resolver turns request paths into resource specs and IDs."""

    def setUp(self):
        """Load upstream's neutron audit map."""
        super(TestResolver, self).setUp()
        self.resolver = _auditmap.Resolver(NEUTRON_MAP)

    def resolve(self, path, method='GET'):
        """Resolve a path with a blank request."""
        return self.resolver.resolve(webob.Request.blank(path,
                                                         method=method))

    def test_service(self):
        """Service type and name come from the map."""
        self.assertEqual('network', self.resolver.service_type)
        self.assertEqual('neutron', self.resolver.service_name)
        self.assertIn('routers', self.resolver.resource_specs)

    def test_collection_and_element(self):
        """Collections have no ID; elements carry it."""
        res = self.resolve('/v2.0/routers')
        self.assertEqual('network/router', res.res_spec.el_type_uri)
        self.assertIsNone(res.res_id)
        self.assertIsNone(res.suffix)
        res = self.resolve('/v2.0/routers/%s.json' % R)
        self.assertEqual(R, res.res_id)

    def test_action_suffix(self):
        """A trailing action is the suffix."""
        res = self.resolve('/v2.0/routers/%s/add_router_interface' % R)
        self.assertEqual(R, res.res_id)
        self.assertEqual('add_router_interface', res.suffix)

    def test_child_with_parent(self):
        """Children carry the parent ID through singleton namespaces."""
        res = self.resolve('/v2.0/bgpvpn/bgpvpns/%s/router_associations/%s'
                           % (B, R))
        self.assertEqual('network/bgpvpn/router-association',
                         res.res_spec.el_type_uri)
        self.assertEqual(R, res.res_id)
        self.assertEqual(B, res.parent_id)

    def test_prefix_mismatch(self):
        """Paths outside the prefix resolve to None."""
        self.assertIsNone(self.resolve('/v3/routers'))

    def test_missing_file(self):
        """A missing file is a ConfigError."""
        self.assertRaises(_auditmap.ConfigError, _auditmap.Resolver,
                          '/nonexistent.yaml')

    def test_missing_prefix(self):
        """A map without a prefix is a ConfigError."""
        path = os.path.join(self.useFixture(fixtures.TempDir()).path,
                            'map.yaml')
        with open(path, 'w') as f:
            f.write("service_type: network\nresources:\n  routers:\n")
        self.assertRaises(_auditmap.ConfigError, _auditmap.Resolver, path)
