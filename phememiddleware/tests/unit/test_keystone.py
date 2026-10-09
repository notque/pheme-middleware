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

"""Keystone domain and Neutron owner lookups."""

from unittest import mock

from keystoneauth1 import exceptions as ks_exc

from phememiddleware import _keystone
from phememiddleware.tests.unit import base


class TestLookups(base.TestCase):
    """Lookups cache successes and swallow failures."""

    def test_owner_lookup_caches(self):
        """The BGPVPN owner is fetched once and cached."""
        session = mock.Mock()
        session.get.return_value.json.return_value = {
            'bgpvpn': {'id': base.BGPVPN, 'project_id': base.PROJECT}}
        lookup = _keystone.OwnerLookup(session, self.log, region='local')
        for _ in range(2):
            self.assertEqual(base.PROJECT, lookup(
                'bgpvpn/bgpvpns', 'bgpvpn', base.BGPVPN))
        session.get.assert_called_once_with(
            '/v2.0/bgpvpn/bgpvpns/' + base.BGPVPN,
            endpoint_filter={'service_type': 'network',
                             'interface': 'public', 'region_name': 'local'},
            timeout=2.0)

    def test_owner_lookup_failure_is_not_cached(self):
        """A failed lookup returns None and is retried next time."""
        session = mock.Mock()
        session.get.side_effect = ks_exc.NotFound()
        lookup = _keystone.OwnerLookup(session, self.log)
        self.assertIsNone(lookup('bgpvpn/bgpvpns', 'bgpvpn', base.BGPVPN))
        self.assertIsNone(lookup('bgpvpn/bgpvpns', 'bgpvpn', base.BGPVPN))
        self.assertEqual(2, session.get.call_count)

    def test_domain_lookup_caches(self):
        """The project domain is fetched once and cached."""
        session = mock.Mock()
        session.get.return_value.json.return_value = {
            'project': {'id': base.PROJECT, 'domain_id': base.DOMAIN}}
        lookup = _keystone.DomainLookup(session, self.log)
        self.assertEqual(base.DOMAIN, lookup(base.PROJECT))
        self.assertEqual(base.DOMAIN, lookup(base.PROJECT))
        self.assertEqual(1, session.get.call_count)

    def test_no_credentials_no_lookups(self):
        """Without credentials there are no lookups."""
        self.assertEqual((None, None), _keystone.create_lookups(
            None, None, None, None, 'Default', 'Default', None, self.log))
