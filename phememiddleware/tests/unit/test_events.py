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

"""Event content per kind and verb, and the contract paths."""

import json
import uuid

from phememiddleware import _events
from phememiddleware import _metrics
from phememiddleware.tests.unit import base

ROUTER_PATH = '/domains/%s/projects/%s/network/routers/%s' % (
    base.DOMAIN, base.PROJECT, base.ROUTER)
BGPVPN_PATH = '/domains/%s/projects/%s/network/bgpvpns/%s' % (
    base.DOMAIN, base.PROJECT, base.BGPVPN)
ASSOC_PATH = BGPVPN_PATH + '/router_associations/' + base.ASSOC


class TestEventBuilder(base.TestCase):
    """EventBuilder turns facts into contract CloudEvents."""

    def setUp(self):
        """Create a builder on the neutron audit map."""
        super(TestEventBuilder, self).setUp()
        self.builder = _events.EventBuilder(base.NEUTRON_AUDIT_MAP, 'local',
                                            self.counters, self.log)

    def build_one(self, facts):
        """Build events and return the single event, parsed."""
        events = self.builder.build(facts)
        self.assertEqual(1, len(events), events)
        return events[0], json.loads(events[0].body)

    def assert_event(self, ev, ce, ce_type, path, data):
        """Check the full set of contract attributes."""
        kind = ce_type.rsplit('.', 1)[0]
        self.assertEqual('pheme.events.' + kind, ev.subject)
        self.assertEqual('1.0', ce['specversion'])
        self.assertEqual(str(uuid.UUID(ce['id'])), ce['id'])
        self.assertEqual(ce['id'], ev.msg_id)
        self.assertEqual({'Nats-Msg-Id': ce['id'],
                          'Content-Type': 'application/cloudevents+json'},
                         ev.headers)
        self.assertEqual('openstack/neutron/local', ce['source'])
        self.assertEqual(ce_type, ce['type'])
        self.assertEqual(path, ce['subject'])
        self.assertEqual('2026-10-09T10:00:00.123456Z', ce['time'])
        self.assertEqual('application/json', ce['datacontenttype'])
        self.assertEqual('pheme:schema/%s/v1' % kind, ce['dataschema'])
        self.assertEqual(base.PROJECT, ce['projectid'])
        self.assertEqual(base.DOMAIN, ce['domainid'])
        self.assertEqual(base.REQUEST_ID, ce['requestid'])
        self.assertEqual(base.USER, ce['initiatoruser'])
        self.assertEqual(data, ce.get('data'))

    # routers

    def test_router_added(self):
        """POST /routers is network.router.added with the router object."""
        ev, ce = self.build_one(base.make_facts(
            'POST', '/v2.0/routers', {'router': base.router()}, 201))
        self.assert_event(ev, ce, 'network.router.added', ROUTER_PATH,
                          base.router())

    def test_router_updated(self):
        """PUT /routers/{id} is network.router.updated."""
        body = {'router': base.router(name='renamed')}
        ev, ce = self.build_one(base.make_facts(
            'PUT', '/v2.0/routers/' + base.ROUTER, body))
        self.assert_event(ev, ce, 'network.router.updated', ROUTER_PATH,
                          base.router(name='renamed'))

    def test_router_deleted_with_last_known_state(self):
        """DELETE carries the last state this process saw for the router."""
        self.builder.build(base.make_facts(
            'POST', '/v2.0/routers', {'router': base.router()}, 201))
        ev, ce = self.build_one(base.make_facts(
            'DELETE', '/v2.0/routers/' + base.ROUTER, status=204))
        self.assert_event(ev, ce, 'network.router.deleted', ROUTER_PATH,
                          base.router())

    def test_router_deleted_without_state(self):
        """Non-admin DELETE without cached state: null data, token owner."""
        ev, ce = self.build_one(base.make_facts(
            'DELETE', '/v2.0/routers/' + base.ROUTER, status=204))
        self.assert_event(ev, ce, 'network.router.deleted', ROUTER_PATH,
                          None)

    def test_admin_delete_without_state_is_dropped(self):
        """An admin DELETE with an unknown owner is dropped, not misfiled."""
        events = self.builder.build(base.make_facts(
            'DELETE', '/v2.0/routers/' + base.ROUTER, status=204,
            roles='admin,member', token_project_id=base.ADMIN_PROJECT,
            token_domain_id=base.ADMIN_DOMAIN))
        self.assertEqual([], events)
        self.assertEqual(1, self.counters.get(_metrics.DROPPED,
                                              'owner_unknown'))

    def test_admin_delete_uses_cached_owner(self):
        """An admin DELETE of another project's router uses the cache."""
        lookups = []

        def lookup(project_id):
            lookups.append(project_id)
            return base.OTHER_DOMAIN

        builder = _events.EventBuilder(base.NEUTRON_AUDIT_MAP, 'local',
                                       self.counters, self.log,
                                       domain_lookup=lookup)
        obj = base.router(project_id=base.OTHER_PROJECT,
                          tenant_id=base.OTHER_PROJECT)
        admin = dict(roles='admin', token_project_id=base.ADMIN_PROJECT,
                     token_domain_id=base.ADMIN_DOMAIN)
        builder.build(base.make_facts('POST', '/v2.0/routers',
                                      {'router': obj}, 201, **admin))
        events = builder.build(base.make_facts(
            'DELETE', '/v2.0/routers/' + base.ROUTER, status=204, **admin))
        ce = json.loads(events[0].body)
        self.assertEqual(
            '/domains/%s/projects/%s/network/routers/%s'
            % (base.OTHER_DOMAIN, base.OTHER_PROJECT, base.ROUTER),
            ce['subject'])
        self.assertEqual(obj, ce['data'])
        self.assertEqual([base.OTHER_PROJECT], lookups)   # cached after
        # deleted: forgotten, a second delete has no owner any more
        self.assertEqual([], builder.build(base.make_facts(
            'DELETE', '/v2.0/routers/' + base.ROUTER, status=204, **admin)))

    def test_member_action_keeps_cached_state(self):
        """A member action with no router body does not erase the cache."""
        self.builder.build(base.make_facts(
            'POST', '/v2.0/routers', {'router': base.router()}, 201))
        self.builder.build(base.make_facts(
            'PUT', '/v2.0/routers/%s/add_router_interface' % base.ROUTER,
            {'id': base.ROUTER, 'subnet_id': 'sub'}))
        ev, ce = self.build_one(base.make_facts(
            'DELETE', '/v2.0/routers/' + base.ROUTER, status=204))
        self.assertEqual(base.router(), ce['data'])

    def test_owner_cache_is_bounded(self):
        """The owner cache evicts the least recently used entry."""
        cache = _events._OwnerCache(2)
        cache.put('a', 'p', 'd', {'n': 1})
        cache.put('b', 'p', 'd', None)
        cache.get('a')
        cache.put('c', 'p', 'd', None)
        self.assertIsNone(cache.get('b'))
        self.assertEqual({'n': 1}, cache.get('a').data)
        cache.put('a', 'p', 'd', None)
        self.assertEqual({'n': 1}, cache.get('a').data)

    def test_router_add_interface(self):
        """add_router_interface is network.router.updated."""
        body = {'id': base.ROUTER, 'subnet_id': 'sub', 'port_id': 'port',
                'project_id': base.PROJECT}
        ev, ce = self.build_one(base.make_facts(
            'PUT', '/v2.0/routers/%s/add_router_interface' % base.ROUTER,
            body))
        self.assert_event(ev, ce, 'network.router.updated', ROUTER_PATH,
                          None)
        self.assertEqual('add_router_interface', ce['subaction'])

    def test_router_remove_interface(self):
        """remove_router_interface is network.router.updated."""
        ev, ce = self.build_one(base.make_facts(
            'PUT', '/v2.0/routers/%s/remove_router_interface' % base.ROUTER,
            {'id': base.ROUTER, 'subnet_id': 'sub'}))
        self.assertEqual('network.router.updated', ce['type'])
        self.assertEqual(ROUTER_PATH, ce['subject'])
        self.assertEqual('remove_router_interface', ce['subaction'])

    def test_router_member_action_with_router_body(self):
        """A member action that returns the router carries it as data."""
        body = {'router': base.router(routes=[{'destination': '10.0.0.0/8',
                                                'nexthop': '192.0.2.1'}])}
        ev, ce = self.build_one(base.make_facts(
            'PUT', '/v2.0/routers/%s/add_extraroutes' % base.ROUTER, body))
        self.assertEqual('network.router.updated', ce['type'])
        self.assertEqual(body['router'], ce['data'])

    def test_router_bulk_create(self):
        """A bulk POST creates one event per router."""
        r2 = base.router(id='55555555-5555-5555-5555-555555555555')
        events = self.builder.build(base.make_facts(
            'POST', '/v2.0/routers', {'routers': [base.router(), r2]}, 201))
        self.assertEqual(
            [ROUTER_PATH, ROUTER_PATH.replace(base.ROUTER, r2['id'])],
            [e.path for e in events])

    def test_path_normalization(self):
        """Trailing slashes and .json suffixes resolve like the audit map."""
        for path in ('/v2.0/routers/%s.json' % base.ROUTER,
                     '/v2.0/routers/%s/' % base.ROUTER):
            ev, ce = self.build_one(base.make_facts(
                'PUT', path, {'router': base.router()}))
            self.assertEqual(ROUTER_PATH, ce['subject'])

    # BGPVPN

    def test_bgpvpn_added(self):
        """POST /bgpvpn/bgpvpns is network.bgpvpn.added."""
        ev, ce = self.build_one(base.make_facts(
            'POST', '/v2.0/bgpvpn/bgpvpns', {'bgpvpn': base.bgpvpn()}, 201))
        self.assert_event(ev, ce, 'network.bgpvpn.added', BGPVPN_PATH,
                          base.bgpvpn())

    def test_bgpvpn_updated(self):
        """PUT /bgpvpn/bgpvpns/{id} is network.bgpvpn.updated."""
        body = {'bgpvpn': base.bgpvpn(name='vpn2')}
        ev, ce = self.build_one(base.make_facts(
            'PUT', '/v2.0/bgpvpn/bgpvpns/' + base.BGPVPN, body))
        self.assert_event(ev, ce, 'network.bgpvpn.updated', BGPVPN_PATH,
                          body['bgpvpn'])

    def test_bgpvpn_deleted(self):
        """DELETE /bgpvpn/bgpvpns/{id} is network.bgpvpn.deleted."""
        self.builder.build(base.make_facts(
            'POST', '/v2.0/bgpvpn/bgpvpns', {'bgpvpn': base.bgpvpn()}, 201))
        ev, ce = self.build_one(base.make_facts(
            'DELETE', '/v2.0/bgpvpn/bgpvpns/' + base.BGPVPN, status=204))
        self.assert_event(ev, ce, 'network.bgpvpn.deleted', BGPVPN_PATH,
                          base.bgpvpn())

    # BGPVPN router associations

    def test_router_association_added(self):
        """POST router_associations is ..._router_association.added."""
        ev, ce = self.build_one(base.make_facts(
            'POST', '/v2.0/bgpvpn/bgpvpns/%s/router_associations'
            % base.BGPVPN, {'router_association': base.router_association()},
            201))
        self.assert_event(ev, ce,
                          'network.bgpvpn_router_association.added',
                          ASSOC_PATH, base.router_association())

    def test_router_association_updated(self):
        """PUT router_associations/{id} is ..._router_association.updated."""
        body = {'router_association': base.router_association(
            advertise_extra_routes=False)}
        ev, ce = self.build_one(base.make_facts(
            'PUT', '/v2.0/bgpvpn/bgpvpns/%s/router_associations/%s'
            % (base.BGPVPN, base.ASSOC), body))
        self.assert_event(ev, ce,
                          'network.bgpvpn_router_association.updated',
                          ASSOC_PATH, body['router_association'])

    def test_router_association_deleted(self):
        """DELETE router_associations/{id} is ..._association.deleted."""
        ev, ce = self.build_one(base.make_facts(
            'DELETE', '/v2.0/bgpvpn/bgpvpns/%s/router_associations/%s'
            % (base.BGPVPN, base.ASSOC), status=204))
        self.assert_event(ev, ce,
                          'network.bgpvpn_router_association.deleted',
                          ASSOC_PATH, None)

    # owner and domain

    def test_cross_project_uses_domain_lookup(self):
        """An owner other than the token project gets its domain looked up."""
        lookups = []

        def lookup(project_id):
            lookups.append(project_id)
            return base.OTHER_DOMAIN

        builder = _events.EventBuilder(base.NEUTRON_AUDIT_MAP, 'local',
                                       self.counters, self.log,
                                       domain_lookup=lookup)
        obj = base.router(project_id=base.OTHER_PROJECT,
                          tenant_id=base.OTHER_PROJECT)
        events = builder.build(base.make_facts('POST', '/v2.0/routers',
                                               {'router': obj}, 201))
        ce = json.loads(events[0].body)
        self.assertEqual([base.OTHER_PROJECT], lookups)
        self.assertEqual(
            '/domains/%s/projects/%s/network/routers/%s'
            % (base.OTHER_DOMAIN, base.OTHER_PROJECT, base.ROUTER),
            ce['subject'])
        self.assertEqual(base.OTHER_PROJECT, ce['projectid'])
        self.assertEqual(base.OTHER_DOMAIN, ce['domainid'])

    def test_cross_project_without_lookup_is_dropped(self):
        """Without a lookup, an unknown owner domain drops the event."""
        obj = base.router(project_id=base.OTHER_PROJECT,
                          tenant_id=base.OTHER_PROJECT)
        events = self.builder.build(base.make_facts(
            'POST', '/v2.0/routers', {'router': obj}, 201))
        self.assertEqual([], events)
        self.assertEqual(1, self.counters.get(_metrics.DROPPED,
                                              'domain_unknown'))

    def test_tenant_id_only_payload(self):
        """Owner falls back to tenant_id when project_id is absent."""
        obj = base.router()
        del obj['project_id']
        ev, ce = self.build_one(base.make_facts(
            'POST', '/v2.0/routers', {'router': obj}, 201))
        self.assertEqual(base.PROJECT, ce['projectid'])

    def test_path_segments_are_percent_encoded(self):
        """Segment values are percent-encoded, unreserved chars kept."""
        self.assertEqual('10.0.0.0%2F24', _events.quote_segment('10.0.0.0/24'))
        self.assertEqual('a-b_c.d~e', _events.quote_segment('a-b_c.d~e'))
        self.assertEqual('/x/a%20b/2001%3Adb8%3A%3A%2F32',
                         _events.build_path(['x', 'a b', '2001:db8::/32']))

    # things that are not in the contract

    def test_other_resources_are_ignored(self):
        """Networks, ports and router tags are not contract kinds."""
        cases = [
            ('POST', '/v2.0/networks', {'network': {'id': 'n1'}}),
            ('PUT', '/v2.0/ports/' + base.ROUTER, {'port': {'id': 'p'}}),
            ('PUT', '/v2.0/routers/%s/tags/foo' % base.ROUTER, None),
            ('POST', '/v2.0/bgpvpn/bgpvpns/%s/network_associations'
             % base.BGPVPN, {'network_association': {'id': base.ASSOC}}),
        ]
        for method, path, body in cases:
            self.assertEqual([], self.builder.build(
                base.make_facts(method, path, body)), path)

    def test_unknown_prefix_is_ignored(self):
        """Paths outside the audit map prefix produce nothing."""
        self.assertEqual([], self.builder.build(
            base.make_facts('POST', '/v3/routers', {'router': {}})))

    def test_missing_body_on_create_is_ignored(self):
        """A create without a response object produces nothing."""
        self.assertEqual([], self.builder.build(
            base.make_facts('POST', '/v2.0/routers', None, 201)))

    def test_region_and_service_type(self):
        """Region feeds the source; service_type overrides the map."""
        builder = _events.EventBuilder(base.NEUTRON_AUDIT_MAP, 'qa-de-1',
                                       self.counters, self.log)
        self.assertEqual('openstack/neutron/qa-de-1', builder.source)
        self.assertEqual('network', builder.service_type)
