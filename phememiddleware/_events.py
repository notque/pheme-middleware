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

"""Turn captured request facts into Pheme CloudEvents.

Everything in this module runs on the publisher thread, never on the
request thread.
"""

import collections
import json
import urllib.parse
import uuid

import webob

from auditmiddleware import _api
from phememiddleware import _metrics

try:
    # cloudevents >= 2.0 keeps the 1.x API under cloudevents.v1
    from cloudevents.v1.conversion import to_structured
    from cloudevents.v1.http import CloudEvent
except ImportError:
    from cloudevents.conversion import to_structured
    from cloudevents.http import CloudEvent

# The raw facts captured on the request thread. Nothing here is parsed yet.
Facts = collections.namedtuple('Facts', [
    'method', 'path', 'status', 'time', 'token_project_id',
    'token_domain_id', 'user_id', 'roles', 'request_id', 'body'])

# Result of resolving a request path with the audit map.
Resolution = collections.namedtuple('Resolution', [
    'res_spec', 'res_id', 'res_parent_id', 'suffix', 'target_project'])

# A ready-to-publish message.
Event = collections.namedtuple('Event', [
    'subject', 'msg_id', 'headers', 'body', 'ce_type', 'path'])

# Contract kinds, keyed by the audit map element type URI.
# Each entry: kind name, function (res_id, parent_id) -> path segments.
Kind = collections.namedtuple('Kind', ['name', 'segments'])

KINDS = {
    'network/router': Kind(
        'router', lambda rid, pid: ['routers', rid]),
    'network/bgpvpn': Kind(
        'bgpvpn', lambda rid, pid: ['bgpvpns', rid]),
    'network/bgpvpn/router-association': Kind(
        'bgpvpn_router_association',
        lambda rid, pid: ['bgpvpns', pid, 'router_associations', rid]),
}

# Kinds whose member actions (PUT /routers/{id}/add_router_interface)
# count as an update of the resource itself.
MEMBER_ACTION_KINDS = frozenset(['router'])

ADDED = 'added'
UPDATED = 'updated'
DELETED = 'deleted'


def quote_segment(value):
    """Percent-encode one path segment, keeping RFC 3986 unreserved chars."""
    return urllib.parse.quote(str(value), safe='')


def build_path(segments):
    """Join segments into a contract path (each segment encoded)."""
    return '/' + '/'.join(quote_segment(s) for s in segments)


def _format_time(ts):
    return ts.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


class _Resolver(_api.OpenStackAuditMiddleware):
    """Reuse the audit map path parser, without building CADF events."""

    def _create_events(self, target_project, res_id, res_parent_id,
                       res_spec, request, response, suffix=None):
        return Resolution(res_spec, res_id, res_parent_id, suffix,
                          target_project)


Owner = collections.namedtuple('Owner', ['project_id', 'domain_id', 'data'])


class _OwnerCache(object):
    """Bounded LRU of resource -> (project_id, domain_id, last data).

    Neutron's legacy API controller, which serves routers and BGPVPN
    resources, does not expose the object it deletes, and a DELETE response
    has no body. The cache remembers the owner and the last state from the
    added/updated events this process built, so a later DELETE or member
    action can use them. Only the publisher thread uses it.
    """

    def __init__(self, size):
        self._size = size
        self._items = collections.OrderedDict()

    def get(self, key):
        entry = self._items.get(key)
        if entry is not None:
            self._items.move_to_end(key)
        return entry

    def put(self, key, project_id, domain_id, data):
        old = self._items.pop(key, None)
        if data is None and old is not None:
            data = old.data
        self._items[key] = Owner(project_id, domain_id, data)
        while len(self._items) > self._size:
            self._items.popitem(last=False)

    def pop(self, key):
        self._items.pop(key, None)


def _is_admin(roles):
    return 'admin' in [r.strip().lower() for r in (roles or '').split(',')]


class EventBuilder(object):
    """Build CloudEvents for the kinds in the event contract."""

    def __init__(self, audit_map_file, region, counters, log,
                 service_type=None, domain_lookup=None,
                 owner_cache_size=10000):
        """Load the audit map and remember the event source identity."""
        self._resolver = _Resolver(audit_map_file, False, False, log)
        self._log = log
        self._counters = counters
        self._domain_lookup = domain_lookup
        self._owners = _OwnerCache(owner_cache_size)
        self.service_type = service_type or self._resolver._service_type
        self.service_name = self._resolver._service_name
        self.source = 'openstack/%s/%s' % (self.service_name, region)

    def resolve(self, method, path):
        """Resolve a request path to the audit map resource spec."""
        request = webob.Request.blank(path, method=method)
        res = self._resolver.create_events(request)
        if isinstance(res, Resolution):
            return res
        return None

    def build(self, facts):
        """Return the list of Events for one request (often empty)."""
        res = self.resolve(facts.method, facts.path)
        if res is None or res.res_spec.el_type_uri not in KINDS:
            return []
        kind = KINDS[res.res_spec.el_type_uri]
        body = json.loads(facts.body) if facts.body else None

        if res.suffix is not None:
            # member action, e.g. add_router_interface
            if (kind.name not in MEMBER_ACTION_KINDS or not res.res_id or
                    facts.method not in ('PUT', 'POST')):
                return []
            data = None
            if isinstance(body, dict) and isinstance(
                    body.get(res.res_spec.el_type_name), dict):
                data = body[res.res_spec.el_type_name]
            return self._events(facts, res, kind, UPDATED, [data],
                                subaction=res.suffix)

        if facts.method == 'DELETE':
            return self._events(facts, res, kind, DELETED, [None])

        if facts.method == 'POST' and not res.res_id:
            verb = ADDED
        elif facts.method in ('POST', 'PUT', 'PATCH'):
            verb = UPDATED
        else:
            return []

        items = []
        if isinstance(body, dict):
            bulk = body.get(res.res_spec.type_name)
            single = body.get(res.res_spec.el_type_name)
            if isinstance(bulk, list):
                items = [i for i in bulk if isinstance(i, dict)]
            elif isinstance(single, dict):
                items = [single]
        if not items:
            self._log.debug("pheme: no %s object in response to %s %s",
                            res.res_spec.el_type_name, facts.method,
                            facts.path)
            return []
        return self._events(facts, res, kind, verb, items)

    def _owner(self, facts, cached, data):
        """Return (project_id, domain_id, reason) for the owning project.

        Order: the object's project_id, the cached owner, then the token's
        project. The token's project is only trusted for non-admin tokens:
        a non-admin can only change resources of its own project, while an
        admin may be acting on any project.
        """
        project_id = None
        if isinstance(data, dict):
            project_id = data.get('project_id') or data.get('tenant_id')
        if not project_id and cached is not None:
            project_id = cached.project_id
        if not project_id:
            if _is_admin(facts.roles) or not facts.token_project_id:
                return None, None, 'owner_unknown'
            project_id = facts.token_project_id
        if cached is not None and cached.project_id == project_id:
            return project_id, cached.domain_id, None
        if project_id == facts.token_project_id and facts.token_domain_id:
            return project_id, facts.token_domain_id, None
        if self._domain_lookup is not None:
            domain_id = self._domain_lookup(project_id)
            if domain_id:
                return project_id, domain_id, None
        return project_id, None, 'domain_unknown'

    def _events(self, facts, res, kind, verb, items, subaction=None):
        events = []
        for data in items:
            rid = res.res_id
            if not rid and isinstance(data, dict):
                rid = data.get(res.res_spec.id_field)
            segments = kind.segments(rid, res.res_parent_id)
            if not rid or None in segments:
                self._counters.inc(_metrics.DROPPED, 'unresolved')
                continue
            key = (kind.name, rid)
            cached = self._owners.get(key)
            if verb == DELETED and cached is not None:
                data = cached.data
            project_id, domain_id, reason = self._owner(facts, cached, data)
            if reason:
                self._counters.inc(_metrics.DROPPED, reason)
                self._log.info("pheme: dropping %(kind)s %(verb)s for "
                               "%(id)s: %(reason)s",
                               {'kind': kind.name, 'verb': verb, 'id': rid,
                                'reason': reason})
                continue
            if verb == DELETED:
                self._owners.pop(key)
            else:
                self._owners.put(key, project_id, domain_id, data)
            path = build_path(['domains', domain_id, 'projects', project_id,
                               self.service_type] + segments)
            events.append(self._cloudevent(facts, kind, verb, path, data,
                                           project_id, domain_id, subaction))
        return events

    def _cloudevent(self, facts, kind, verb, path, data, project_id,
                    domain_id, subaction):
        full_kind = '%s.%s' % (self.service_type, kind.name)
        ce_type = '%s.%s' % (full_kind, verb)
        attrs = {
            'id': str(uuid.uuid4()),
            'source': self.source,
            'type': ce_type,
            'subject': path,
            'time': _format_time(facts.time),
            'datacontenttype': 'application/json',
            'dataschema': 'pheme:schema/%s/v1' % full_kind,
            'projectid': project_id,
            'domainid': domain_id,
        }
        if facts.request_id:
            attrs['requestid'] = facts.request_id
        if facts.user_id:
            attrs['initiatoruser'] = facts.user_id
        if subaction:
            attrs['subaction'] = subaction
        headers, body = to_structured(CloudEvent(attrs, data))
        msg_headers = {'Nats-Msg-Id': attrs['id'],
                       'Content-Type': headers['content-type']}
        return Event('pheme.events.%s' % full_kind, attrs['id'],
                     msg_headers, body, ce_type, path)
