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

"""Owner lookups on the publisher thread, with service credentials.

- ``DomainLookup``: project -> domain in Keystone, when the owning project
  differs from the token's project.
- ``OwnerLookup``: resource -> project_id in Neutron, for child resources
  whose API object has no project_id (BGPVPN associations: their owner is
  the parent BGPVPN's).

Owners and domains never change, so successful lookups are cached for the
life of the process. Never used on the request thread.
"""

from keystoneauth1 import exceptions as ks_exc
from keystoneauth1.identity import v3
from keystoneauth1 import session as ks_session


class DomainLookup(object):
    """Look up a project's domain in Keystone, with a permanent cache."""

    def __init__(self, session, log, timeout=2.0):
        """Use an authenticated keystoneauth1 session."""
        self._session = session
        self._log = log
        self._timeout = timeout
        self._cache = {}

    def __call__(self, project_id):
        """Return the domain ID of a project, or None if unknown."""
        if project_id in self._cache:
            return self._cache[project_id]
        try:
            resp = self._session.get(
                '/projects/%s' % project_id,
                endpoint_filter={'service_type': 'identity',
                                 'interface': 'public',
                                 'version': (3, 0)},
                timeout=self._timeout)
            domain_id = resp.json()['project']['domain_id']
        except (ks_exc.ClientException, ValueError, KeyError) as e:
            self._log.warning("pheme: domain lookup for project %(p)s "
                              "failed: %(err)r", {'p': project_id, 'err': e})
            return None
        self._cache[project_id] = domain_id
        return domain_id


class OwnerLookup(object):
    """Look up a Neutron resource's project_id, with a permanent cache."""

    def __init__(self, session, log, region=None, timeout=2.0):
        """Use an authenticated keystoneauth1 session."""
        self._session = session
        self._log = log
        self._region = region
        self._timeout = timeout
        self._cache = {}

    def __call__(self, collection, resource, resource_id):
        """Return project_id of ``/v2.0/<collection>/<id>``, or None."""
        key = (collection, resource_id)
        if key in self._cache:
            return self._cache[key]
        try:
            resp = self._session.get(
                '/v2.0/%s/%s' % (collection, resource_id),
                endpoint_filter={'service_type': 'network',
                                 'interface': 'public',
                                 'region_name': self._region},
                timeout=self._timeout)
            obj = resp.json()[resource]
            project_id = obj.get('project_id') or obj.get('tenant_id')
        except (ks_exc.ClientException, ValueError, KeyError,
                AttributeError) as e:
            self._log.warning("pheme: owner lookup for %(c)s/%(id)s failed: "
                              "%(err)r", {'c': collection, 'id': resource_id,
                                          'err': e})
            return None
        if project_id:
            self._cache[key] = project_id
        return project_id


def create_lookups(auth_url, username, password, project_name,
                   user_domain_name, project_domain_name, region, log):
    """Build (DomainLookup, OwnerLookup) from service credentials.

    Returns (None, None) if no credentials are configured.
    """
    if not (auth_url and username and password):
        return None, None
    auth = v3.Password(auth_url=auth_url, username=username,
                       password=password, project_name=project_name,
                       user_domain_name=user_domain_name,
                       project_domain_name=project_domain_name)
    session = ks_session.Session(auth=auth)
    return (DomainLookup(session, log),
            OwnerLookup(session, log, region=region))
