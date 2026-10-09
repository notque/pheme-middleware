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

"""Project to domain lookup for cross-project requests.

Only used on the publisher thread, when the owning project differs from the
token's project. A project's domain never changes, so successful lookups are
cached for the life of the process.
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


def create_lookup(auth_url, username, password, project_name,
                  user_domain_name, project_domain_name, log):
    """Build a DomainLookup from service credentials, or None."""
    if not (auth_url and username and password):
        return None
    auth = v3.Password(auth_url=auth_url, username=username,
                       password=password, project_name=project_name,
                       user_domain_name=user_domain_name,
                       project_domain_name=project_domain_name)
    return DomainLookup(ks_session.Session(auth=auth), log)
