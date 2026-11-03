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

"""Audit map loading and request path resolution.

This is the parser the audit middleware uses to interpret OpenStack API
paths with an audit map file (``etc/*_audit_map.yaml``), so Pheme resolves
requests exactly the way the CADF audit filter in the same pipeline does::

    from phememiddleware import _auditmap

    resolver = _auditmap.Resolver('/etc/neutron/neutron_audit_map.yaml')
    res = resolver.resolve(request)   # a webob.Request
    if res is not None:
        res.res_spec.el_type_uri      # e.g. 'network/router'
        res.res_id, res.parent_id, res.suffix, res.target_project

Origin: the parser in ``auditmiddleware/_api.py`` of
sapcc/openstack-audit-middleware (``_build_audit_map``, ``_build_res_spec``,
``_build_events``, ``register_resource``, ``_handle_url_prefix``), extracted
into a ``Resolver`` that returns a ``Resolution`` instead of building CADF
events. It matches upstream master d87988b9877a (unchanged in _api.py since
211c39868bd4, the commit it was extracted from).

The code below is the extraction from our former fork
(``auditmiddleware/auditmap.py`` at 0d9540d) unchanged apart from this
docstring, so it diffs cleanly against that file. Against upstream
``_api.py`` it differs only by these renames:

- ``OpenStackAuditMiddleware.create_events`` -> ``Resolver.resolve``
- ``_build_events`` -> ``_walk``, without the ``response`` argument
- ``_create_events(...)`` at the end of the path -> ``Resolution(...)``
- ``_service_type``, ``_service_name``, ``_resource_specs`` ->
  ``service_type``, ``service_name``, ``resource_specs``

To pick up upstream changes, run
``git log d87988b9877a..<new> -- auditmiddleware/_api.py etc/`` in a clone
of upstream. If it prints nothing, only the drift test's UPSTREAM_COMMIT
needs updating; otherwise port the parser change here with the renames
above and refresh the fixtures as ``tests/unit/test_auditmap_drift.py``
describes. That test checks the parser against upstream's own audit maps.
"""

import collections
import re

from oslo_log import log as logging
import yaml

ResourceSpec = collections.namedtuple('ResourceSpec',
                                      ['type_name', 'el_type_name',
                                       'type_uri', 'el_type_uri', 'singleton',
                                       'id_field', 'name_field',
                                       'custom_actions', 'custom_attributes',
                                       'children', 'payloads'])

# The result of resolving a request path:
#   res_spec: ResourceSpec of the target resource type
#   res_id: ID of the target resource from the path (None for collections)
#   parent_id: ID of the parent resource (for child resources)
#   suffix: trailing path segment that is an action or a key (or None)
#   target_project: project ID from the URL prefix, if the prefix has one
Resolution = collections.namedtuple('Resolution',
                                    ['res_spec', 'res_id', 'parent_id',
                                     'suffix', 'target_project'])

# matcher for UUIDs
_UUID_RE = re.compile("[0-9a-f-]+$")


class ConfigError(Exception):
    """Error raised when pyCADF fails to configure correctly."""

    pass


def str_map(param):
    """Ensure that a dictionary contains only string values."""
    if not param:
        return {}

    for k, v in param.items():
        if v is not None and (not isinstance(k, str) or
                              not isinstance(v, str)):
            raise Exception("Invalid config entry %s:%s (not strings)",
                            k, v)

    return param


def payloads_config(param):
    """Create a valid payloads config from the config file contents."""
    if not param:
        return {'enabled': True}

    payloads_config = param.copy()
    payloads_config['enabled'] = bool(param.get('enabled', True))

    return payloads_config


class Resolver(object):
    """Load an audit map and resolve request paths against it.

    Not thread-safe: unknown path segments are registered in the resource
    tree on demand, so use one instance per thread.
    """

    def __init__(self, cfg_file, log=None):
        """Load the audit map file.

        :raises ConfigError: if the file is missing, unreadable or lacks
            ``service_type``, ``prefix`` or ``resources``.
        """
        self._log = log or logging.getLogger(__name__)
        try:
            with open(cfg_file, 'r') as f:
                conf = yaml.safe_load(f)

            self.service_type = conf['service_type']
            self.service_name = conf.get('service_name', self.service_type)
            self._prefix_re = re.compile(conf['prefix'])
            self.resource_specs = self._build_audit_map(conf['resources'])

        except KeyError as err:
            raise ConfigError('Missing config property in %s: %s', cfg_file,
                              str(err))
        except (OSError, yaml.YAMLError) as err:
            raise ConfigError('Error opening config file %s: %s',
                              cfg_file, str(err))

    def resolve(self, request):
        """Resolve a webob request's path.

        :returns: a ``Resolution``, or None if the path does not match the
            audit map prefix or cannot be interpreted.
        """
        # drop the endpoint's path prefix
        path, target_project = self._handle_url_prefix(request)
        if not path:
            self._log.info("ignoring request with path: %s",
                           request.path)
            return None

        # normalize url: remove trailing slash and .json suffix
        path = path[:-1] if path.endswith('/') else path
        path = path[:-5] if path.endswith('.json') else path
        return self._walk(target_project, self.resource_specs,
                          None, None, request, path, 0)

    def _walk(self, target_project, res_spec, res_id, res_parent_id,
              request, path, cursor=0):
        """Parse a request path recursively.

        This method parses the URL path from left to right and builds the
        resource hierarchy from it. The res_spec resource tree is used to
        interpret the path segments properly, e.g. known when a path
        segment represents a resource name, an ID or an attribute name.

        Parameters:
            target_project: target project ID if specified in the path
            res_spec: resource tree constructed from the mapping file
            res_id: ID of the target resource
            res_parent_id: ID of the parent resource of the target resource
            request: incoming request to parse
            path: URL path being parsed
            cursor: current position in the path as it is parsed
        """
        self._log.debug("_build_events: path=%(path)s, cursor=%(cursor)s, "
                        "res_spec=%(res_spec)s, res_id=%(res_id)s",
                        {'path': path, 'cursor': cursor,
                         'res_spec': res_spec, 'res_id': res_id})
        # Check if the end of path is reached and event can be created finally
        if cursor == -1:
            # end of path reached
            return Resolution(res_spec, res_id, res_parent_id, None,
                              target_project)

        # Find next path segment (skip leading / with +1)
        next_pos = path.find('/', cursor + 1)
        # token = scanned token (NOT keystone token)
        token = None
        if next_pos != -1:
            # that means there are more path segments
            token = path[cursor + 1:next_pos]
        elif (cursor + 1) < len(path):
            # last path segment found, not more '/' right of it
            token = path[cursor + 1:]

        # handle the current token
        if isinstance(res_spec, dict):
            # the resource tree node contains a dict => the token contains the
            # top-level resource name
            sub_res_spec = res_spec.get(token)
            if sub_res_spec is None:
                # create resource spec on demand using defaults
                sub_res_spec = self.register_resource(None, token)
                res_spec[token] = sub_res_spec

            return self._walk(target_project, sub_res_spec, None, None,
                              request, path, next_pos)
        elif isinstance(res_spec, ResourceSpec):
            # if the ID is set or it is a singleton, then the next token will
            # be an action or child
            if res_id or res_spec.singleton or token in res_spec.children:
                child_res = res_spec.children.get(token)
                if child_res:
                    # the ID is still the one of the parent (or its parent if
                    # the direct parent is a singleton)
                    return self._walk(target_project, child_res, None,
                                      res_id or res_parent_id, request,
                                      path, next_pos)
            elif _UUID_RE.match(token):
                # next up should be an ID (unless it is a known action)
                return self._walk(target_project, res_spec, token,
                                  res_parent_id, request, path, next_pos)

            if next_pos == -1:
                # last path segment --> token must be an action or a key
                return Resolution(res_spec, res_id, res_parent_id, token,
                                  target_project)
            else:
                # unknown resource name
                # create resource spec on demand ...
                res_spec.children[token] = self.register_resource(
                    res_spec.el_type_uri,
                    token)

                # ... then repeat same call with res_spec now existing
                return self._walk(target_project, res_spec, res_id,
                                  res_parent_id, request, path, cursor)

        self._log.warning(
            "Unexpected continuation of resource path after segment %s: %s",
            token, request.path)
        return None

    def _build_audit_map(self, res_dict, parent_type_uri=None):
        """Build the resourc hierarchy in a dictionary.

        The dictionary maps the resource name used in the REST API's URL
        path to the ResourceSpec descriptor. That descriptor contains all
        the information needed to produce the CADF events from HTTP requests.
        """
        result = {}

        for name, s in res_dict.items():
            res_spec, rest_name = self._build_res_spec(name, parent_type_uri,
                                                       s)

            # ensure that cust
            result[rest_name] = res_spec

        return result

    def _build_res_spec(self, name, parent_type_uri, spec=None):
        """Build the resource descriptor from and entry in the mapping file.

        Parameters:
            name: CADF name of the resource type
            parent_type_uri: type URI of the parent CADF resource type
                             (acting as prefix)
            spec: mapping entry from the config to be parsed
        """
        if not spec:
            spec = {}

        if parent_type_uri:
            pfx = parent_type_uri
        else:
            pfx = self.service_type
        # REST path segment normally equals resource name
        rest_name = spec.get('api_name', name)
        singleton = spec.get('singleton', False)
        type_name = spec.get('type_name')
        # derive the type name used for resource representations in JSON from
        # the REST name
        if not type_name:
            type_name = rest_name.replace('-', '_')
            if type_name.startswith('os_'):
                type_name = type_name[3:]
        type_uri = spec.get('type_uri', pfx + "/" + name)
        el_type_name = None
        el_type_uri = None
        childs_parent_type_uri = None
        if not singleton:
            # derive the name of the individual resource instances (elements)
            # by omitting the last character of the resource name
            el_type_name = spec.get('el_type_name', type_name[:-1])
            el_type_uri = spec.get('el_type_uri', type_uri[:-1])
            childs_parent_type_uri = el_type_uri
        else:
            childs_parent_type_uri = type_uri
        res_spec = ResourceSpec(type_name, el_type_name,
                                type_uri, el_type_uri, singleton,
                                spec.get('custom_id', 'id'),
                                spec.get('custom_name', 'name'),
                                str_map(spec.get('custom_actions')),
                                str_map(spec.get('custom_attributes')),
                                self._build_audit_map(
                                    spec.get('children', {}),
                                    childs_parent_type_uri),
                                payloads_config(spec.get('payloads')))
        return res_spec, rest_name

    def register_resource(self, parent_type_uri, token):
        """Register an unknown resource to avoid missed events.

        The resulting events are a bit raw but contain enough
        information to understand what happened. This allows for
        incremental improvement.
        """
        # Defensive check for None token
        if token is None:
            self._log.warning("unknown resource: None (created on demand)")
            res_name = 'unknown'
            res_dict = {'api_name': 'unknown'}
            sub_res_spec, _ = self._build_res_spec(res_name,
                                                   parent_type_uri,
                                                   res_dict)
            return sub_res_spec

        self._log.warning("unknown resource: %s (created on demand)",
                          token)
        res_name = token.replace('_', '-')
        if res_name.startswith('os-'):
            res_name = res_name[3:]
        res_name = 'X' + res_name
        res_dict = {'api_name': token}
        sub_res_spec, _ = self._build_res_spec(res_name,
                                               parent_type_uri,
                                               res_dict)

        return sub_res_spec

    def _handle_url_prefix(self, request):
        """Process the prefix from the URL path and remove it.

        :param request: incoming request
        :return: URL request path without the leading prefix or None if prefix
        was missing and optional target tenant or None
        """
        g = self._prefix_re.match(request.path)
        if g:
            path = request.path[g.end():]
            project = None
            try:
                # project needs to be specified in a named group in order to
                #  be detected
                project = g.group('project_id')
            except IndexError:
                project = None

            return path, project

        return None, None
