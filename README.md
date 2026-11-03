# pheme-middleware

A paste filter for OpenStack APIs that publishes a CloudEvent to NATS JetStream for every successful change to a Pheme kind. Pheme is the watch API prototype; the event contract is `docs/event-contract.md` in the pheme-build repo. It resolves request paths with the audit middleware's audit map parser, copied into `phememiddleware/_auditmap.py`, so it reads the same `*_audit_map.yaml` files the same way. It is independent of the CADF audit filter, changes nothing about it and does not need it installed.

Kinds (neutron): `network.router`, `network.port`, `network.bgpvpn`, `network.bgpvpn_router_association`, `network.bgpvpn_network_association`, `network.bgpvpn_port_association`.

## Configuration

```ini
[filter:pheme]
paste.filter_factory = phememiddleware:filter_factory
audit_map_file = /etc/neutron/neutron_audit_map.yaml
nats_url = nats://nats:4222
nats_user = neutron
# nats_password, region (local), queue_size (1000), publish_timeout (2.0),
# enabled (true), service_type (from the audit map), owner_cache_size (10000),
# metrics_enabled (false), stats_file, keystone_auth_url, keystone_username,
# keystone_password, keystone_project_name (service),
# keystone_user_domain_name / keystone_project_domain_name (Default),
# keystone_region_name
```

Each option falls back to an environment variable `PHEME_<OPTION>`. Place the filter after `keystonecontext` (or `authtoken`).

## Behaviour

- **Request thread:**
  - Skips GET/HEAD/OPTIONS and non-2xx responses.
  - Records the raw facts: method, path, status, token project/domain/user/roles, request ID, and the response body bytes.
  - Calls `put_nowait` on a bounded, lock-free buffer.
  - A full buffer drops the event (`dropped.buffer_full`). It never waits, retries or raises into the request.
- **Publisher thread:** a daemon OS thread with its own asyncio loop and a nats-py client.
  - Resolves the target and builds the structured CloudEvent (sdk-python).
  - Publishes to `pheme.events.<service>.<kind>` with `Nats-Msg-Id` set to the event `id` and a short timeout.
  - Failures are dropped and counted (`dropped.publish_failed`) while it reconnects. After `resolve_after` seconds disconnected it resolves the NATS hostname again.
- **Event content:**
  - Bulk creates (for example `POST /ports` with a list) produce one event per object.
  - Router member actions (`add_router_interface`, `remove_router_interface`) become `network.router.updated` with the `subaction` extension and `data: null`.

### Owners and deletes

- **Owner:** the object's own `project_id`. A port belongs to its own project, not to the network owner.
- **No `project_id` in the object** (BGPVPN associations): the parent BGPVPN's owner, taken from the cache or a Neutron lookup with the service credentials.
- **Last resort:** the token's project, but only for non-admin tokens. A non-admin can only change its own project; an admin can act on any.
- **Domain:** from the token when the owner is the token's project, otherwise a Keystone lookup. Both lookups are cached forever (owners and domains never change).

A DELETE has no response body, and Neutron's legacy controller doesn't expose the deleted object. If this worker built an event for the resource before (an LRU of owner and last state), the delete gets the full path and the last state. Otherwise it is a contract **delete by ID**:

- subject `/by-id/<service>/<kind>/<id>`
- the `resourceid` extension
- no `projectid`/`domainid`
- `data: null`

Pheme resolves the path itself.

### What `data` holds

`data` is the inner object exactly as it appears in the response body; the middleware never merges or adds fields. Some Neutron responses are partial. networking-bgpvpn's association create/update responses lack `project_id`/`tenant_id` and some fields that a GET returns. Member actions return no router object at all, so their events carry `data: null`. Pheme then holds what the response held until the next full update; neutron-resync corrects that drift periodically. Children removed by a cascading parent delete get no event of their own: Pheme removes a deleted parent's descendants.

### Counters

`PhemeMiddleware.get_counters()` gives `published`, `by_id_delete` and `dropped.<reason>`. The reasons are `buffer_full`, `publish_failed`, `owner_unknown`, `domain_unknown`, `unresolved`, `build_failed` and `capture_failed`. With `metrics_enabled`, the same counters go to statsd (`openstack_pheme.events_*`), and drops are logged as warnings.

With `stats_file` (for example `/var/lib/pheme-stats/neutron-{pid}.json`), the publisher thread also writes all counters as JSON (`{"pid", "time", "counters"}`) to that file once a second, replaced atomically. `{pid}` gives each uwsgi worker its own file; a reader sums the files it finds fresh. Nothing is served over the API: the file is only visible to whoever can read that path (the local demo console mounts it read-only).

### Eventlet and uwsgi

Neutron's API monkey-patches with eventlet, under both the eventlet server and uwsgi `neutron-api`. A greenthread publisher would starve under uwsgi between requests, so the publisher is a real OS thread: `eventlet.patcher.original('threading')`, a real selector, and NATS names resolved with the unpatched resolver. The thread starts lazily in each worker; a pid check handles forked workers. uwsgi needs Python threads (`enable-threads = true`; uWSGI 2.0.31 always has them on).

## Audit map parser

`phememiddleware/_auditmap.py` is the path parser from `auditmiddleware/_api.py` in [sapcc/openstack-audit-middleware](https://github.com/sapcc/openstack-audit-middleware), extracted into a `Resolver` that returns the resource spec, ID, parent ID, suffix and URL project instead of building CADF events. It matches upstream master `d87988b9877a`. Keep the code identical to the upstream logic so the two filters in one pipeline agree on every path.

The code is the extraction from our former fork (`auditmiddleware/auditmap.py` at `0d9540d`) unchanged apart from the module docstring, so it diffs cleanly against that file. Against upstream `_api.py` it differs only by these renames:

- `OpenStackAuditMiddleware.create_events` → `Resolver.resolve`
- `_build_events` → `_walk`, without the `response` argument
- `_create_events(...)` at the end of the path → `Resolution(...)`
- `_service_type`, `_service_name`, `_resource_specs` → `service_type`, `service_name`, `resource_specs`

`tests/unit/test_auditmap_drift.py` resolves real Neutron, Cinder and Nova paths against upstream's own `etc/*_audit_map.yaml` (copied into `tests/unit/upstream/`) and pins the results that upstream's parser gives. To pick up upstream changes, run `git log d87988b9877a..<new> -- auditmiddleware/_api.py etc/` in a clone of upstream. If it prints nothing, only `UPSTREAM_COMMIT` in the drift test needs updating. Otherwise port the parser change into `_auditmap.py` with the renames above and refresh the fixtures as described at the top of that test.

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e . -r test-requirements.txt
stestr run
```

Or run `tox -e py3,pep8`.

`test_nats` needs a nats-server. It uses `PHEME_TEST_NATS_URL`, a `nats-server` binary, or docker (`nats:2.10-alpine`), and skips if none of them is available.
