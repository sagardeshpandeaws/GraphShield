import neo4j.exceptions
from neo4j import GraphDatabase
from neo4j.graph import Node, Relationship, Path
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from collectors.query_registry import get_queries
from analytics.groups import GROUP_QUERY_KEYS, ALL_QUERY_KEYS
from collectors.schema_probe import probe as probe_schema

MAX_FETCH = 100000


def test_connection(uri=None, user=None, password=None):
    uri = uri or NEO4J_URI
    user = user or NEO4J_USER
    password = password or NEO4J_PASSWORD
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            session.run("RETURN 1").single()
        driver.close()
        return True, None
    except neo4j.exceptions.ServiceUnavailable as e:
        return False, f"Neo4j server not reachable at {uri}: {e}"
    except neo4j.exceptions.AuthError as e:
        return False, f"Authentication failed: {e}"
    except neo4j.exceptions.ClientError as e:
        return False, f"Client error: {e}"
    except Exception as e:
        return False, f"Unexpected connection error: {e}"


def _serialize(value):
    if isinstance(value, Node):
        return {"labels": list(value.labels), **dict(value)}
    if isinstance(value, Relationship):
        return {"type": value.type, **dict(value)}
    if isinstance(value, Path):
        return {
            "nodes": [_serialize(n) for n in value.nodes],
            "relationships": [_serialize(r) for r in value.relationships],
        }
    if isinstance(value, list):
        return [_serialize(v) for v in value]
    if isinstance(value, dict):
        return {k: _serialize(v) for k, v in value.items()}
    return value


class BloodHoundCollector:
    def __init__(self, uri=None, user=None, password=None):
        self.driver = GraphDatabase.driver(
            uri or NEO4J_URI, auth=(user or NEO4J_USER, password or NEO4J_PASSWORD)
        )
        self.errors = []

    def run(self, query):
        output = []
        with self.driver.session() as session:
            result = session.run(query)
            for record in result:
                output.append({k: _serialize(v) for k, v in dict(record).items()})
                if len(output) >= MAX_FETCH:
                    break
        return output

    def _run_scalar(self, query):
        with self.driver.session() as session:
            result = session.run(query)
            return list(result)[0][0] if result else 0

    def _collect_env_stats(self):
        """Query Neo4j for actual environment node counts (AD + Azure)."""
        env = {}
        with self.driver.session() as session:
            try:
                env["total_users"] = list(session.run(
                    "MATCH (n:User) WHERE n.enabled = true RETURN count(n) AS c"))[0]["c"]
                env["total_computers"] = list(session.run(
                    "MATCH (n:Computer) RETURN count(n) AS c"))[0]["c"]
                env["total_groups"] = list(session.run(
                    "MATCH (n:Group) RETURN count(n) AS c"))[0]["c"]
                env["total_gpos"] = list(session.run(
                    "MATCH (n:GPO) RETURN count(n) AS c"))[0]["c"]
                env["total_ous"] = list(session.run(
                    "MATCH (n:OU) RETURN count(n) AS c"))[0]["c"]
                env["total_domains"] = list(session.run(
                    "MATCH (n:Domain) RETURN count(n) AS c"))[0]["c"]
                env["servers"] = list(session.run(
                    "MATCH (n:Computer) WHERE toUpper(n.operatingsystem) CONTAINS 'SERVER' RETURN count(n) AS c"))[0]["c"]
                env["domain_controllers"] = list(session.run(
                    "MATCH (n:Computer)-[:DCFor]->(:Domain) RETURN count(n) AS c"))[0]["c"]
                env["service_accounts"] = list(session.run(
                    "MATCH (n:User) WHERE n.hasspn = true AND n.enabled = true RETURN count(n) AS c"))[0]["c"]
                env["trusts"] = list(session.run(
                    "MATCH ()-[r:CrossForestTrust]->() RETURN count(r) AS c"))[0]["c"]
                env["domains"] = [r["name"] for r in session.run(
                    "MATCH (n:Domain) RETURN n.name AS name ORDER BY name")]
                env["forests"] = self._collect_per_domain_stats(session)
                # ── Azure environment stats ─────────────────────
                env["azure_tenants"] = [r["name"] for r in session.run(
                    "MATCH (n:AZTenant) RETURN n.name AS name ORDER BY name")]
                env["azure_users"] = list(session.run(
                    "MATCH (n:AZUser) RETURN count(n) AS c"))[0]["c"]
                env["azure_groups"] = list(session.run(
                    "MATCH (n:AZGroup) RETURN count(n) AS c"))[0]["c"]
                env["azure_service_principals"] = list(session.run(
                    "MATCH (n:AZServicePrincipal) RETURN count(n) AS c"))[0]["c"]
                env["azure_managed_identities"] = list(session.run(
                    "MATCH (n:AZManagedIdentity) RETURN count(n) AS c"))[0]["c"]
                env["azure_applications"] = list(session.run(
                    "MATCH (n:AZApplication) RETURN count(n) AS c"))[0]["c"]
                env["azure_key_vaults"] = list(session.run(
                    "MATCH (n:AZKeyVault) RETURN count(n) AS c"))[0]["c"]
                env["azure_vms"] = list(session.run(
                    "MATCH (n:AZVM) RETURN count(n) AS c"))[0]["c"]
                env["azure_subscriptions"] = list(session.run(
                    "MATCH (n:AZSubscription) RETURN count(n) AS c"))[0]["c"]
                env["azure_tenants_detail"] = self._collect_per_tenant_stats(session)
            except neo4j.exceptions.ServiceUnavailable as e:
                self.errors.append(f"Env stats connection lost: {e}")
            except neo4j.exceptions.SessionExpired as e:
                self.errors.append(f"Env stats session expired: {e}")
            except Exception as e:
                self.errors.append(f"Env stats error: {e}")
        return env

    def _collect_per_tenant_stats(self, session):
        """Collect per-tenant Azure stats."""
        tenants = list(session.run(
            "MATCH (t:AZTenant) RETURN t.name AS name, t.objectid AS tid ORDER BY t.name"))
        if not tenants:
            return []
        result = []
        for t in tenants:
            tid = t["tid"]
            users = list(session.run(
                "MATCH (u:AZUser) WHERE u.tenantid = $tid RETURN count(u) AS c", tid=tid))[0]["c"]
            groups = list(session.run(
                "MATCH (g:AZGroup) WHERE g.tenantid = $tid RETURN count(g) AS c", tid=tid))[0]["c"]
            sps = list(session.run(
                "MATCH (s:AZServicePrincipal) WHERE s.tenantid = $tid RETURN count(s) AS c", tid=tid))[0]["c"]
            mis = list(session.run(
                "MATCH (m:AZManagedIdentity) WHERE m.tenantid = $tid RETURN count(m) AS c", tid=tid))[0]["c"]
            apps = list(session.run(
                "MATCH (a:AZApplication) WHERE a.tenantid = $tid RETURN count(a) AS c", tid=tid))[0]["c"]
            global_admins = list(session.run(
                "MATCH (n)-[:AZGlobalAdmin]->(t:AZTenant) WHERE t.objectid = $tid "
                "RETURN count(DISTINCT n) AS c", tid=tid))[0]["c"]
            result.append({
                "name": t["name"],
                "tenant_id": tid,
                "metrics": {
                    "users": users,
                    "groups": groups,
                    "service_principals": sps,
                    "managed_identities": mis,
                    "applications": apps,
                    "global_admins": global_admins,
                },
            })
        return result

    def _collect_per_domain_stats(self, session):
        """Collect per-domain stats and group into forests."""
        # Get all domains with their SID prefixes
        domains_raw = list(session.run(
            "MATCH (d:Domain) RETURN d.name AS name, d.objectid AS sid ORDER BY d.name"))
        if not domains_raw:
            return []

        domain_info = []
        for dr in domains_raw:
            sid_prefix = dr["sid"]
            domain_name = dr["name"]
            # Per-domain queries scoped by objectid prefix
            users = list(session.run(
                "MATCH (n:User) WHERE n.enabled = true AND n.objectid STARTS WITH $sid RETURN count(n) AS c",
                sid=sid_prefix))[0]["c"]
            computers = list(session.run(
                "MATCH (n:Computer) WHERE n.objectid STARTS WITH $sid RETURN count(n) AS c",
                sid=sid_prefix))[0]["c"]
            servers = list(session.run(
                "MATCH (n:Computer) WHERE n.objectid STARTS WITH $sid AND toUpper(n.operatingsystem) CONTAINS 'SERVER' RETURN count(n) AS c",
                sid=sid_prefix))[0]["c"]
            dcs = list(session.run(
                "MATCH (n:Computer)-[:DCFor]->(d:Domain) WHERE d.objectid = $sid RETURN count(n) AS c",
                sid=sid_prefix))[0]["c"]
            groups = list(session.run(
                "MATCH (n:Group) WHERE n.objectid STARTS WITH $sid RETURN count(n) AS c",
                sid=sid_prefix))[0]["c"]
            tier0_members = list(session.run(
                "MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' AND g.objectid STARTS WITH $sid "
                "MATCH (u:User)-[:MemberOf]->(g) WHERE u.enabled = true RETURN count(u) AS c",
                sid=sid_prefix))[0]["c"]
            service_accounts = list(session.run(
                "MATCH (n:User) WHERE n.hasspn = true AND n.enabled = true AND n.objectid STARTS WITH $sid RETURN count(n) AS c",
                sid=sid_prefix))[0]["c"]
            domain_info.append({
                "name": domain_name,
                "sid": sid_prefix,
                "users": users,
                "computers": computers,
                "servers": servers,
                "domain_controllers": dcs,
                "child_domain_controllers": 0,
                "groups": groups,
                "tier0_accounts": tier0_members,
                "service_accounts": service_accounts,
            })

        # Group domains into forests by name suffix
        sorted_domains = sorted(domain_info, key=lambda d: d["name"])
        forests = {}
        assigned = set()
        for d in sorted_domains:
            if d["name"] in assigned:
                continue
            # Find root: the shortest domain name that others end with
            root_name = d["name"]
            members = [d]
            assigned.add(d["name"])
            for other in sorted_domains:
                if other["name"] in assigned:
                    continue
                if other["name"].upper().endswith("." + root_name.upper()):
                    members.append(other)
                    assigned.add(other["name"])
            forest_key = root_name
            forests[forest_key] = members

        # Build forest breakdown
        forest_breakdown = []
        for forest_name, domains_in_forest in forests.items():
            forest_metrics = {
                "users": 0,
                "computers": 0,
                "servers": 0,
                "domain_controllers": 0,
                "child_domain_controllers": 0,
                "groups": 0,
                "tier0_accounts": 0,
                "service_accounts": 0,
            }
            for dm in domains_in_forest:
                for k in forest_metrics:
                    forest_metrics[k] += dm.get(k, 0)
            forest_breakdown.append({
                "name": forest_name,
                "domains": [dm["name"] for dm in domains_in_forest],
                "metrics": forest_metrics,
            })

        # Compute total trusts per forest (cross-forest relationships involving any domain in the forest)
        for fb in forest_breakdown:
            forest_domain_names = fb["domains"]
            trust_count = 0
            for dr in list(session.run(
                "MATCH (d:Domain)-[r:CrossForestTrust]->(t:Domain) "
                "RETURN d.name AS src, t.name AS tgt"
            )):
                src = dr["src"]
                tgt = dr["tgt"]
                if src in forest_domain_names or tgt in forest_domain_names:
                    trust_count += 1
            fb["metrics"]["trusts"] = trust_count

        return forest_breakdown

    def _is_large_query(self, name):
        """Queries known to produce large result sets in dense environments."""
        return name in (
            "dacl_abuse", "admin_to", "tier0_paths", "enterprise_admin_paths",
            "gpo_control", "rbcd", "az_contributor", "az_owner",
        )

    def _safe_run(self, name, query):
        try:
            result = self.run(query)
            print("[+]", name, len(result))
            return result
        except neo4j.exceptions.ServiceUnavailable as e:
            msg = f"Connection lost during {name}: {e}"
            print("[-]", msg)
            self.errors.append(msg)
        except neo4j.exceptions.SessionExpired as e:
            msg = f"Session expired for {name}: {e}"
            print("[-]", msg)
            self.errors.append(msg)
        except neo4j.exceptions.CypherSyntaxError as e:
            msg = f"Query syntax error in {name}: {e}"
            print("[-]", msg)
            self.errors.append(msg)
        except neo4j.exceptions.ClientError as e:
            msg = f"Query rejected for {name}: {e}"
            print("[-]", msg)
            self.errors.append(msg)
        except Exception as e:
            msg = f"Unexpected error in {name}: {e}"
            print("[-]", msg)
            self.errors.append(msg)
        return []

    def collect(self, selected_groups=None):
        self.errors = []
        schema = probe_schema(self.driver, selected_groups)
        for w in schema.warnings:
            self.errors.append(f"[schema] {w}")
        for e in schema.errors:
            self.errors.append(f"[schema] {e}")
        if selected_groups is not None:
            active_keys = set()
            for g in selected_groups:
                active_keys.update(GROUP_QUERY_KEYS.get(g, set()))
        else:
            active_keys = ALL_QUERY_KEYS
        all_queries = get_queries()
        data = {}
        for name, query in all_queries.items():
            if name not in active_keys:
                continue
            data[name] = self._safe_run(name, query)
        data["_env_stats"] = self._collect_env_stats()
        print("[+] _env_stats collected")
        return data

    def close(self):
        self.driver.close()
