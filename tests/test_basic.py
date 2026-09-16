import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics.finding_builder import FindingBuilder
from analytics.constants import COMPLIANCE_MAP, EXCLUSIONS_MAP
from config import _load_si_from_raw

AD_IDS = [
    "TIER0_PATHS", "ENTERPRISE_ADMIN_PATHS", "KERBEROAST", "ASREP_ROAST",
    "DELEGATION", "ADMIN_TO", "DACL_ABUSE", "GPO_CONTROL", "SID_HISTORY",
    "DCSYNC", "CONSTRAINED_DELEGATION", "RBCD", "PASSWORD_NOT_REQUIRED",
    "REVERSIBLE_ENCRYPTION", "ACCOUNT_OPERATORS", "CROSS_FOREST",
    "PRIVILEGED_GROUPS", "DISABLED_PRIVILEGED",
    "CERT_ABUSE_ESC1", "CERT_ABUSE_ESC3", "SHADOW_CREDENTIALS",
    "DANGEROUS_COMPUTER_ACLS", "NTLM_RELAY_PATHS", "LAPS_GAPS",
    "SQL_LINKED_SERVERS", "DOMAIN_TRUST_ESCALATION",
]

AZ_IDS = [
    "AZ_GLOBAL_ADMIN", "AZ_PRIVILEGED_ROLE_ADMIN", "AZ_HYBRID_IDENTITY_ADMIN",
    "AZ_APPLICATION_ADMIN", "AZ_CLOUD_APP_ADMIN", "AZ_CONDITIONAL_ACCESS_ADMIN",
    "AZ_PRIVILEGED_AUTH_ADMIN", "AZ_SECURITY_ADMIN", "AZ_USER_ACCESS_ADMIN",
    "AZ_ADD_SECRET", "AZ_ADD_OWNER", "AZ_ADD_TO_GROUP", "AZ_CONTRIBUTOR",
    "AZ_OWNER", "AZ_KEY_VAULT_ABUSE", "AZ_MANAGED_IDENTITY", "AZ_EXTERNAL_USER",
    "AZ_EXECUTE_COMMAND", "AZ_RESET_PASSWORD", "AZ_ROLE_ESCALATION",
    "AZ_MFA_GAP", "AZ_CA_POLICY_GAPS", "AZ_PIM_AUDIT", "AZ_SP_OVERSIGHT",
    "AZ_CROSS_TENANT_ACCESS", "AZ_CUSTOM_ROLES", "AZ_PASSWORD_PROTECTION",
    "AZ_LEGACY_AUTH", "AZ_IDENTITY_GOVERNANCE", "AZ_AUTH_METHODS_POLICY",
    "AZ_LOGGING_AUDIT", "AZ_GRAPH_API_ABUSE", "AZ_SYNC_ACCOUNT_COMPROMISE",
    "AZ_PRT_TOKEN_ABUSE", "AZ_CA_BYPASS", "AZ_CROSS_TENANT_AUTH_CHAIN",
    "AZ_DEVICE_JOIN_ABUSE", "AZ_MI_TOKEN_THEFT", "AZ_FUNCTION_KEY_ABUSE",
    "AZ_PAG_ESCALATION",
    "AZ_SP_NO_OWNER", "AZ_ORPHANED_APP", "AZ_OVERCONSENTED_APP",
    "AZ_SP_PRIVILEGED_NO_CA", "AZ_USER_ASSIGNED_MI", "AZ_STALE_SERVICE_PRINCIPAL",
    "AZ_SP_DISABLED_PRIVILEGED", "AZ_SP_SINGLE_OWNER", "AZ_SP_OWNER_DISABLED",
    "AZ_STALE_MANAGED_IDENTITY", "AZ_STALE_DEVICE", "AZ_SP_COMBINED_PRIVILEGES",
    "AZ_SP_OWNER_GROUP", "AZ_SP_LEGACY_TYPE",
]

ALL_IDS = AD_IDS + AZ_IDS


class TestFindingCounts:
    def test_total_findings(self):
        assert len(FindingBuilder.FINDINGS) == 80

    def test_ad_findings(self):
        ad = [f for f in FindingBuilder.FINDINGS if f[3] == "Active Directory"]
        assert len(ad) == 26

    def test_azure_findings(self):
        az = [f for f in FindingBuilder.FINDINGS if f[3] == "Azure"]
        assert len(az) == 54

    def test_all_ids_present(self):
        ids = {f[0] for f in FindingBuilder.FINDINGS}
        for fid in ALL_IDS:
            assert fid in ids, f"Missing finding ID: {fid}"

    def test_ad_prefix(self):
        ids = {f[0] for f in FindingBuilder.FINDINGS if f[3] == "Active Directory"}
        for fid in ids:
            assert fid.startswith("TIER0") or fid.startswith("ENTERPRISE") or \
                   not fid.startswith("AZ_"), f"AD finding has AZ_ prefix: {fid}"

    def test_az_prefix(self):
        ids = {f[0] for f in FindingBuilder.FINDINGS if f[3] == "Azure"}
        for fid in ids:
            assert fid.startswith("AZ_"), f"Azure finding missing AZ_ prefix: {fid}"


class TestFindingBuilder:
    def test_build_returns_dict_with_all_ids(self):
        builder = FindingBuilder()
        result = builder.build({})
        result_ids = {f["id"] for f in result}
        for fid in ALL_IDS:
            assert fid in result_ids, f"build() missing: {fid}"

    def test_build_returns_correct_count(self):
        builder = FindingBuilder()
        result = builder.build({})
        assert len(result) == 80

    def test_build_has_required_keys(self):
        builder = FindingBuilder()
        result = builder.build({})
        for f in result:
            assert "id" in f
            assert "title" in f
            assert "severity" in f
            assert "source" in f
            assert "has_evidence" in f


class TestComplianceMap:
    def test_compliance_map_has_all_ids(self):
        for fid in ALL_IDS:
            assert fid in COMPLIANCE_MAP, f"COMPLIANCE_MAP missing: {fid}"

    def test_compliance_map_has_no_extra(self):
        extra = set(COMPLIANCE_MAP.keys()) - set(ALL_IDS)
        assert not extra, f"COMPLIANCE_MAP has extra keys: {extra}"

    def test_compliance_map_has_expected_frameworks(self):
        expected = {"NIST", "CIS", "ISO 27001", "SA 315", "DPDP"}
        for fid in ALL_IDS:
            entry = COMPLIANCE_MAP[fid]
            for key in expected:
                assert key in entry, f"{fid} missing {key}"


class TestExclusionsMap:
    def test_exclusions_map_has_all_ids(self):
        for fid in ALL_IDS:
            assert fid in EXCLUSIONS_MAP, f"EXCLUSIONS_MAP missing: {fid}"

    def test_exclusions_are_strings(self):
        for fid, exclusions in EXCLUSIONS_MAP.items():
            assert isinstance(exclusions, list), f"{fid} exclusions not a list"
            for ex in exclusions:
                assert isinstance(ex, str), f"{fid} exclusion not a string: {ex}"


class TestSourceIntegrity:
    def test_load_si_from_raw_empty(self):
        assert _load_si_from_raw(None) == {}
        assert _load_si_from_raw({}) == {}

    def test_load_si_from_raw_full(self):
        raw = {
            "_source_integrity": {
                "sh_sha256": "abc123",
                "sh_method": "DCOnly",
                "sh_timestamp": "2026-01-01",
                "ah_sha256": "def456",
                "ah_method": "AzureGlobalAdmin",
                "ah_timestamp": "2026-01-02",
            }
        }
        si = _load_si_from_raw(raw)
        assert si["sh_sha256"] == "abc123"
        assert si["ah_method"] == "AzureGlobalAdmin"
        assert si["sh_timestamp"] == "2026-01-01"

    def test_load_si_from_raw_partial(self):
        raw = {
            "_source_integrity": {
                "sh_sha256": "abc123",
            }
        }
        si = _load_si_from_raw(raw)
        assert si["sh_sha256"] == "abc123"
        assert si["ah_sha256"] is None


class TestEnrichFinding:
    """Each finding type must survive enrich_finding with empty evidence."""

    @pytest.mark.parametrize("fid", ALL_IDS)
    def test_enrich_no_crash(self, fid):
        from analytics.finding_enrichment import enrich_finding
        finding = {
            "id": fid,
            "title": "test",
            "severity": "MEDIUM",
            "source": "Active Directory" if fid in AD_IDS else "Azure",
            "has_evidence": False,
            "mitre": {},
        }
        result = enrich_finding(finding, {})
        assert result["id"] == fid
        assert "impact" in result
        assert "remediation" in result
        assert "compliance" in result
        assert "confidence" in result

    @pytest.mark.parametrize("fid", AZ_IDS)
    def test_enrich_azure_no_crash(self, fid):
        from analytics.finding_enrichment import enrich_finding
        finding = {
            "id": fid,
            "title": "test",
            "severity": "MEDIUM",
            "source": "Azure",
            "has_evidence": False,
            "mitre": {},
        }
        result = enrich_finding(finding, {})
        assert result["id"] == fid
        assert result["source"] == "Azure"
