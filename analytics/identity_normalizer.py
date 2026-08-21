class IdentityNormalizer:
    DEFAULT_AD_OBJECTS = {
        "users": [],
        "groups": [],
        "computers": [],
        "gpos": [],
        "organizational_units": [],
    "domains": [],
    "service_principals": [],
    "managed_identities": [],
    "applications": [],
    "key_vaults": [],
    "tenants": [],
    "subscriptions": [],
    "resource_groups": [],
    "management_groups": [],
    "relationships": [],
}

    def normalize(self, findings):
        normalized = []
        for item in findings:
            clean_item = dict(item)  # keep everything, including 'evidence'
            clean_item["id"] = item.get("id", "UNKNOWN")
            clean_item["title"] = item.get("title", "Unknown Finding")
            clean_item["severity"] = (item.get("severity") or "LOW").upper()
            clean_item["source"] = item.get("source", "Active Directory")
            clean_item["mitre"] = item.get("mitre") or {}
            clean_item["impact"] = item.get("impact", "")
            clean_item["remediation"] = item.get("remediation") or []
            clean_item["detection"] = item.get("detection") or []
            clean_item["ad_objects"] = {**self.DEFAULT_AD_OBJECTS, **(item.get("ad_objects") or {})}
            clean_item["compliance"] = item.get("compliance") or {}
            clean_item["has_evidence"] = item.get("has_evidence", False)
            normalized.append(clean_item)
        return normalized