# Proof Reports (synthetic sample data)

`scripts/generate_proof_reports.py` produces a complete, self-contained set of
GraphShield reports for **every assessment group** without a live Neo4j, BloodHound
or AzureHound dataset, and without a client engagement. It exists to demonstrate
that the whole analysis and reporting path works end to end.

All data is **synthetic and clearly labelled as such** in the reports
(`Data Source: Sample Data (Synthetic)`). These artifacts are for proof of
functioning and demos only — they are not a real assessment and must never be
presented as one.

## Usage

```powershell
# default client "1st_Client", default output
python scripts\generate_proof_reports.py

python scripts\generate_proof_reports.py --client "Acme_Corp" --version v2
python scripts\generate_proof_reports.py --output D:\temp\proof
```

Output lands in `outputs\<client>\proof\<group>\`, plus a `proof_manifest.json`
at the `proof\` root.

### Executive briefs

Briefs are **deterministic by default** so a proof run is reproducible: same
input, same bytes. A real Ollama narrative is opt-in because `llama3.1` takes
several minutes per group and does not reliably follow the required section
format:

```powershell
python scripts\generate_proof_reports.py --ai-groups nhi_governance
```

Pass a comma-separated list to brief several groups live. Any Ollama error falls
back to the deterministic brief, so the run never fails on a missing model.

## What it generates

Seven artifacts per assessment group, six groups = **42 files**:

| Artifact | Contents |
|----------|----------|
| `*_Assessment_Report_*.pdf` | Full client-facing assessment report |
| `*_Engineering_*.xlsx` | Engineering workbook (Findings Register, chains, …) |
| `*_Findings_*.csv` | Flat findings register for ticketing / SIEM |
| `*_Evidence_*.json` | Machine-readable evidence, including `nhi_correlation` |
| `*_Attack_Graph_*.html` | Interactive attack-chain graph (pyvis) |
| `*_Executive_Brief_*.pdf` | AI/management summary |
| `*_Package_*.zip` | The six files above, packaged for delivery |

Groups: `ad_core`, `ad_attack`, `az_core`, `az_zt_review`, `az_arch_sim`,
`nhi_governance`.

`proof_manifest.json` records, per group, the finding / chain / risk counts, the
brief source, and a **SHA-256 and byte size for every artifact** so a delivered
proof set can be verified as untampered.

## How it works

The script does not reimplement the pipeline. It builds synthetic raw query
results and then calls exactly the production path, in order:

```
FindingBuilder().build(raw, selected_groups=[group])   # the 80 declared finding types
 -> enrich_finding(f, raw)                             # severity, impact, MITRE, ad_objects
 -> IdentityNormalizer().normalize(...)                # canonical identity strings
 -> load_lifecycle_feed(...)                           # NHI group only
 -> build_lifecycle_findings(...) + correlate_nhi_sources(...)
 -> RiskEngine().calculate(active_evidence)
 -> AttackChainBuilder / HybridAttackChain
 -> export_pdf / export_excel / export_csv / export_json / export_ai_pdf
    / create_attack_graph / create_zip
```

Because it is the same code as the app, a change that breaks report generation
breaks this script too — which is what makes it useful as a proof harness.

## Two-source NHI proof

`nhi_governance` is the only assessment that merges a second data source. The
inline dummy feed contains three workload identities sharing Entra object ids
with the synthetic graph data:

- **2 identities appear in both sources** — corroborated, listed in the
  `Corroboration (NHI)` column of the CSV, in column 23 of the Excel Findings
  Register, as a `Corroboration (NHI)` row in the assessment PDF, and as
  `nhi_correlation` in the evidence JSON.
- **1 identity exists only in the logs** — reported as
  `Neo4j: not found | Logs: …` rather than a blank cell, because "the logs
  found a workload posture data never contained" is a real result.

Correlation is strictly NHI-scoped (`group == nhi_governance` plus `AZ_LC_*`), so
the other five assessments are unchanged and contain no corroboration data at
all. See [ASSESSMENT_SCOPE.md](ASSESSMENT_SCOPE.md).

## Notes

- The report date is pinned (`2026-09-26`) so repeated runs are comparable.
- Re-running overwrites in place. Each file is written to a temp sibling and
  atomically moved into place, which avoids the intermittent `PermissionError`
  Windows raises when an AV scanner holds a just-written report open.
- A handful of policy / architecture-simulation findings have empty
  `ad_objects`: those finding types have no object-extraction branch, so there
  is no entity list to populate. This is expected, not a data gap.
