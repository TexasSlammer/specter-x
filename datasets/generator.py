"""Northstar Health — synthetic org + event generator for SPECTER X.

Deterministic (seed=42). Produces:
  datasets/org.json                 entities + grants (the permission graph source)
  datasets/normal/baseline.jsonl    two weeks of normal activity (controls inside)
  datasets/attack-scenarios/*.jsonl labeled compromise sequences
  datasets/ground_truth.json        labels for evaluation (paths, detections, scores)
  datasets/provenance.json          full provenance, no external data

All identities, resources and events are fictional. City coordinates are
approximations used for distance math in D3.
"""
from __future__ import annotations

import json
import random
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 42
random.seed(SEED)
ROOT = Path(__file__).resolve().parent
GEN_VERSION = "generator-1.0.0"

# Approximate city coordinates (lat, lon) for impossible-travel math.
CITY = {
    "San Antonio": (29.42, -98.49), "Austin": (30.27, -97.74),
    "Dallas": (32.78, -96.80), "Houston": (29.76, -95.37),
    "Berlin": (52.52, 13.40), "Lagos": (6.52, 3.37),
}

_counter = [0]

def eid() -> str:
    # Deterministic ids: same seed + same call sequence => byte-identical datasets.
    _counter[0] += 1
    return "evt-" + hashlib.md5(f"{SEED}:{_counter[0]}".encode()).hexdigest()

def ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------- entities
identities, grants, resources = [], [], []

def user(uid, name, dept, privileged=False, kind="user", city="San Antonio"):
    identities.append({"identity_id": uid, "display_name": name, "kind": kind,
                       "department": dept, "privileged": privileged, "city": city})
    return uid

def grant(kind, from_id, to_id, resource_id=None, scopes=None, conditions=None,
          verified=True, gid=None):
    _counter[0] += 1
    grants.append({"grant_id": gid or "grt-" + hashlib.md5(f"{SEED}:g:{_counter[0]}".encode()).hexdigest()[:10], "kind": kind,
                   "from_id": from_id, "to_id": to_id, "resource_id": resource_id,
                   "scopes": scopes, "conditions": conditions, "verified": verified})

def res(rid, label, sensitivity, kind="cloud_resource"):
    resources.append({"resource_id": rid, "label": label, "kind": kind,
                      "sensitivity": sensitivity})

# People (all fictional)
u_exec1   = user("usr-alvarez.exec",  "R. Alvarez",  "Executive",   privileged=True)
u_exec2   = user("usr-okafor.exec",   "C. Okafor",   "Executive",   privileged=True)
u_it1     = user("usr-flores",        "M. Flores",   "IT",          privileged=True)
u_it2     = user("usr-chen",          "K. Chen",     "IT",          privileged=True)
u_marcus  = user("usr-marcus.webb",   "M. Webb",     "IT",          privileged=True)
u_billing = [user(f"usr-billing.{n}", n.title(), "Billing") for n in ("reyes", "dalton", "kim", "patel", "moore", "santos")]
u_dana    = u_billing[0]  # dana.reyes — victim in scenario 1
u_clin    = [user(f"usr-clin.{i:02d}", f"Clinician {i:02d}", "Clinical") for i in range(1, 13)]
u_contract= [user("usr-connor.wells", "T. Wells", "Contractor"), user("usr-lena.ortiz", "L. Ortiz", "Contractor")]
u_svc_report = user("svc-reporting",  "Reporting Service", "IT", kind="service_account")
u_svc_backup = user("svc-ehr-backup", "EHR Backup Job",   "IT", kind="service_account")
u_svc_mail   = user("svc-mail-sync",  "Mail Sync",        "IT", kind="service_account")
u_svc_scan   = user("svc-scan",       "Vuln Scanner",     "IT", kind="service_account")

# Groups, apps, roles, resources
GRP = {"it_admins": "grp-it-admins", "billing": "grp-billing", "clinicians": "grp-clinicians",
       "executives": "grp-executives", "oncall": "grp-exec-oncall", "contractors": "grp-contractors"}
APPS = {"mail_sync": "app-mail-sync", "office_helper": "app-office-helper",
        "reporting": "app-reporting", "payroll_sync": "app-payroll-sync"}
RESOURCES = {"ehr": "res-ehr-database", "billing_exp": "res-billing-exports",
             "backup": "res-backup-vault", "hr": "res-hr-portal",
             "marketing": "res-marketing-site", "wiki": "res-wiki",
             "analytics": "res-analytics", "payroll": "res-payroll-db"}
ROLE_BREAKGLASS = "role-breakglass"

res(RESOURCES["ehr"], "EHR Database (PHI)", "sensitive", "database")
res(RESOURCES["billing_exp"], "Billing Exports Bucket", "sensitive", "storage")
res(RESOURCES["backup"], "Backup Vault", "sensitive", "storage")
res(RESOURCES["hr"], "HR Portal", "sensitive", "webapp")
res(RESOURCES["marketing"], "Marketing Site", "public", "webapp")
res(RESOURCES["wiki"], "Internal Wiki", "internal", "webapp")
res(RESOURCES["analytics"], "Analytics Warehouse", "internal", "database")
res(RESOURCES["payroll"], "Payroll Database", "sensitive", "database")

def member(uid, grp, gid=None):
    grant("GROUP_MEMBER", uid, grp, gid=gid)

for uid in (u_it1, u_it2, u_marcus):
    member(uid, GRP["it_admins"])
    grant("DIRECTORY_ROLE", uid, "role-global-admin")
for uid in u_billing:
    member(uid, GRP["billing"])
for uid in u_clin:
    member(uid, GRP["clinicians"])
for uid in u_contract:
    member(uid, GRP["contractors"])
member(u_exec1, GRP["executives"])
member(u_exec2, GRP["oncall"])            # exec2 reachable ONLY through nesting
member(GRP["oncall"], GRP["executives"])   # group nesting: oncall ⊂ executives (depth 2)

# Grants — the heart of the permission model
grant("IDENTITY_POLICY_ALLOW", GRP["billing"],   RESOURCES["billing_exp"], conditions={"time_window": "00:00-23:59"})
grant("IDENTITY_POLICY_ALLOW", GRP["billing"],   RESOURCES["analytics"],   conditions={"time_window": "08:00-18:00"})
grant("IDENTITY_POLICY_ALLOW", GRP["it_admins"], RESOURCES["ehr"])
grant("IDENTITY_POLICY_ALLOW", GRP["it_admins"], RESOURCES["backup"])
grant("IDENTITY_POLICY_ALLOW", GRP["executives"], RESOURCES["hr"])
grant("IDENTITY_POLICY_DENY",  u_contract[0],    RESOURCES["hr"], gid="grt-deny-contractor-hr")
grant("IDENTITY_POLICY_DENY",  u_svc_mail,       RESOURCES["ehr"], gid="grt-deny-mailsvc-ehr")
grant("IDENTITY_POLICY_ALLOW", GRP["contractors"], RESOURCES["marketing"])
grant("IDENTITY_POLICY_ALLOW", GRP["contractors"], RESOURCES["wiki"])
grant("RESOURCE_POLICY",       RESOURCES["backup"], u_svc_backup, gid="grt-rp-backup-svc")
grant("TRUST_ASSUME",          GRP["it_admins"],  ROLE_BREAKGLASS, conditions={"asn_type_in": ["corporate", "vpn"]})
grant("IDENTITY_POLICY_ALLOW", ROLE_BREAKGLASS,  RESOURCES["backup"], gid="grt-breakglass-backup")
grant("APP_CONSENT",           GRP["clinicians"], APPS["mail_sync"], scopes=["Mail.Read"], verified=True)
grant("APP_CONSENT",           GRP["billing"],    APPS["reporting"], scopes=["Reports.Read"], verified=True)
grant("APP_CONSENT",           u_dana,            APPS["office_helper"], scopes=["Files.ReadWrite.All"], verified=False, gid="grt-consent-office-helper")
grant("APP_CONSENT",           GRP["it_admins"],  APPS["payroll_sync"], scopes=["Files.ReadWrite.All"], verified=True)

# Scope -> resource reachability mapping (documented subset, CONTRACTS §2)
SCOPE_RESOURCES = {"Files.ReadWrite.All": [RESOURCES["billing_exp"], RESOURCES["payroll"]],
                   "Mail.ReadWrite": [RESOURCES["wiki"]]}
org = {"org": "Northstar Health", "seed": SEED, "generator": GEN_VERSION,
       "identities": identities, "groups": GRP, "apps": APPS,
       "roles": {"breakglass": ROLE_BREAKGLASS}, "resources": resources,
       "grants": grants, "scope_resources": SCOPE_RESOURCES,
       "cities": CITY}

# ---------------------------------------------------------------- events
events: list[dict] = []
DEV = {}  # identity -> known devices

def dev(uid, n=1):
    DEV.setdefault(uid, [f"dev-{uid.split('-', 1)[1]}-{i}" for i in range(1, n + 1)])
    return DEV[uid]

def ev(source, type_, when, identity, **attrs):
    e = {"event_id": eid(), "source": source, "type": type_,
         "timestamp": ts(when), "identity_id": identity, "attributes": attrs, "raw": {}}
    events.append(e)
    return e

BASE = datetime(2026, 10, 19, 8, 0, tzinfo=timezone.utc)  # baseline Monday
WORKDAYS = [BASE + timedelta(days=d) for d in range(12) if (BASE + timedelta(days=d)).weekday() < 5]

def baseline():
    # staff: one success signin per workday from known device
    for uid in (u_exec1, u_exec2, u_it1, u_it2, u_marcus, *u_billing, *u_clin, *u_contract):
        ds = dev(uid, 2)
        for i, day in enumerate(WORKDAYS):
            hour = random.choice([7, 8, 8, 9, 10])
            ev("entra", "signin", day.replace(hour=hour, minute=random.randint(0, 55)),
               uid, ip=f"198.51.100.{random.randint(2, 250)}", device_id=ds[i % 2],
               city="San Antonio", country="US", asn_type="residential", result="success")
    # VPN control: IT staff sometimes on VPN from new-ish IPs — must NOT alert (D2 FP rule)
    for day in WORKDAYS[::3]:
        ev("entra", "signin", day.replace(hour=20, minute=30), u_it1,
           ip=f"203.0.113.{random.randint(2, 250)}", device_id=dev(u_it1)[0],
           city="San Antonio", country="US", asn_type="vpn", result="success")
    # clinicians get a laptop refresh mid-baseline (new device, residential -> no alert)
    ev("entra", "signin", WORKDAYS[6].replace(hour=9, minute=12), u_clin[3],
       ip="198.51.100.77", device_id="dev-clin.04-NEW", city="Austin", country="US",
       asn_type="residential", result="success")
    # service accounts: batch runs (api_call, no interactive signin) from fixed IP — control for D6
    for day in WORKDAYS:
        ev("cloudtrail", "api_call", day.replace(hour=1, minute=15), u_svc_backup,
           ip="198.51.100.9", resource_id=RESOURCES["backup"], operation="snapshot")
        ev("cloudtrail", "api_call", day.replace(hour=2, minute=0), u_svc_mail,
           ip="198.51.100.10", resource_id=RESOURCES["wiki"], operation="sync")
        ev("cloudtrail", "api_call", day.replace(hour=3, minute=45), u_svc_scan,
           ip="198.51.100.11", resource_id=RESOURCES["marketing"], operation="scan")
    # verified read-only consent — control for D4
    ev("oauth", "consent_granted", WORKDAYS[2].replace(hour=11, minute=3), u_clin[5],
       app_id=APPS["mail_sync"], scopes=["Mail.Read"], verified=True)
    ev("oauth", "consent_granted", WORKDAYS[4].replace(hour=14, minute=41), u_billing[2],
       app_id=APPS["reporting"], scopes=["Reports.Read"], verified=True)
    # admin activates role during business hours by admin — control for D5
    ev("entra", "role_assigned", WORKDAYS[3].replace(hour=10, minute=5), u_it1,
       role=GRP["it_admins"], target_id=u_it2, grantor_has_admin=True)

def mfa_fatigue():
    t0 = datetime(2026, 11, 2, 9, 5, tzinfo=timezone.utc)
    for i in range(7):
        ev("entra", "mfa_denied", t0 + timedelta(minutes=i), u_dana,
           ip="45.134.20.18", device_id="dev-atk-01", mfa_method="push",
           city="Frankfurt", country="DE", asn_type="datacenter", result="denied")
    ev("entra", "signin", t0 + timedelta(minutes=12), u_dana,
       ip="45.134.20.18", device_id="dev-atk-01", city="Frankfurt", country="DE",
       asn_type="datacenter", result="success")
    ev("oauth", "consent_granted", t0 + timedelta(minutes=16), u_dana,
       app_id=APPS["office_helper"], scopes=["Files.ReadWrite.All"], verified=False)
    ev("cloudtrail", "api_call", t0 + timedelta(minutes=21), u_dana,
       ip="45.134.20.18", resource_id=RESOURCES["billing_exp"], operation="GetObject")

def oauth_service_abuse():
    t0 = datetime(2026, 11, 2, 22, 40, tzinfo=timezone.utc)
    ev("entra", "signin", t0, u_svc_report, ip="91.240.118.6", device_id="dev-atk-02",
       city="Lagos", country="NG", asn_type="datacenter", result="success", interactive=True)
    ev("cloudtrail", "api_call", t0 + timedelta(minutes=6), u_svc_report,
       ip="91.240.118.6", resource_id=RESOURCES["analytics"], operation="Query")
    # far-away success shortly after a San Antonio success -> impossible travel, no VPN/mobile involved
    ev("entra", "signin", datetime(2026, 11, 2, 20, 10, tzinfo=timezone.utc), u_exec2,
       ip="198.51.100.51", device_id=dev(u_exec2)[0], city="San Antonio", country="US",
       asn_type="residential", result="success")
    ev("entra", "signin", t0 + timedelta(minutes=55), u_exec2,
       ip="45.134.20.99", device_id="dev-atk-03", city="Lagos", country="NG",
       asn_type="datacenter", result="success")

def role_grant_abuse():
    t0 = datetime(2026, 11, 2, 3, 12, tzinfo=timezone.utc)
    ev("entra", "role_assigned", t0, u_contract[0],
       role=GRP["it_admins"], target_id=u_marcus, grantor_has_admin=False)
    ev("entra", "signin", t0 + timedelta(minutes=8), u_marcus,
       ip="45.134.20.44", device_id="dev-atk-04", city="Dallas", country="US",
       asn_type="datacenter", result="success")
    ev("cloudtrail", "api_call", t0 + timedelta(minutes=13), u_marcus,
       ip="45.134.20.44", resource_id=RESOURCES["ehr"], operation="GetRecords")

baseline(); mfa_fatigue(); oauth_service_abuse(); role_grant_abuse()
events.sort(key=lambda e: e["timestamp"])

# ---------------------------------------------------------------- ground truth
CTX_CORP = {"ip": "198.51.100.2", "asn_type": "corporate", "time": "14:00"}
ground_truth = {
    "org": "Northstar Health", "generator": GEN_VERSION, "seed": SEED,
    "reachable_paths": [
        {"identity_id": u_dana,    "resource_id": RESOURCES["billing_exp"], "ctx": CTX_CORP, "expect": True,  "via": "group_allow"},
        {"identity_id": u_marcus,  "resource_id": RESOURCES["ehr"],         "ctx": CTX_CORP, "expect": True,  "via": "group_allow"},
        {"identity_id": u_it1,     "resource_id": RESOURCES["backup"],      "ctx": {"ip": "198.51.100.2", "asn_type": "vpn", "time": "14:00"}, "expect": True, "via": "trust_assume_chain"},
        {"identity_id": u_svc_backup, "resource_id": RESOURCES["backup"],   "ctx": CTX_CORP, "expect": True,  "via": "resource_policy"},
        {"identity_id": u_dana,    "resource_id": RESOURCES["payroll"],     "ctx": CTX_CORP, "expect": True,  "via": "consent_delegation"},
        {"identity_id": u_exec1,    "resource_id": RESOURCES["hr"],          "ctx": CTX_CORP, "expect": True,  "via": "group_allow"},
        {"identity_id": u_exec2,    "resource_id": RESOURCES["hr"],          "ctx": CTX_CORP, "expect": True,  "via": "nested_group", "_note": "member of grp-exec-oncall nested inside grp-executives (depth-2 expansion)"},
    ],
    "denied_paths": [
        {"identity_id": u_contract[0], "resource_id": RESOURCES["hr"],        "ctx": CTX_CORP, "expect": False, "reason": "explicit_deny"},
        {"identity_id": u_svc_mail,    "resource_id": RESOURCES["ehr"],       "ctx": CTX_CORP, "expect": False, "reason": "explicit_deny"},
        {"identity_id": u_billing[1],  "resource_id": RESOURCES["analytics"], "ctx": {"ip": "198.51.100.2", "asn_type": "corporate", "time": "22:00"}, "expect": False, "reason": "condition_mismatch"},
        {"identity_id": u_clin[0],     "resource_id": RESOURCES["payroll"],   "ctx": CTX_CORP, "expect": False, "reason": "no_allow_path"},
        {"identity_id": u_it1,         "resource_id": RESOURCES["backup"],    "ctx": {"ip": "45.134.20.2", "asn_type": "datacenter", "time": "14:00"}, "expect": False, "reason": "condition_mismatch"},
    ],
    "attack_scenarios": {
        "mfa_fatigue": {"events_file": "attack-scenarios/mfa_fatigue.jsonl",
                        "compromised": [u_dana],
                        "expected_detections": ["D1_mfa_fatigue", "D2_new_device_signin", "D4_risky_oauth_consent"],
                        "min_score": 85},
        "service_account_abuse": {"events_file": "attack-scenarios/service_account_abuse.jsonl",
                                  "compromised": [u_svc_report],
                                  "expected_detections": ["D6_service_account_interactive"],
                                  "min_score": 40},
        "impossible_travel": {"events_file": "attack-scenarios/impossible_travel.jsonl",
                              "compromised": [u_exec2],
                              "expected_detections": ["D3_impossible_travel", "D2_new_device_signin"],
                              "min_score": 75},
        "role_grant_abuse": {"events_file": "attack-scenarios/role_grant_abuse.jsonl",
                             "compromised": [u_marcus],
                             "expected_detections": ["D5_role_assignment_anomaly", "D2_new_device_signin"],
                             "min_score": 80},
    },
    "normal_baseline": {"events_file": "normal/baseline.jsonl", "max_alerts": 3,
                        "expected_detections": []},
}

# split baseline vs scenarios by time boundary (baseline ends before 2026-11-01)
cut = "2026-11-01"
baseline_events = [e for e in events if e["timestamp"] < cut]
scenario_events = [e for e in events if e["timestamp"] >= cut]

# tag scenarios by member events using identifiable attributes
def events_of_identity(iids, start=None):
    out = [e for e in scenario_events if e["identity_id"] in iids]
    return sorted(out, key=lambda e: e["timestamp"])

sc1 = events_of_identity([u_dana])
sc2 = events_of_identity([u_svc_report])
sc3 = [e for e in events_of_identity([u_exec2]) if e["type"] == "signin"]
sc4 = events_of_identity([u_contract[0], u_marcus])

def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

(ROOT / "org.json").write_text(json.dumps(org, indent=2))
write_jsonl(ROOT / "normal" / "baseline.jsonl", baseline_events)
write_jsonl(ROOT / "attack-scenarios" / "mfa_fatigue.jsonl", sc1)
write_jsonl(ROOT / "attack-scenarios" / "service_account_abuse.jsonl", sc2)
write_jsonl(ROOT / "attack-scenarios" / "impossible_travel.jsonl", sc3)
write_jsonl(ROOT / "attack-scenarios" / "role_grant_abuse.jsonl", sc4)
(ROOT / "ground_truth.json").write_text(json.dumps(ground_truth, indent=2))
(ROOT / "provenance.json").write_text(json.dumps({
    "type": "synthetic", "generator": GEN_VERSION, "seed": SEED,
    "generated_at": ts(datetime.now(timezone.utc)),
    "external_data": "none", "license": "MIT",
    "notes": ["All identities and organizations are fictional.",
              "City coordinates are approximations for distance math.",
              "Attack scenarios emulate documented cloud-identity TTPs (MFA fatigue, OAuth consent abuse, role-grant abuse, service-account takeover)."],
}, indent=2))

print(f"identities={len(identities)} grants={len(grants)} resources={len(resources)}")
print(f"baseline={len(baseline_events)} events; scenarios: mfa={len(sc1)} svc={len(sc2)} travel={len(sc3)} role={len(sc4)}")
