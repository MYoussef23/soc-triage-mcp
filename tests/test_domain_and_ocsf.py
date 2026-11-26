import json
import os
import random
import sys
from pathlib import Path

import pytest

from soc_triage.domain import classify
from soc_triage.normalise import normalise

SCHEMA = os.environ.get("OCSF_SCHEMA_DIR")


def test_synthetic_identity_incident(incident_alert):
    r = classify(incident_alert)
    assert r.primary == "identity"
    assert r.confidence == "high"
    assert r.scores["identity"] > 3 * max(v for k, v in r.scores.items() if k != "identity")


@pytest.mark.parametrize("expected", ["endpoint", "network", "cloud", "appsec"])
def test_synthetic_domains(synthetic, expected):
    assert classify(synthetic[expected]).primary == expected


def test_classifier_is_deterministic_and_order_independent(incident_alert):
    a = classify(incident_alert).as_dict()
    shuffled = json.loads(json.dumps(incident_alert))
    random.Random(7).shuffle(shuffled[0]["evidence"])
    assert classify(shuffled).as_dict()["scores"] == a["scores"]
    assert classify(incident_alert).as_dict() == a


def test_full_rule_query_strengthens_signal(incident_alert):
    full = 'let aadFunc = (t:string){table(t)};\nunion isfuzzy=true aadFunc("SigninLogs"), aadFunc("AADNonInteractiveUserSignInLogs")'
    assert classify(incident_alert, detection_query=full).scores["identity"] > classify(incident_alert).scores["identity"]


def test_ocsf_core_fields(incident_alert):
    f = normalise(incident_alert)
    assert (f["class_uid"], f["category_uid"], f["type_uid"], f["activity_id"]) == (2004, 2, 200401, 1)
    assert f["severity_id"] == 2 and f["status_id"] == 1 and f["is_alert"] is True
    assert f["metadata"]["version"] == "1.10.0"
    assert f["finding_info"]["attacks"][0]["technique"]["uid"] == "T1110"
    assert f["finding_info"]["attacks"][0]["tactic"]["uid"] == "TA0006"
    assert f["finding_info"]["related_events_count"] == 202
    assert f["finding_info"]["data_sources"] == ["example-sentinel-workspace"]
    users = [e["user"] for e in f["evidences"] if "user" in e]
    ips = [e["src_endpoint"]["ip"] for e in f["evidences"] if "src_endpoint" in e]
    assert len(users) == 19 and len(ips) == 81
    assert {"operator-one@example.invalid", "operator-two@example.invalid"} <= {
        u["name"] for u in users
    }
    assert all((u["type_id"], u["type"]) == (1, "User") for u in users)
    assert "detection_query_truncated" in f["metadata"]["labels"]
    assert f["unmapped"]["investigationState"] == "unsupportedAlertType"


def test_ocsf_is_deterministic(incident_alert):
    assert json.dumps(normalise(incident_alert), sort_keys=True) == json.dumps(normalise(incident_alert), sort_keys=True)


@pytest.mark.skipif(not SCHEMA, reason="set OCSF_SCHEMA_DIR to a v1.10.0 ocsf-schema clone")
def test_ocsf_schema_valid(incident_alert, synthetic):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from validate_ocsf import Schema, validate
    schema = Schema(SCHEMA)
    for name, alert in [("incident", incident_alert), *synthetic.items()]:
        errs = validate(schema, normalise(alert))
        assert not errs, f"{name}: {errs}"
