"""Batch OCSP responses: multiple SingleResponses, duplicate serials across
distinct issuers (same serial, different name/key hashes) and exact-CertID
conflicts (RFC 6960 permits several SingleResponses per BasicOCSPResponse).

The target leaf's GOOD entry must be usable regardless of its position in the
encoding; a response that asserts contradictory statuses for one complete
CertID must be reported deterministically as ambiguous evidence.
"""
import hashlib
import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes as H
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.storage import Store
from app.adjudge import adjudicate
from app.certmodel import fp_of
from app.package import build_package
from verify.verify_package import verify_package

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000
SHARED_SERIAL = 987654321


@pytest.fixture
def pki():
    """Two distinct-name CAs sharing one responder signing key; two leaves
    with the same serial, one under each CA; byKey delegated responders."""
    ka, kb, kl, kr = pf.gen_key(), pf.gen_key(), pf.gen_key(), pf.gen_key()
    root_a = pf.build_cert("Issuer Alpha", None, ka, ka, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"),
                           policies=[ANY], self_signed=True)
    root_b = pf.build_cert("Issuer Bravo", None, kb, kb, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"),
                           policies=[ANY], self_signed=True)
    leaf_a = pf.build_cert("target.alpha.test", root_a, kl, ka,
                           serial=SHARED_SERIAL,
                           key_usage=("digitalSignature",),
                           eku=("codeSigning",), policies=[ANY],
                           san_dns=("target.alpha.test",))
    other_key = pf.gen_key()
    leaf_b = pf.build_cert("other.bravo.test", root_b, other_key, kb,
                           serial=SHARED_SERIAL,
                           key_usage=("digitalSignature",),
                           eku=("codeSigning",), policies=[ANY],
                           san_dns=("other.bravo.test",))
    resp_a = pf.build_cert("Responder Alpha", root_a, kr, ka,
                           key_usage=("digitalSignature",),
                           eku=("ocspSigning",), policies=[ANY])
    resp_b = pf.build_cert("Responder Bravo", root_b, kr, kb,
                           key_usage=("digitalSignature",),
                           eku=("ocspSigning",), policies=[ANY])
    return {
        "keys": (ka, kb, kl, kr, other_key),
        "root_a": root_a, "root_b": root_b,
        "leaf_a": leaf_a, "leaf_b": leaf_b,
        "resp_a": resp_a, "resp_b": resp_b,
    }


def _entry(leaf, issuer, status, responder_cert, **kw):
    return dict(leaf_cert=leaf, issuer_cert=issuer, issuer_key=None,
                status=status, hash_alg=H.SHA256(),
                this_update=SIGNED - 100, next_update=SIGNED + 100,
                responder_cert=responder_cert, **kw)


def _run(path, pki, ocsp_raw):
    ka, kb, kl, kr, _ = pki["keys"]
    store = Store(str(path / "data"))
    sid = "es_batch_ocsp_0000000000000000001"
    store.create_set(sid, "create")
    rows = []

    def add(obj, kind):
        d = obj if isinstance(obj, bytes) else pf.der(obj)
        store.put_blob(d)
        rows.append({"client_ref": f"{kind}-{fp_of(d)[:12]}", "kind": kind,
                     "content_sha256": fp_of(d), "received_at": RECEIVED})

    for c in (pki["root_a"], pki["root_b"], pki["leaf_a"], pki["leaf_b"],
              pki["resp_a"], pki["resp_b"]):
        add(c, "certificate")
    add(ocsp_raw, "ocsp")
    store.add_items(sid, rows)
    manifest = store.seal(sid)

    digest = hashlib.sha256(b"batch-ocsp-artifact").digest()
    sig = kl.sign(digest, ec.ECDSA(Prehashed(H.SHA256())))
    result = adjudicate(store, sid, {
        "artifact_digest": digest.hex(), "signature": sig.hex(),
        "signature_algorithm": "1.2.840.10045.4.3.2",
        "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(pki["leaf_a"])),
        "initial_policies": [ANY],
        "trust_anchors": [fp_of(pf.der(pki["root_a"]))]})
    return store, manifest, result


def _leaf_revocation(result, pki):
    snap = {x["certificate"]: x for x in result["revocation_snapshot"]}
    return snap[fp_of(pf.der(pki["leaf_a"]))]


@pytest.mark.parametrize("target_first", [True, False])
def test_cross_issuer_same_serial_target_good(tmp_path, pki, target_first):
    """GOOD for the target issuer + UNKNOWN for another issuer sharing the
    serial number: target cert is GOOD no matter which entry is encoded first.
    The response is signed by one key, authorized via byKey responder certs
    chained under each CA."""
    kr = pki["keys"][3]
    good = _entry(pki["leaf_a"], pki["root_a"], "good", pki["resp_a"])
    unknown = _entry(pki["leaf_b"], pki["root_b"], "unknown", pki["resp_b"])
    entries = [good, unknown] if target_first else [unknown, good]
    ocsp_raw = pf.build_batch_ocsp(
        entries, sign_key=kr, responder_key_cert=pki["resp_a"],
        embedded_certs=[pki["resp_a"], pki["resp_b"]])
    store, manifest, result = _run(tmp_path, pki, ocsp_raw)
    assert result["verdict"]["status"] == "VALID", result["verdict"]
    rr = _leaf_revocation(result, pki)
    assert rr["conclusion"] == "GOOD"
    assert rr["selected_evidence"]["kind"] == "ocsp"
    dispositions = {(c["kind"], c["decision"], c["reason"])
                    for c in rr["considered_evidence"]}
    assert ("ocsp", "USED", "USED") in dispositions


def test_single_entry_response_unchanged(tmp_path, pki):
    """A one-entry response keeps its original behavior: GOOD clears, UNKNOWN
    does not."""
    kr = pki["keys"][3]
    good = pf.build_ocsp(pki["leaf_a"], pki["root_a"], None, "good",
                         this_update=SIGNED - 100, next_update=SIGNED + 100,
                         responder_key=kr, responder_cert=pki["resp_a"],
                         hash_alg=H.SHA256())
    _, _, result_good = _run(tmp_path / "good", pki, good)
    assert result_good["verdict"]["status"] == "VALID"

    unknown = pf.build_ocsp(pki["leaf_a"], pki["root_a"], None, "unknown",
                            this_update=SIGNED - 100,
                            next_update=SIGNED + 100,
                            responder_key=kr, responder_cert=pki["resp_a"],
                            hash_alg=H.SHA256())
    _, _, result_unknown = _run(tmp_path / "unknown", pki, unknown)
    assert result_unknown["verdict"]["status"] == "REJECTED"
    rr = _leaf_revocation(result_unknown, pki)
    assert rr["conclusion"] == "UNKNOWN"


@pytest.mark.parametrize("target_first", [True, False])
def test_same_certid_conflicting_status_is_ambiguous(tmp_path, pki,
                                                     target_first):
    """Two entries for the SAME complete CertID (same issuer name+key, same
    serial) with GOOD vs REVOKED: the conflict must be reported stably and
    must never be resolved by encoding order."""
    kr = pki["keys"][3]
    good = _entry(pki["leaf_a"], pki["root_a"], "good", pki["resp_a"])
    revoked = _entry(pki["leaf_a"], pki["root_a"], "revoked", pki["resp_a"],
                     revocation_time=SIGNED - 50_000,
                     reason="key_compromise")
    entries = [good, revoked] if target_first else [revoked, good]
    ocsp_raw = pf.build_batch_ocsp(
        entries, sign_key=kr, responder_key_cert=pki["resp_a"],
        embedded_certs=[pki["resp_a"]])
    _, _, result = _run(tmp_path, pki, ocsp_raw)
    assert result["verdict"]["status"] == "REJECTED"
    assert result["verdict"]["failed_rule"] == "REVOCATION"
    rr = _leaf_revocation(result, pki)
    assert rr["conclusion"] == "MALFORMED_EVIDENCE"
    reasons = {c["reason"] for c in rr["considered_evidence"]}
    assert "conflicting_status_for_certid" in reasons


@pytest.mark.parametrize("target_first", [True, False])
def test_same_certid_contradictory_revocation_times(tmp_path, pki,
                                                    target_first):
    """Both entries say REVOKED, but one revocation is before signed_at and
    the other after it: the effective historical status contradicts, so the
    response is ambiguous rather than GOOD-by-later-event."""
    kr = pki["keys"][3]
    earlier = _entry(pki["leaf_a"], pki["root_a"], "revoked", pki["resp_a"],
                     revocation_time=SIGNED - 50_000,
                     reason="key_compromise")
    later = _entry(pki["leaf_a"], pki["root_a"], "revoked", pki["resp_a"],
                   revocation_time=SIGNED + 50_000,
                   reason="cessation_of_operation")
    entries = [earlier, later] if target_first else [later, earlier]
    ocsp_raw = pf.build_batch_ocsp(
        entries, sign_key=kr, responder_key_cert=pki["resp_a"],
        embedded_certs=[pki["resp_a"]])
    _, _, result = _run(tmp_path, pki, ocsp_raw)
    rr = _leaf_revocation(result, pki)
    assert rr["conclusion"] == "MALFORMED_EVIDENCE"
    reasons = {c["reason"] for c in rr["considered_evidence"]}
    assert "conflicting_status_for_certid" in reasons


def test_cross_issuer_batch_ocsp_package_verifies_offline(tmp_path, pki):
    """The GOOD verdict produced from a cross-issuer same-serial batch must
    survive the fully offline package re-adjudication."""
    kr = pki["keys"][3]
    good = _entry(pki["leaf_a"], pki["root_a"], "good", pki["resp_a"])
    unknown = _entry(pki["leaf_b"], pki["root_b"], "unknown", pki["resp_b"])
    ocsp_raw = pf.build_batch_ocsp(
        [good, unknown], sign_key=kr, responder_key_cert=pki["resp_a"],
        embedded_certs=[pki["resp_a"], pki["resp_b"]])
    store, manifest, result = _run(tmp_path, pki, ocsp_raw)
    assert result["verdict"]["status"] == "VALID"
    pkg = build_package(store, result, manifest)
    pkg_path = tmp_path / "pkg.zip"
    pkg_path.write_bytes(pkg)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
