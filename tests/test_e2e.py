"""End-to-end scenarios over the real adjudication core."""
import base64
import hashlib
import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.storage import Store
from app.adjudge import adjudicate
from app.package import build_package
from app.certmodel import fp_of
from verify.verify_package import verify_package
import io, zipfile, json

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


def _sig(leaf_key, artifact=b"artifact"):
    d = hashlib.sha256(artifact).digest()
    s = leaf_key.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    return d, s, "1.2.840.10045.4.3.2"


class Harness:
    def __init__(self, tmp_path):
        self.store = Store(str(tmp_path / "data"))
        self.sid = "es_harness_000000000000000000000001"
        self.store.create_set(self.sid, "create")
        self.rows = []

    def add_cert(self, c, received=RECEIVED):
        d = pf.der(c)
        self.store.put_blob(d)
        self.rows.append({"client_ref": "c" + fp_of(d)[:20],
                          "kind": "certificate", "content_sha256": fp_of(d),
                          "received_at": received})

    def add_rev(self, obj, i, kind="crl", received=RECEIVED):
        d = pf.der(obj)
        self.store.put_blob(d)
        self.rows.append({"client_ref": f"{kind}{i}", "kind": kind,
                          "content_sha256": fp_of(d), "received_at": received})

    def seal(self):
        self.store.add_items(self.sid, self.rows)
        return self.store.seal(self.sid)

    def judge(self, leaf, root_fp, leaf_key=None, policies=(ANY,), signed=SIGNED,
              cutoff=CUTOFF, digest_sig=None):
        d, s, alg = digest_sig or _sig(leaf_key)
        return adjudicate(self.store, self.sid, {
            "artifact_digest": d.hex(), "signature": s.hex(),
            "signature_algorithm": alg, "signed_at": signed,
            "knowledge_cutoff": cutoff,
            "leaf_certificate_sha256": fp_of(pf.der(leaf)),
            "initial_policies": list(policies), "trust_anchors": [root_fp]})


def test_cross_sign_short_revoked_long_valid(tmp_path):
    h = Harness(tmp_path)
    r1k, r2k = pf.gen_key(), pf.gen_key()
    cak, midk, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    r1 = pf.build_cert("R1", None, r1k, r1k, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       self_signed=True)
    r2 = pf.build_cert("R2", None, r2k, r2k, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       self_signed=True)
    # Same CA subject + key cross-signed by R1 (short) and by Mid under R2.
    x1 = pf.build_cert("Shared CA", r1, cak, r1k, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    mid = pf.build_cert("Mid CA", r2, midk, r2k, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    x2 = pf.build_cert("Shared CA", mid, cak, midk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("codesign", x1, lk, cak,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("codesign.test",))
    # X1 revoked BEFORE signed_at by R1's CRL.
    crl_r1 = pf.build_crl(r1, r1k, [(x1.serial_number, SIGNED - 100_000,
                                     "key_compromise")],
                          last_update=SIGNED - 86400, next_update=SIGNED + 86400,
                          crl_number=5)
    # X2 chain clear.
    crl_mid = pf.build_crl(mid, midk, [], last_update=SIGNED - 86400,
                           next_update=SIGNED + 86400, crl_number=2)
    crl_ca = pf.build_crl(x2, cak, [], last_update=SIGNED - 86400,
                          next_update=SIGNED + 86400, crl_number=2)
    crl_r2 = pf.build_crl(r2, r2k, [], last_update=SIGNED - 86400,
                          next_update=SIGNED + 86400, crl_number=1)
    for c in (r1, r2, x1, x2, mid, leaf):
        h.add_cert(c)
    for i, c in enumerate((crl_r1, crl_mid, crl_ca, crl_r2)):
        h.add_rev(c, i)
    manifest = h.seal()
    # Anchor R1: only path leaf->x1->r1, revoked => REJECTED.
    res1 = h.judge(leaf, fp_of(pf.der(r1)), lk)
    assert res1["verdict"]["status"] == "REJECTED"
    assert res1["verdict"]["failed_rule"] == "REVOCATION"
    # Anchor R2: short branch via R1 impossible; long path accepted.
    res2 = h.judge(leaf, fp_of(pf.der(r2)), lk)
    assert res2["verdict"]["status"] == "VALID", res2["verdict"]
    path = res2["verdict"]["selected_path"]
    assert path == [fp_of(pf.der(leaf)), fp_of(pf.der(x2)),
                    fp_of(pf.der(mid)), fp_of(pf.der(r2))]


def test_bitemporal_cutoff_excludes_late_evidence(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    # GOOD CRL possessed by cutoff...
    good = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    # ...and a REVOKED CRL only acquired AFTER the cutoff (forged hindsight):
    # it must NOT change the historical decision.
    late = pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 50,
                                  "key_compromise")],
                        last_update=SIGNED + 200, next_update=SIGNED + 900,
                        crl_number=3)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(good, 0); h.add_rev(rcrl, 2)
    h.add_rev(late, 1, received=CUTOFF + 10)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID"
    rr = res["revocation_results"][0]
    assert rr["conclusion"] == "GOOD"
    late_rows = [c for c in rr["considered_evidence"]
                 if c["reason"] == "not_received_by_knowledge_cutoff"]
    assert late_rows and late_rows[0]["eligible"] is False


def test_archival_revoked_response_counts_when_held_by_cutoff(tmp_path):
    from cryptography.hazmat.primitives import hashes as H
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    # OCSP response produced AFTER signed_at but documenting an event BEFORE
    # it; acquired before cutoff => REVOKED at signed_at.
    oc = pf.build_ocsp(leaf, ca, ck, "revoked",
                       this_update=SIGNED + 50_000, next_update=SIGNED + 200_000,
                       revocation_time=SIGNED - 100_000,
                       reason="key_compromise", hash_alg=H.SHA256())
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(oc, 0, kind="ocsp")
    h.add_rev(rcrl, 1)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "REVOCATION"
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    rr = snap[fp_of(pf.der(leaf))]
    assert rr["conclusion"] == "REVOKED"
    assert rr["selected_evidence"]["kind"] == "ocsp"


def test_delta_crl_remove_from_crl(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    base = pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 200_000,
                                  "certificate_hold")],
                        last_update=SIGNED - 300_000,
                        next_update=SIGNED + 300_000, crl_number=10)
    delta = pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 200_000,
                                   "remove_from_crl")],
                         last_update=SIGNED - 1_000,
                         next_update=SIGNED + 300_000, crl_number=11,
                         delta_of=10)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 300_000,
                        next_update=SIGNED + 300_000, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(base, 0); h.add_rev(delta, 1); h.add_rev(rcrl, 2)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID"
    sel = res["revocation_results"][0]["selected_evidence"]
    assert sel["kind"] == "crl" and sel["delta"] == fp_of(pf.der(delta))


def test_delegated_ocsp_responder(tmp_path):
    from cryptography.hazmat.primitives import hashes as H
    h = Harness(tmp_path)
    rk, ck, lk, dk = pf.gen_key(), pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    deleg = pf.build_cert("OCSP Responder", ca, dk, ck,
                          key_usage=("digitalSignature",),
                          eku=("ocspSigning",), policies=[ANY])
    oc = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                       next_update=SIGNED + 100, responder_key=dk,
                       responder_cert=deleg, hash_alg=H.SHA256())
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf, deleg):
        h.add_cert(c)
    h.add_rev(oc, 0, kind="ocsp"); h.add_rev(rcrl, 1)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    assert res["revocation_results"][0]["selected_evidence"]["kind"] == "ocsp"


def test_rejection_proof_covers_branches(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    # CA without codeSigning EKU propagation: give CA an EKU lacking it,
    # and another CA candidate with a bad signature branch.
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       eku=("1.3.6.1.5.5.7.3.1",))  # serverAuth only
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(crl, 0)
    h.add_rev(rcrl, 1)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    proof = res["verdict"]["rejection_proof"]
    assert proof is not None
    edges = {(e["child"], e["parent"]): e["first_failure"]
             for e in proof["edges"]}
    assert (fp_of(pf.der(leaf)), fp_of(pf.der(ca))) in edges
    assert any(f and f["rule"] == "EKU"
               for f in proof["path_level_failures"])


def test_determinism_and_offline_verification(tmp_path):
    from cryptography.hazmat.primitives import hashes as H
    # Build two stores with reversed upload order.
    def build(td):
        h = Harness(td)
        rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
        root = pf.build_cert("R", None, rk, rk, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY], self_signed=True)
        ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"),
                           policies=[ANY])
        leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY])
        crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=2)
        rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                            next_update=SIGNED + 100, crl_number=1)
        oc = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                           next_update=SIGNED + 100, hash_alg=H.SHA256())
        return h, (root, ca, leaf), (crl, rcrl, oc), lk

    h1, certs, revs, lk = build(tmp_path / "a")
    fixed_sig = _sig(lk)
    for c in certs:
        h1.add_cert(c)
    for i, r in enumerate(revs[:2]):
        h1.add_rev(r, i)
    h1.add_rev(revs[2], 0, kind="ocsp")
    m1 = h1.seal()
    res1 = h1.judge(certs[2], fp_of(pf.der(certs[0])), digest_sig=fixed_sig)
    pkg1 = build_package(h1.store, res1, m1)

    h2 = Harness(tmp_path / "b")
    for c in reversed(certs):
        h2.add_cert(c)
    h2.add_rev(revs[2], 0, kind="ocsp")
    h2.add_rev(revs[1], 1)
    h2.add_rev(revs[0], 0)
    m2 = h2.seal()
    res2 = h2.judge(certs[2], fp_of(pf.der(certs[0])), digest_sig=fixed_sig)
    assert m1["content_digest"] == m2["content_digest"]
    from app import canonical
    assert canonical.dumps(res1) == canonical.dumps(res2)

    pkg_path = tmp_path / "pkg.zip"
    pkg_path.write_bytes(pkg1)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]

    # Tamper a DER inside the package -> verification must fail.
    zf = zipfile.ZipFile(io.BytesIO(pkg1))
    members = {n: zf.read(n) for n in zf.namelist()}
    der_name = sorted(n for n in members if n.startswith("der/"))[0]
    tampered = bytearray(members[der_name])
    tampered[40] ^= 0xFF
    bad_members = dict(members)
    bad_members[der_name] = bytes(tampered)
    (tmp_path / "bad.zip").write_bytes(_rezip(bad_members))
    assert not verify_package(str(tmp_path / "bad.zip"))["ok"]

    # Tamper a rule conclusion in result.json -> fail.
    result = json.loads(members["result.json"])
    result["verdict"]["status"] = "VALID" if result["verdict"]["status"] != "VALID" else "INVALID"
    from app import canonical as cj
    tr_members = dict(members)
    tr_members["result.json"] = cj.dumps(result)
    (tmp_path / "tampered_result.zip").write_bytes(_rezip(tr_members))
    assert not verify_package(str(tmp_path / "tampered_result.zip"))["ok"]


def _rezip(members: dict) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zo.writestr(info, members[name])
    return out.getvalue()


def test_rejected_package_offline_verifies(tmp_path):
    """A REJECTED adjudication (no valid path) also produces a package whose
    offline recomputation matches byte-for-byte."""
    import zipfile
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       eku=("1.3.6.1.5.5.7.3.1",))  # serverAuth only
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(crl, 0)
    h.add_rev(rcrl, 1)
    manifest = h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    pkg = build_package(h.store, res, manifest)
    path = tmp_path / "rejected.zip"
    path.write_bytes(pkg)
    report = verify_package(str(path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]


def test_stale_evidence_when_window_expired(tmp_path):
    """A CRL expired before signed_at cannot establish GOOD -> STALE."""
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    # CRL validity ended well before signed_at -> stale clearance.
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 1000,
                       next_update=SIGNED - 500, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(crl, 0)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    assert snap[fp_of(pf.der(leaf))]["conclusion"] == "STALE"


class BatchOcspHarness(Harness):
    """Two differently named CAs sharing one signing key; the target leaf and
    an unrelated leaf share one serial."""

    def __init__(self, tmp_path):
        from cryptography.hazmat.primitives import hashes as H
        super().__init__(tmp_path)
        rk, ck, lk, l2k = pf.gen_key(), pf.gen_key(), pf.gen_key(), pf.gen_key()
        self.ck, self.lk = ck, lk
        self.root = pf.build_cert(
            "Batch R", None, rk, rk, is_ca=True,
            key_usage=("keyCertSign", "cRLSign"), policies=[ANY], self_signed=True)
        self.ca1 = pf.build_cert(
            "Batch CA One", self.root, ck, rk, is_ca=True,
            key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
        self.ca2 = pf.build_cert(
            "Batch CA Two", self.root, ck, rk, is_ca=True,
            key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
        assert self.ca1.subject != self.ca2.subject
        assert (self.ca1.public_key().public_numbers()
                == self.ca2.public_key().public_numbers())
        serial = 0x0BADF00D12345678
        self.leaf = pf.build_cert(
            "batch-leaf.test", self.ca1, lk, ck, serial=serial,
            key_usage=("digitalSignature",), eku=("codeSigning",),
            policies=[ANY], san_dns=("batch-leaf.test",))
        self.other = pf.build_cert(
            "batch-other.test", self.ca2, l2k, ck, serial=serial,
            key_usage=("digitalSignature",), eku=("codeSigning",),
            policies=[ANY], san_dns=("batch-other.test",))
        self.rcrl = pf.build_crl(
            self.root, rk, [], last_update=SIGNED - 100,
            next_update=SIGNED + 100, crl_number=1)
        self.hash_alg = H.SHA256()

    def good_entry(self):
        return dict(cert=self.leaf, issuer=self.ca1, status="good",
                    this_update=SIGNED - 100, next_update=SIGNED + 100,
                    hash_alg=self.hash_alg)

    def unknown_entry(self):
        return dict(cert=self.other, issuer=self.ca2, status="unknown",
                    this_update=SIGNED - 100, next_update=SIGNED + 100,
                    hash_alg=self.hash_alg)

    def revoked_entry(self):
        return dict(cert=self.leaf, issuer=self.ca1, status="revoked",
                    this_update=SIGNED - 100, next_update=SIGNED + 100,
                    revocation_time=SIGNED - 1000,
                    reason="key_compromise", hash_alg=self.hash_alg)

    def seal_with(self, ocsp_obj):
        for c in (self.root, self.ca1, self.ca2, self.leaf):
            self.add_cert(c)
        self.add_rev(self.rcrl, 0)
        self.add_rev(ocsp_obj, 1, kind="ocsp")
        return self.seal()

    def judge_leaf(self):
        return self.judge(self.leaf, fp_of(pf.der(self.root)), self.lk)

    def batch(self, entries):
        return pf.build_ocsp_batch(
            entries, sign_key=self.ck, produced_at=SIGNED - 90,
            responder_cert=self.ca1)


def test_batch_ocsp_cross_issuer_same_serial_good_first(tmp_path):
    """GOOD entry for the target issuer ahead of an UNKNOWN entry for another
    issuer with the same serial must establish GOOD (regression: the parser
    collapsed entries by serial, so encoding order decided the result)."""
    h = BatchOcspHarness(tmp_path)
    h.seal_with(h.batch([h.good_entry(), h.unknown_entry()]))
    res = h.judge_leaf()
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    rr = snap[fp_of(pf.der(h.leaf))]
    assert rr["conclusion"] == "GOOD"
    assert rr["ambiguity"] is None
    used = [c for c in rr["considered_evidence"] if c["decision"] == "USED"]
    assert len(used) == 1


def test_batch_ocsp_cross_issuer_same_serial_good_last(tmp_path):
    """Same conclusion regardless of where the target issuer's entry sits."""
    h = BatchOcspHarness(tmp_path)
    h.seal_with(h.batch([h.unknown_entry(), h.good_entry()]))
    res = h.judge_leaf()
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    assert snap[fp_of(pf.der(h.leaf))]["conclusion"] == "GOOD"


def test_batch_ocsp_single_entry_unchanged(tmp_path):
    """A single-entry batch response keeps the original GOOD behavior."""
    h = BatchOcspHarness(tmp_path)
    h.seal_with(h.batch([h.good_entry()]))
    res = h.judge_leaf()
    assert res["verdict"]["status"] == "VALID"
    rr = res["revocation_results"][0]
    assert rr["conclusion"] == "GOOD"
    assert rr["selected_evidence"]["single_response_index"] == 0


def test_batch_ocsp_same_certid_conflict_is_stable(tmp_path):
    """Two entries attesting to one complete CertID with conflicting statuses
    must be reported as ambiguity in both encoding orders — never picking one
    by DER order."""
    h = BatchOcspHarness(tmp_path)
    for c in (h.root, h.ca1, h.ca2, h.leaf):
        h.add_cert(c)
    h.add_rev(h.rcrl, 0)
    good, revoked = h.good_entry(), h.revoked_entry()
    orders = [
        ("es_conf_a_000000000000000000000001", [good, revoked]),
        ("es_conf_b_000000000000000000000002", [revoked, good]),
    ]
    conclusions = []
    details = []
    artifact = b"artifact"
    for sid, entries in orders:
        h.store.create_set(sid, f"create-{sid}")
        oc = h.batch(entries)
        d = pf.der(oc)
        h.store.put_blob(d)
        rows = [{"client_ref": f"oc-{sid}", "kind": "ocsp",
                 "content_sha256": fp_of(d), "received_at": RECEIVED}]
        # Reuse the already-stored cert/CRL blobs via a second set's items.
        for c in (h.root, h.ca1, h.ca2, h.leaf):
            cd = pf.der(c)
            rows.append({"client_ref": f"c-{sid}-{fp_of(cd)[:8]}",
                         "kind": "certificate", "content_sha256": fp_of(cd),
                         "received_at": RECEIVED})
        cd = pf.der(h.rcrl)
        rows.append({"client_ref": f"crl-{sid}", "kind": "crl",
                     "content_sha256": fp_of(cd), "received_at": RECEIVED})
        h.store.add_items(sid, rows)
        h.store.seal(sid)
        dig, sig, alg = _sig(h.lk, artifact)
        res = adjudicate(h.store, sid, {
            "artifact_digest": dig.hex(), "signature": sig.hex(),
            "signature_algorithm": alg, "signed_at": SIGNED,
            "knowledge_cutoff": CUTOFF,
            "leaf_certificate_sha256": fp_of(pf.der(h.leaf)),
            "initial_policies": [ANY],
            "trust_anchors": [fp_of(pf.der(h.root))]})
        assert res["verdict"]["status"] == "REJECTED", res["verdict"]
        assert res["verdict"]["failed_rule"] == "REVOCATION"
        snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
        rr = snap[fp_of(pf.der(h.leaf))]
        conclusions.append(rr["conclusion"])
        details.append(rr["ambiguity"])
        assert any(c["reason"] == "conflicting_status_for_same_certid"
                   for c in rr["considered_evidence"])
    assert conclusions == ["MALFORMED_EVIDENCE", "MALFORMED_EVIDENCE"]
    assert details[0] is not None and details[1] is not None
    assert details[0]["kind"] == "ocsp_conflicting_status_for_same_certid"
    assert details[0]["statuses"] == ["GOOD", "REVOKED"]
    # Same complete CertID (shared PKI) in both orders; only the evidence
    # bytes differ because of encoding order.
    assert details[0]["certid"] == details[1]["certid"]
    assert details[0]["evidence_fingerprint"] != details[1]["evidence_fingerprint"]


def test_batch_ocsp_good_package_offline_verifies(tmp_path):
    """The cross-issuer batch GOOD adjudication survives an offline rerun."""
    h = BatchOcspHarness(tmp_path)
    manifest = h.seal_with(h.batch([h.good_entry(), h.unknown_entry()]))
    res = h.judge_leaf()
    assert res["verdict"]["status"] == "VALID"
    pkg = build_package(h.store, res, manifest)
    path = tmp_path / "batch-good.zip"
    path.write_bytes(pkg)
    report = verify_package(str(path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
