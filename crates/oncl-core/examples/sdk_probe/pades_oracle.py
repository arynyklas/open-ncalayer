"""Independent pyHanko 0.38+ oracle for fresh --case P03 public artifacts.

Run in a dedicated environment with pyHanko installed. No SDK implementation is
imported, no private material is read, and network fetching is disabled. This is
an explicit synthetic root/clock PKI exercise, not NCA/qualified certification.
"""
import argparse
import asyncio
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from importlib.metadata import version

from asn1crypto import x509, crl, ocsp
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import (
    validate_pdf_signature, validate_pdf_timestamp, KeyUsageConstraints,
)
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec, SignatureValidationSpec, LocalKnowledge,
    RevocationInfoGatheringSpec, RevinfoOnlineFetchingRule,
)
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo

NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)

def timestamp_ok(status):
    # validate_pdf_timestamp does not populate DocMDP (None means inapplicable).
    # This fixture profile explicitly forbids /Perms; regular-signature diff
    # analysis below remains enabled for every revision.
    return bool(status.intact and status.valid and status.trusted
                and status.coverage.name in ('ENTIRE_FILE', 'ENTIRE_REVISION'))
KU = KeyUsageConstraints(key_usage={'digital_signature'})


def oracle(directory):
    root = x509.Certificate.load((directory / 'root.der').read_bytes())
    tsa = x509.Certificate.load((directory / 'tsa.der').read_bytes())
    status_crl = crl.CertificateList.load((directory / 'status.crl.der').read_bytes())
    status_ocsp = ocsp.OCSPResponse.load((directory / 'status.ocsp.der').read_bytes())

    def context():
        return ValidationContext(
            trust_roots=[root], other_certs=[tsa], moment=NOW,
            crls=[status_crl], ocsps=[status_ocsp], allow_fetching=False,
            revocation_mode='require',
        )

    base = context()
    policy = CertValidationPolicySpec(
        trust_manager=base.path_builder.trust_manager,
        revinfo_policy=base.revinfo_policy,
    )
    spec = PdfSignatureValidationSpec(SignatureValidationSpec(
        cert_validation_policy=policy, ts_cert_validation_policy=policy,
        key_usage_settings=KU,
        revinfo_gathering_policy=RevocationInfoGatheringSpec(
            online_fetching_rule=RevinfoOnlineFetchingRule.LOCAL_ONLY),
        # LTA validation must discover carried status/certificates from the PDF;
        # external fixture OCSP/CRL data is not an archival-evidence substitute.
        local_knowledge=LocalKnowledge(known_certs=[root]),
    ))
    results = {'oracle': 'pyHanko ' + version('pyHanko'), 'network': False,
               'trust': 'explicit synthetic root.der', 'clock': NOW.isoformat(),
               'cases': {}}
    cases = [
        ('rsa-B.pdf', 'B'), ('rsa-T.pdf', 'T'), ('rsa-Lt.pdf', 'LT'),
        ('rsa-Lta.pdf', 'LTA'), ('rsa-Renewed-Lta.pdf', 'LTA'),
        ('rsa-B-Extended-T.pdf', 'T'), ('rsa-Multiple-Lta.pdf', 'LTA'),
        ('rsa-B-Then-T.pdf', 'B'), ('rsa-B-Then-Lta.pdf', 'LTA'),
    ]
    failures = []
    for filename, required in cases:
        data = (directory / filename).read_bytes()
        reader = PdfFileReader(io.BytesIO(data))
        signatures = reader.embedded_signatures
        if reader.root.get('/Perms') is not None:
            raise AssertionError('oracle fixture must not bypass permission transforms')
        regular = [s for s in signatures if s.sig_object.get('/Type') != '/DocTimeStamp']
        documents = [s for s in signatures if s.sig_object.get('/Type') == '/DocTimeStamp']
        dss_store = None
        if required in ('LT', 'LTA'):
            dss_store = DocumentSecurityStore.read_dss(reader)

        def case_context():
            if dss_store is None:
                return context()
            return dss_store.as_validation_context({
                'trust_roots': [root], 'moment': NOW,
                'allow_fetching': False, 'revocation_mode': 'require',
            })
        rows = []
        for signature in regular:
            status = validate_pdf_signature(signature, case_context(), case_context(), key_usage_settings=KU)
            row = {'field': signature.field_name, 'intact': status.intact,
                   'valid': status.valid, 'trusted': status.trusted,
                   'bottom_line': status.bottom_line, 'coverage': str(status.coverage),
                   'modifications': str(status.modification_level),
                   'signature_timestamp': None if status.timestamp_validity is None
                       else (status.timestamp_validity.intact and status.timestamp_validity.valid and status.timestamp_validity.trusted)}
            rows.append(row)
            if not status.bottom_line:
                failures.append(filename + ': regular signature failed: ' + status.pretty_print_details())
        timestamps = []
        for signature in documents:
            status = validate_pdf_timestamp(signature, case_context())
            timestamps.append({'field': signature.field_name, 'intact': status.intact,
                               'valid': status.valid, 'trusted': status.trusted,
                               'bottom_line': timestamp_ok(status), 'coverage': str(status.coverage)})
            if not timestamp_ok(status):
                failures.append(filename + ': document timestamp failed')
        dss = reader.root.get('/DSS')
        if required in ('LT', 'LTA') and dss is None:
            failures.append(filename + ': missing actual DSS')
        if required != 'B' and not documents and not all(row['signature_timestamp'] for row in rows):
            failures.append(filename + ': no verified trusted time indication')
        lta = []
        if required == 'LTA':
            for signature, row in zip(regular, rows):
                if row['signature_timestamp'] is None:
                    # pyHanko's ades_lta_validation unconditionally demands a CMS
                    # signature-timestamp attribute ("No signature timestamp present").
                    # A signature that was B before this extension (an earlier B signature
                    # on a PDF that later gained DSS + covering document timestamps,
                    # EN 319 142-1 6.3) is instead judged by the regular-signature check
                    # above plus the validated, covering document timestamps and DSS.
                    if (not timestamps or not all(t['bottom_line'] for t in timestamps)
                            or not timestamps[-1]['coverage'].endswith('ENTIRE_FILE')
                            or dss is None):
                        failures.append(filename + ': ' + str(row['field']) +
                                        ': no CMS timestamp and no valid covering document timestamp/DSS')
                    lta.append({'field': row['field'], 'ades_lta_validation': 'not applicable (no CMS signature timestamp)',
                                'document_timestamps_valid': bool(documents)})
                    continue
                result = asyncio.run(ades_lta_validation(
                    signature, spec, ValidationTimingInfo(NOW, NOW, True)))
                lta.append({'subindication': str(result.ades_subindic),
                            'oldest_evidence_record_timestamp': str(result.oldest_evidence_record_timestamp),
                            'best_signature_time': str(result.best_signature_time),
                            'failure': result.failure_msg})
                if result.ades_subindic.name != 'OK' or result.oldest_evidence_record_timestamp is None:
                    failures.append(filename + ': independent archival validation failed: ' + str(result))
        results['cases'][filename] = {'required': required, 'regular': rows,
            'document_timestamps': timestamps, 'dss': dss is not None, 'archive': lta,
            'status_material': 'DSS only' if dss_store is not None else 'explicit host fixture'}

    for filename in ('negative-dss.pdf', 'negative-doctimestamp.pdf'):
        rejected = False
        details = []
        try:
            reader = PdfFileReader(io.BytesIO((directory / filename).read_bytes()))
            for signature in reader.embedded_signatures:
                if signature.sig_object.get('/Type') == '/DocTimeStamp':
                    status = validate_pdf_timestamp(signature, context())
                    details.append({'intact': status.intact, 'valid': status.valid,
                                    'bottom_line': timestamp_ok(status)})
                    rejected |= not timestamp_ok(status)
        except Exception as exc:
            rejected = True
            details.append({'error': type(exc).__name__, 'message': str(exc)})
        results['cases'][filename] = {'rejected': rejected, 'timestamps': details}
        if not rejected:
            failures.append(filename + ': independent oracle accepted tampered document timestamp')
    results['failures'] = failures
    destination = directory / 'P03-pyhanko-oracle.json'
    destination.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    oracle(parser.parse_args().out)
