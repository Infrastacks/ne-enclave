"""Verify the packaged Python SDK preserves complete live Azure evidence."""

from __future__ import annotations

import os

from ne import Client
from ne.runtime.v1 import runtime_pb2


target = os.environ.get("NE_API_TARGET", "127.0.0.1:50051")
with Client(target) as client:
    caps = client.get_runtime_capabilities(timeout=30)
    assert caps.execution_profile == runtime_pb2.EXECUTION_PROFILE_CONFIDENTIAL_AZURE
    response = client.get_attestation_evidence(
        workspace_id="azure-release-gate",
        nonce=bytes.fromhex("22" * 32),
        timeout=60,
    )
    evidence = response.public_evidence
    assert evidence.provider == runtime_pb2.ATTESTATION_PROVIDER_SEV_SNP_AZURE
    assert evidence.WhichOneof("proof") == "sev_snp_azure"
    proof = evidence.sev_snp_azure
    assert all(
        (
            proof.report,
            proof.vcek_cert_chain,
            proof.var_data,
            proof.ak_pub_tpm2b,
            proof.quote_msg,
            proof.quote_sig,
        )
    )
