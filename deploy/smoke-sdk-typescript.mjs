import {
	AttestationProvider,
	Client,
	ExecutionProfile,
} from "@neuronedge/enclave";

const client = new Client({
	target: process.env.NE_API_TARGET ?? "127.0.0.1:50051",
	deadlineMs: 60_000,
});

try {
	const caps = await client.getRuntimeCapabilities();
	if (
		caps.executionProfile !==
		ExecutionProfile.EXECUTION_PROFILE_CONFIDENTIAL_AZURE
	) {
		throw new Error(`unexpected execution profile: ${caps.executionProfile}`);
	}
	const response = await client.getAttestationEvidence({
		workspaceId: "azure-release-gate",
		nonce: Uint8Array.from({ length: 32 }, () => 0x33),
	});
	const evidence = response.publicEvidence;
	if (
		!evidence ||
		evidence.provider !==
			AttestationProvider.ATTESTATION_PROVIDER_SEV_SNP_AZURE ||
		evidence.proof?.$case !== "sevSnpAzure"
	) {
		throw new Error("candidate TypeScript SDK lost the Azure proof variant");
	}
	const proof = evidence.proof.sevSnpAzure;
	for (const bytes of [
		proof.report,
		proof.vcekCertChain,
		proof.varData,
		proof.akPubTpm2b,
		proof.quoteMsg,
		proof.quoteSig,
	]) {
		if (bytes.length === 0) {
			throw new Error("empty Azure proof field");
		}
	}
} finally {
	client.close();
}
