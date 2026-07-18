// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared types and protocol definitions for NeuronEdge Enclave.
//!
//! This crate is Apache-2.0 and is consumed by both the NeuronEdge Enclave runtime
//! (Apache-2.0) and the NeuronEdge Enclave control plane (BSL-1.1, separate repo).
//! It must not depend on either side's internals (PRD §9.3, STANDARDS §8).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod attestation;
pub mod audit;
pub mod guest;
pub mod profile;
pub mod snapshot;
pub mod supervisor;

pub use attestation::{
    PUBLIC_EVIDENCE_SCHEMA_VERSION, PublicAttestationError, PublicAttestationEvidence,
    PublicAttestationProof, PublicAttestationProvider,
};

#[cfg(feature = "grpc")]
pub mod grpc;
