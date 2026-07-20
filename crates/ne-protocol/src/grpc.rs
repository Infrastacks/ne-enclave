// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Generated gRPC stubs for the NeuronEdge Enclave Runtime API.
//!
//! The .proto source lives at `proto/ne/v1/runtime.proto`; the
//! generated code lands here via `tonic::include_proto!` at compile
//! time. Re-exported under `runtime::v1` so callers write
//! `ne_protocol::grpc::runtime::v1::runtime_server::Runtime`.

// The generated code is not author-controlled; relax all project
// lints for this module so we don't have to apply `cargo fix`
// against tonic's codegen output on every tonic-build upgrade.
#![allow(
    missing_docs,
    unreachable_pub,
    unused_qualifications,
    rust_2018_idioms,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]

pub mod runtime {
    /// NeuronEdge Enclave Runtime API v1 — see `proto/ne/v1/runtime.proto`.
    pub mod v1 {
        tonic::include_proto!("ne.runtime.v1");
    }
}
