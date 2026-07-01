// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Build script — compiles `proto/ne/runtime/v1/runtime.proto` into Rust
//! gRPC server + client stubs via tonic-build. Uses the vendored
//! `protoc` binary so the dev loop doesn't depend on a system protobuf
//! install.

// build.rs runs single-threaded before the crate compiles, so the
// `unsafe { env::set_var(...) }` below is sound. We disable the
// workspace `unsafe_code = deny` lint just for this file.
#![allow(unsafe_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Point tonic-build (which delegates to prost-build) at the
    // vendored protoc binary. `env::set_var` is `unsafe` in Rust
    // 2024 because of thread-safety concerns; safe here because
    // build.rs runs single-threaded before the main crate compiles.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build.rs runs single-threaded; no other thread can
    // observe the env mutation during this process.
    unsafe {
        std::env::set_var("PROTOC", &protoc);
    }

    let proto_root = "../../proto";
    let proto_file = "../../proto/ne/runtime/v1/runtime.proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_file], &[proto_root])?;

    println!("cargo:rerun-if-changed={proto_file}");
    println!("cargo:rerun-if-changed={proto_root}");
    Ok(())
}
