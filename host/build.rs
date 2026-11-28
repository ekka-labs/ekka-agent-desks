//! Generates NVIDIA OpenShell's gRPC types from the .proto files vendored byte for byte at v0.1.9
//! (`vendor/openshell`, pinned by sha256 in its PIN.json), with protox: the build needs no `protoc` and compiles none
//! of OpenShell's Rust code. The descriptor set kept in the program (for reading and writing provider profiles in
//! protobuf JSON) carries no source comments. The server half is generated for the tests' fake gateway only.

use prost::Message as _;

fn main() {
    println!("cargo:rerun-if-changed=../vendor/openshell/proto");
    let fds = protox::compile(["openshell.proto"], ["../vendor/openshell/proto"])
        .unwrap_or_else(|e| panic!("the vendored OpenShell protos do not compile: {e:?}"));
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let mut shipped = fds.clone();
    for file in &mut shipped.file {
        file.source_code_info = None;
    }
    std::fs::write(out.join("openshell_descriptor.bin"), shipped.encode_to_vec())
        .unwrap_or_else(|e| panic!("writing the OpenShell descriptor: {e}"));
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .generate_default_stubs(true)
        .compile_fds(fds)
        .unwrap_or_else(|e| panic!("generating the OpenShell types: {e}"));
}
