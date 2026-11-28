//! NVIDIA OpenShell's gRPC types, generated at build time from its .proto files vendored byte for byte at v0.1.9
//! (`vendor/openshell`, `build.rs`). Only the gateway's admin client in `gateway_grpc` uses them; the server half is
//! for the tests' fake gateway.

#[allow(clippy::all, clippy::pedantic, dead_code, missing_docs, unreachable_pub, unused_qualifications)]
pub mod openshell {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/openshell.v1.rs"));
    }
    pub mod datamodel {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/openshell.datamodel.v1.rs"));
        }
    }
    pub mod options {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/openshell.options.v1.rs"));
        }
    }
    pub mod sandbox {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/openshell.sandbox.v1.rs"));
        }
    }
}

pub use openshell::datamodel::v1 as datamodel;
pub use openshell::v1 as api;

/// The compiled descriptor set of the vendored files (no source comments), for OpenShell's protobuf JSON.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/openshell_descriptor.bin"));

#[cfg(test)]
mod tests {
    use crate::util::sha256_hex;

    /// The vendored files are NVIDIA's bytes at v0.1.9, as vendor/openshell/PIN.json records them, and nothing else.
    #[test]
    fn the_vendored_protos_are_openshell_v019_byte_for_byte() {
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../vendor/openshell"));
        let pin: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("PIN.json")).unwrap()).unwrap();
        assert_eq!(pin["tag"], "v0.1.9");
        assert_eq!(
            pin["tag"].as_str().unwrap().trim_start_matches('v'),
            crate::release::Pins::embedded().unwrap().openshell_version,
            "the gateway this host pins"
        );
        let files = pin["files"].as_object().unwrap();
        for (name, want) in files {
            assert_eq!(&sha256_hex(&std::fs::read(dir.join(name)).unwrap()), want.as_str().unwrap(), "{name}");
        }
        let mut on_disk: Vec<String> = std::fs::read_dir(dir.join("proto"))
            .unwrap()
            .map(|e| format!("proto/{}", e.unwrap().file_name().into_string().unwrap()))
            .collect();
        on_disk.sort();
        let mut pinned: Vec<String> = files.keys().filter(|k| k.starts_with("proto/")).cloned().collect();
        pinned.sort();
        assert_eq!(on_disk, pinned, "a proto with no pin, or a pin with no proto");
    }
}
