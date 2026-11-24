// SPDX-License-Identifier: LGPL-3.0-or-later

//! Refuses to build when a zkboo crate resolves from anywhere but crates.io.
//!
//! A `[patch]` entry, in a manifest or in a cargo configuration file, would build the code against
//! a local tree that the lockfile's checksums do not cover. The lockfile is the one record of what
//! was resolved, so it is read here rather than the manifests.
//!
//! It sits in this crate and not in `circuits` because the Ledger app links `circuits` by path,
//! and a build script anywhere in that crate moves the application hash — measured, 2026-09-19 —
//! although it does not run for that build. Building this workspace builds this crate, so the
//! guard still covers it.
//!
//! This crate is also built as a dependency of other workspaces — the standalone provers, the
//! app's `psverify` shim, any user of the published crate — whose builds resolve against their
//! own lockfiles, not this one. Those builds are recognised by an output directory outside this
//! workspace, or by a parent directory that is not this workspace, and left to their own guards;
//! the skip says so on the build's output rather than passing silently.

use std::path::{Path, PathBuf};

/// Whether a crate must resolve from crates.io.
fn guarded(name: &str) -> bool {
    name.starts_with("zkboo")
}

/// The lockfile's source for crates.io.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Lists the guarded packages the lockfile resolves from anywhere but crates.io.
fn off_registry(lock: &str) -> Vec<String> {
    let mut found = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            block.lines().find_map(|line| {
                let (k, v) = line.split_once('=')?;
                (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
            })
        };
        let Some(name) = field("name") else { continue };
        if !guarded(&name) {
            continue;
        }
        let source = field("source");
        if source.as_deref() != Some(CRATES_IO) {
            found.push(format!(
                "{name} {} from {}",
                field("version").unwrap_or_default(),
                source.as_deref().unwrap_or("a path")
            ));
        }
    }
    found
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let is_this_workspace = std::fs::read_to_string(workspace.join("Cargo.toml"))
        .is_ok_and(|m| m.contains("[workspace]") && m.contains("\"host\""));
    if !is_this_workspace || !out_dir.starts_with(&workspace) {
        println!(
            "cargo::warning=built from another workspace ({}); its own lockfile guard applies",
            out_dir.display()
        );
        return;
    }
    let lock_path = workspace.join("Cargo.lock");
    println!("cargo::rerun-if-changed={}", lock_path.display());
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock_path.display()));
    if !lock.contains("\nname = \"zkboo\"\n") {
        panic!("{} resolves no zkboo crate", lock_path.display());
    }
    let found = off_registry(&lock);
    if !found.is_empty() {
        panic!(
            "these crates resolve from somewhere other than crates.io, so a [patch] is in \
             force:\n  {}",
            found.join("\n  ")
        );
    }
}
