// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
extern crate bindgen;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!(r"cargo:rerun-if-changed=wrapper.h");
    println!(r"cargo:rerun-if-changed=../../vendor/sleuthkit");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let sleuthkit_source_dir = std::path::Path::new("../../vendor/sleuthkit");
    let sleuthkit_out_dir = out_path.join("sleuthkit");
    let sleuthkit_out_dir_str = sleuthkit_out_dir
        .clone()
        .into_os_string()
        .into_string()
        .expect("Failed to convert out directory path to a string");

    let target = env::var("TARGET").expect("TARGET was not set");

    // Sleuthkit relies on autotools, which create a configure script and other
    // files in the sleuthkit source directory.  This isn't kosher for Rust
    // build scripts, which are only supposed to mutate the out directory, so
    // this copies the entire sleuthkit source into the out directory first.
    Command::new("cp")
        .arg("-r")
        .arg(sleuthkit_source_dir)
        .arg(&sleuthkit_out_dir)
        .status()
        .expect("Failed to copy sleuthkit source");

    let cfg = cc::Build::new();
    let mut cfg_cc = cc::Build::new();

    // Run autotools. Needed for some generated headers.
    let cc = cfg.get_compiler();
    let cc_path = cc.path().to_str().unwrap();
    let cpp = cfg_cc.get_compiler();
    let cpp_path = cpp.path().to_str().unwrap();
    let host = cc_path
        .strip_suffix("-cc")
        .or_else(|| cc_path.strip_suffix("-gcc"))
        .or_else(|| cc_path.strip_suffix("-gcc-posix"));

    let target = target.trim_end_matches("llvm");
    if cfg!(target_env = "msvc") {
        cfg_cc.flag("/std:c++17").define("NOMINMAX", None);
        eprintln!("{cpp:?}");
        eprintln!("{cpp_path:?}");
        Command::new("msbuild.exe")
            .args([
                r"-target:libtsk",
                r"/p:PlatformToolset=v142",
                r"/p:Platform=x64",
                r"/p:Configuration=Release_NoLibs",
                r"/p:RestorePackages=false",
                r"sleuthkit\win32\tsk-win.sln",
            ])
            .current_dir(&sleuthkit_out_dir)
            .status()
            .expect("msbuild failed");
        println!(
            r"cargo:rustc-link-search={}\win32\x64\Release_NoLibs",
            &sleuthkit_out_dir_str
        );
        println!(r"cargo:rustc-link-arg=/NODEFAULTLIB:libtsk");
    } else {
        cfg_cc.flag("-std=c++17");
        Command::new("autoreconf")
            .args(["--force", "--install"])
            .current_dir(&sleuthkit_out_dir)
            .status()
            .expect("autoreconf failed");
        Command::new("./configure")
            .args(host.map(|h| format!("--host={h}")))
            .env("CC", cc_path)
            .env("CXX", cpp_path)
            .envs(cfg.get_compiler().env().iter().cloned())
            .envs(cfg_cc.get_compiler().env().iter().cloned())
            .current_dir(&sleuthkit_out_dir)
            .status()
            .expect("configure failed");
        Command::new("make")
            .arg("-j")
            .arg(env::var("NUM_JOBS").expect("$NUM_JOBS not set"))
            .arg("tsk/libtsk.la")
            .env("CC", cc_path)
            .env("CXX", cpp_path)
            .envs(cfg.get_compiler().env().iter().cloned())
            .envs(cfg_cc.get_compiler().env().iter().cloned())
            .current_dir(&sleuthkit_out_dir)
            .status()
            .expect("make failed");
        println!(r"cargo:rustc-link-search={}/tsk/.libs", &sleuthkit_out_dir_str);
        println!(r"cargo:rustc-link-lib=tsk");
    }
    let bindings = bindgen::Builder::default()
        .clang_args(&["-I", &sleuthkit_out_dir_str])
        .clang_arg(format!("--target={target}"))
        .header("wrapper.h")
        .derive_debug(true)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

}
