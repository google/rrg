// Copyright 2025 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unnecessary_transmutes)]
// improper_ctypes triggers because TSK uses u128, which is FFI-safe with modern
// LLVM. Remove this when https://github.com/rust-lang/rust/pull/137306 makes it
// into the latest stable release.
#![allow(improper_ctypes)]
#![allow(clippy::all)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
