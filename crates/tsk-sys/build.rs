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
    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR was not set"));
    let sleuthkit_source_path = std::path::Path::new("../../vendor/sleuthkit");
    let sleuthkit_out_path = out_path.join("sleuthkit");

    let target = env::var("TARGET").expect("TARGET was not set");

    // sleuthkit relies on autotools, which create a configure script and other
    // files in the sleuthkit source directory. This isn't kosher for Rust build
    // scripts, which are only supposed to mutate the out directory, so this
    // copies the entire sleuthkit source into the out directory first.
    Command::new("cp")
        .arg("-r")
        .arg(sleuthkit_source_path)
        .arg(&sleuthkit_out_path)
        .status()
        .expect("failed to copy sleuthkit source");

    let build_path = out_path.join("build");

    let mut cfg = cc::Build::new();
    let mut cfg_cc = cc::Build::new();

    // Run autotools. Needed for some generated headers.
    let cc = cfg.get_compiler();
    let cc_path_str = cc.path().to_str().unwrap();
    let cpp = cfg_cc.get_compiler();
    let cpp_path_str = cpp.path().to_str().unwrap();
    if cfg!(target_env = "msvc") {
        cfg_cc.flag("/std:c++17");
        // Disables min/max macros brought in by windows.h. Sleuthkit relies on std::min/max.
        cfg_cc.define("NOMINMAX", None);
    } else {
        let host = cc_path_str
            .strip_suffix("-cc")
            .or_else(|| cc_path_str.strip_suffix("-gcc"))
            .or_else(|| cc_path_str.strip_suffix("-gcc-posix"));
        cfg_cc.flag("-std=c++17");
        Command::new("autoreconf")
            .args(["--force", "--install"])
            .current_dir(&sleuthkit_out_path)
            .status()
            .expect("autoreconf failed");
        Command::new("./configure")
            .args(host.map(|h| format!("--host={h}")))
            .env("CC", cc_path_str)
            .env("CXX", cpp_path_str)
            .envs(cfg.get_compiler().env().iter().cloned())
            .envs(cfg_cc.get_compiler().env().iter().cloned())
            .current_dir(&sleuthkit_out_path)
            .status()
            .expect("configure failed");
    }

    let sleuthkit_out_path_str = sleuthkit_out_path
        .clone()
        .into_os_string()
        .into_string()
        .expect("failed to convert out directory path to a string");

    let target = target.trim_end_matches("llvm");
    let bindings = bindgen::Builder::default()
        .clang_args(&["-I", &sleuthkit_out_path_str])
        .clang_arg(format!("--target={target}"))
        .header("wrapper.h")
        .derive_debug(true)
        .allowlist_function("tsk_version_get_str")
        .allowlist_function("tsk_error_get")
        .allowlist_item("tsk_fs_.*")
        .allowlist_item("TSK_FS_.*")
        .allowlist_item("tsk_img_.*")
        .allowlist_item("TSK_IMG_.*")
        .generate()
        .expect("unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("couldn't write bindings!");

    // Build all C sources. In the submodule, get the list of files with:
    // make --dry-run VERBOSE=1 tsk/libtsk.la | rg -o 'tsk/[^ ]+\.c\b'
    let c_sources = [
        "tsk/base/crc.c",
        "tsk/base/md5c.c",
        "tsk/base/mymalloc.c",
        "tsk/base/sha1c.c",
        "tsk/base/tsk_base_i.c",
        "tsk/base/tsk_endian.c",
        "tsk/base/tsk_error.c",
        "tsk/base/tsk_list.c",
        "tsk/base/tsk_lock.c",
        "tsk/base/tsk_parse.c",
        "tsk/base/tsk_printf.c",
        "tsk/base/tsk_stack.c",
        "tsk/base/tsk_unicode.c",
        "tsk/base/tsk_version.c",
        "tsk/base/XGetopt.c",
        "tsk/fs/exfatfs.c",
        "tsk/fs/fatfs_utils.c",
        "tsk/fs/fatxxfs.c",
        "tsk/fs/fatxxfs_dent.c",
        "tsk/fs/ffind_lib.c",
        "tsk/fs/fs_attrlist.c",
        "tsk/fs/fs_block.c",
        "tsk/fs/fs_inode.c",
        "tsk/fs/fs_io.c",
        "tsk/fs/fs_open.c",
        "tsk/fs/fs_parse.c",
        "tsk/fs/fs_types.c",
        "tsk/fs/lzvn.c",
        "tsk/fs/rawfs.c",
        "tsk/fs/swapfs.c",
        "tsk/hashdb/hashkeeper.c",
        "tsk/img/aff.c",
        "tsk/img/img_types.c",
        "tsk/util/detect_encryption.c",
        "tsk/vs/bsd.c",
        "tsk/vs/dos.c",
        "tsk/vs/gpt.c",
        "tsk/vs/mac.c",
        "tsk/vs/mm_io.c",
        "tsk/vs/mm_open.c",
        "tsk/vs/mm_part.c",
        "tsk/vs/mm_types.c",
        "tsk/vs/sun.c",
    ];
    cfg.out_dir(&build_path)
        .cargo_warnings(false)
        .include(&sleuthkit_out_path)
        .include(sleuthkit_out_path.join("tsk"))
        .files(c_sources.into_iter().map(|f| sleuthkit_out_path.join(f)))
        .compile("tsk");
    // Separate build for C++ files, get the list of files with:
    // make --dry-run VERBOSE=1 tsk/libtsk.la | rg -o 'tsk/[^ ]+\.cpp\b'
    let cpp_sources = [
        "tsk/auto/auto.cpp",
        "tsk/auto/auto.cpp",
        "tsk/auto/auto_db.cpp",
        "tsk/auto/auto_db.cpp",
        "tsk/auto/case_db.cpp",
        "tsk/auto/case_db.cpp",
        "tsk/auto/db_sqlite.cpp",
        "tsk/auto/db_sqlite.cpp",
        "tsk/auto/guid.cpp",
        "tsk/auto/guid.cpp",
        "tsk/auto/is_image_supported.cpp",
        "tsk/auto/is_image_supported.cpp",
        "tsk/auto/tsk_db.cpp",
        "tsk/auto/tsk_db.cpp",
        "tsk/base/tsk_error_win32.cpp",
        "tsk/fs/apfs_compat.cpp",
        "tsk/fs/apfs.cpp",
        "tsk/fs/apfs_fs.cpp",
        "tsk/fs/apfs_open.cpp",
        "tsk/fs/dcalc_lib.cpp",
        "tsk/fs/btrfs.cpp",
        "tsk/fs/btrfs_csum.cpp",
        "tsk/fs/dcat_lib.cpp",
        "tsk/fs/decmpfs.cpp",
        "tsk/fs/dls_lib.cpp",
        "tsk/fs/dstat_lib.cpp",
        "tsk/fs/encryptionHelper.cpp",
        "tsk/fs/exfatfs_dent.cpp",
        "tsk/fs/exfatfs_meta.cpp",
        "tsk/fs/ext2fs.cpp",
        "tsk/fs/ext2fs_dent.cpp",
        "tsk/fs/ext2fs_journal.cpp",
        "tsk/fs/fatfs.cpp",
        "tsk/fs/fatfs_dent.cpp",
        "tsk/fs/fatfs_meta.cpp",
        "tsk/fs/fatxxfs_meta.cpp",
        "tsk/fs/ffs.cpp",
        "tsk/fs/ffs_dent.cpp",
        "tsk/fs/fls_lib.cpp",
        "tsk/fs/fs_attr.cpp",
        "tsk/fs/fs_dir.cpp",
        "tsk/fs/fs_file.cpp",
        "tsk/fs/fs_load.cpp",
        "tsk/fs/fs_name.cpp",
        "tsk/fs/hfs.cpp",
        "tsk/fs/hfs_dent.cpp",
        "tsk/fs/hfs_journal.cpp",
        "tsk/fs/hfs_unicompare.cpp",
        "tsk/fs/icat_lib.cpp",
        "tsk/fs/ifind_lib.cpp",
        "tsk/fs/ils_lib.cpp",
        "tsk/fs/iso9660.cpp",
        "tsk/fs/iso9660_dent.cpp",
        "tsk/fs/logical_fs.cpp",
        "tsk/fs/nofs_misc.cpp",
        "tsk/fs/ntfs.cpp",
        "tsk/fs/ntfs_dent.cpp",
        "tsk/fs/unix_misc.cpp",
        "tsk/fs/usnjls_lib.cpp",
        "tsk/fs/usn_journal.cpp",
        "tsk/fs/walk_cpp.cpp",
        "tsk/fs/yaffs.cpp",
        "tsk/fs/xfs.cpp",
        "tsk/fs/xfs_dent.cpp",
        "tsk/hashdb/binsrch_index.cpp",
        "tsk/hashdb/encase.cpp",
        "tsk/hashdb/hdb_base.cpp",
        "tsk/hashdb/idxonly.cpp",
        "tsk/hashdb/md5sum.cpp",
        "tsk/hashdb/nsrl.cpp",
        "tsk/hashdb/sqlite_hdb.cpp",
        "tsk/hashdb/tsk_hashdb.cpp",
        "tsk/img/aff4.cpp",
        "tsk/img/ewf.cpp",
        "tsk/img/img_io.cpp",
        "tsk/img/img_open.cpp",
        "tsk/img/img_writer.cpp",
        "tsk/img/logical_img.cpp",
        "tsk/img/mult_files.cpp",
        "tsk/img/qcow.cpp",
        "tsk/img/raw.cpp",
        "tsk/img/unsupported_types.cpp",
        "tsk/img/vhd.cpp",
        "tsk/img/vmdk.cpp",
        "tsk/pool/apfs_pool_compat.cpp",
        "tsk/pool/apfs_pool.cpp",
        "tsk/pool/img_bfio_handle.cpp",
        "tsk/pool/lvm_pool_compat.cpp",
        "tsk/pool/lvm_pool.cpp",
        "tsk/pool/pool_open.cpp",
        "tsk/pool/pool_read.cpp",
        "tsk/pool/pool_types.cpp",
        "tsk/util/Bitlocker/BitlockerParser.cpp",
        "tsk/util/Bitlocker/BitlockerUtils.cpp",
        "tsk/util/Bitlocker/DataTypes.cpp",
        "tsk/util/Bitlocker/MetadataEntry.cpp",
        "tsk/util/Bitlocker/MetadataUtils.cpp",
        "tsk/util/Bitlocker/MetadataValueAesCcmEncryptedKey.cpp",
        "tsk/util/Bitlocker/MetadataValueKey.cpp",
        "tsk/util/Bitlocker/MetadataValueOffsetAndSize.cpp",
        "tsk/util/Bitlocker/MetadataValueStretchKey.cpp",
        "tsk/util/Bitlocker/MetadataValueUnicode.cpp",
        "tsk/util/Bitlocker/MetadataValueVolumeMasterKey.cpp",
        "tsk/util/crypto.cpp",
        "tsk/util/file_system_utils.cpp",
    ];
    cfg_cc
        .cargo_warnings(false)
        .out_dir(&build_path)
        .include(&sleuthkit_out_path)
        .include(sleuthkit_out_path.join("tsk"))
        .files(cpp_sources.into_iter().map(|f| sleuthkit_out_path.join(f)))
        .cpp(true)
        .compile("tsk_cc");
}
