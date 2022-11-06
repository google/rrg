fn main() {
    #[cfg(all(target_os = "linux", feature = "action-platform-info"))]
    {
        println!("cargo:rerun-if-changed=src/action/libc_version.c");

        cc::Build::new()
            .file("src/action/libc_version.c")
            .compile("liblibc_version.a");
    }
}
