# Fuzzing

This directory contains fuzz targets for RRG, designed to run with `cargo-fuzz` and `libFuzzer`.

## Usage

To run a specific fuzzer:

```bash
cargo fuzz list
cargo fuzz run fuzz_action_get_filesystem_timeline
```

## Seed corpora

### `disk_images_corpus.zip`

This archive contains small, valid filesystem images used specifically by `fuzz_action_get_file_contents_kmx` and TSK fuzzer soon. The parsers require structurally valid disk images (NTFS, ext4, fat32...) to function; the fuzzer wastes too much time trying to guess the magic values, like `EB 52 90` for NTFS, starting from random bytes.

**Local Usage**

To use these seeds locally, unpack the archive into the target's corpus directory before running the fuzzer:

```bash
mkdir -p fuzz/corpus/fuzz_action_get_file_contents_kmx
unzip fuzz/disk_images_corpus.zip -d fuzz/corpus/fuzz_action_get_file_contents_kmx/
cargo fuzz run fuzz_action_get_file_contents_kmx
```

**Disk corpus generation**

These images were generated using the following commands:

```bash
# Fat32 (2MB)
dd if=/dev/zero of=small_fat32.img bs=1M count=2
mkfs.vfat small_fat32.img

# ext4 (2MB)
dd if=/dev/zero of=small_ext4.img bs=1M count=2
mkfs.ext4 -F small_ext4.img
echo "Secret Content" > secret.txt
debugfs -w -R "mkdir /test_dir" small_ext4.img
debugfs -w -R "write secret.txt /test_dir/secret.txt" small_ext4.img

# NTFS (2MB)
dd if=/dev/zero of=small_ntfs.img bs=1M count=2
mkfs.ntfs -F -f small_ntfs.img

# MBR (2MB)
dd if=/dev/zero of=disk_mbr.img bs=1M count=2
echo "start=2048, type=83" | sfdisk disk_mbr.img
```