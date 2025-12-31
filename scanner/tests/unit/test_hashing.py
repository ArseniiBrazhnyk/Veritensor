import pytest
from veritensor.engines.hashing.calculator import calculate_sha256

def test_calculate_sha256_regular_file(tmp_path):
    # Creating a regular file
    f = tmp_path / "model.bin"
    f.write_bytes(b"hello world")
    
    # echo -n "hello world" | sha256sum
    expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert calculate_sha256(f) == expected

def test_calculate_sha256_lfs_pointer(tmp_path):
    # Creating a fake LFS pointer
    lfs_content = (
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:1111111111111111111111111111111111111111111111111111111111111111\n"
        "size 12345\n"
    )
    f = tmp_path / "model.lfs"
    f.write_text(lfs_content)

    # Veritensor should return the OID from the text, not the hash of the text itself!
    expected_oid = "1111111111111111111111111111111111111111111111111111111111111111"
    assert calculate_sha256(f) == expected_oid
