from pathlib import Path

from sentinel.scan.hashing import hash_bytes, hash_file

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_eicar_hash_constants():
    md5, sha1, sha256 = hash_bytes(EICAR)
    assert md5 == EICAR_MD5
    assert sha1 == EICAR_SHA1
    assert sha256 == EICAR_SHA256


def test_hash_file_matches_bytes(tmp_path: Path):
    path = tmp_path / "eicar.com"
    path.write_bytes(EICAR)
    assert hash_file(path) == hash_bytes(EICAR)


def test_sample_eicar_hash(samples_dir: Path):
    md5, sha1, sha256 = hash_file(samples_dir / "eicar.com.txt")
    assert md5 == EICAR_MD5
    assert sha1 == EICAR_SHA1
    assert sha256 == EICAR_SHA256
