from sentinel.yara.engine import load_rules, match_bytes, match_file

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_bundled_rules_load():
    rules = load_rules()
    names = {r.name for r in rules}
    assert "EICAR_Test_File" in names
    assert "PowerShell_EncodedCommand" in names


def test_eicar_yara_hit():
    hits = match_bytes(EICAR)
    rules = {h["rule"] for h in hits}
    assert "EICAR_Test_File" in rules


def test_clean_bytes_no_eicar():
    hits = match_bytes(b"nothing to see here")
    assert all(h["rule"] != "EICAR_Test_File" for h in hits)


def test_sample_eicar_file(samples_dir):
    hits = match_file(samples_dir / "eicar.com.txt")
    assert any(h["rule"] == "EICAR_Test_File" for h in hits)


def test_macro_lure_yara(samples_dir):
    hits = match_file(samples_dir / "macro_lure.txt")
    names = {h["rule"] for h in hits}
    assert "PowerShell_EncodedCommand" in names
    assert "VBA_Macro_Keywords" in names
