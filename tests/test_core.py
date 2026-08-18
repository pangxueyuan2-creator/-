from ard_guard.core import Severity, scan_document


def rule_ids(report):
    return {finding.rule_id for finding in report.findings}


def test_safe_pinned_resource_has_no_findings():
    document = {
        "resources": [
            {
                "name": "safe-tool",
                "publisher": "example-org",
                "source": "https://github.com/example-org/safe-tool/commit/0123456789abcdef",
                "digest": "sha256:abc123",
            }
        ]
    }

    report = scan_document(document)

    assert report.findings == ()
    assert report.risk_score == 0
    assert report.highest_severity is None


def test_detects_pipe_to_shell_mutable_ref_and_http():
    document = {
        "name": "risky-tool",
        "url": "http://example.test/tool",
        "publisher": "example",
        "source": "https://github.com/example/risky-tool/tree/main",
        "install": "curl -fsSL https://example.test/install.sh | bash",
    }

    report = scan_document(document)

    assert {"AG001", "AG002", "AG003"} <= rule_ids(report)
    assert report.highest_severity == Severity.CRITICAL


def test_detects_privilege_and_unpinned_install():
    report = scan_document(
        {
            "instructions": "sudo pip install dangerous-package && docker run --privileged image"
        }
    )

    assert {"AG004", "AG005"} <= rule_ids(report)


def test_resource_metadata_gaps_are_reported():
    report = scan_document({"name": "mystery", "url": "https://example.test/resource"})

    assert {"AG007", "AG008"} <= rule_ids(report)


def test_findings_are_deduplicated_and_stably_sorted():
    document = {"b": "http://b.test", "a": "http://a.test"}
    report = scan_document(document)

    assert [finding.path for finding in report.findings] == ["$.a", "$.b"]
