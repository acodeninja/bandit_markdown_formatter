import logging

LOG = logging.getLogger(__name__)


def markdown(manager, fileobj, sev_level, conf_level, lines=-1):
    header_block = """# Bandit Report

{metrics}

## Issues

"""
    metrics_block = """
**High Severity**: {severity_high}

**Medium Severity**: {severity_medium}

**Low Severity**: {severity_low}

**Undefined Severity**: {severity_undefined}

**Lines of Code**: {loc}

**Lines Purposefully Skipped**: {nosec}
"""
    issue_block = """
### {issue_text}

**Test**: {test_name} ({test_id})

**Severity**: {issue_severity}

**Confidence**: {issue_confidence}

[CWE Details]({issue_cwe_link})

`{filename}`

```
{code}
```

"""

    result = header_block.format(
        metrics=metrics_block.format(
            severity_high=manager.metrics.data["_totals"]["SEVERITY.HIGH"],
            severity_medium=manager.metrics.data["_totals"]["SEVERITY.MEDIUM"],
            severity_low=manager.metrics.data["_totals"]["SEVERITY.LOW"],
            severity_undefined=manager.metrics.data["_totals"]["SEVERITY.UNDEFINED"],
            loc=manager.metrics.data["_totals"]["loc"],
            nosec=manager.metrics.data["_totals"]["nosec"],
        )
    )

    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    for index, issue in enumerate(issues):
        result += issue_block.format(
            issue_text=issue.text,
            test_name=issue.test,
            test_id=issue.test_id,
            issue_severity=issue.severity,
            issue_confidence=issue.confidence,
            issue_cwe_link=issue.cwe.link(),
            filename=issue.fname,
            code=issue.get_code().strip("\n").lstrip(" "),
        )

    with fileobj:
        fileobj.write(result)
