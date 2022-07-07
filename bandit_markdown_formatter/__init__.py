import bandit
from typing import List
from jinja2 import Environment, BaseLoader
from functools import reduce


def markdown(manager, fileobj, sev_level, conf_level, lines=-1):
    env = Environment(loader=BaseLoader())
    template = env.from_string(__TEMPLATE__)

    class IssueAlert:
        def __init__(
                self,
                title: str,
                test: str,
                test_id: str,
                severity: str,
                cwe: bandit.Cwe,
                instances: List[bandit.Issue]
        ):
            self.title: str = title
            self.test: str = test
            self.test_id: str = test_id
            self.severity: str = severity
            self.cwe: bandit.Cwe = cwe
            self.instances: List[bandit.Issue] = instances

    def combine_tests(accumulator, new_test):
        if new_test.test in accumulator:
            accumulator[new_test.test].instances.append(new_test)
        else:
            accumulator[new_test.test] = IssueAlert(
                title=new_test.text,
                test=new_test.test,
                test_id=new_test.test_id,
                severity=new_test.severity,
                cwe=new_test.cwe,
                instances=[new_test]
            )

        return accumulator

    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    severity_sort_order = {'HIGH': 0, 'MEDIUM': 1000, 'LOW': 2000, 'UNDEFINED': 3000}
    alerts = reduce(combine_tests, issues, {}).values()
    sorted_alerts = sorted(alerts, key=lambda x: severity_sort_order[x.severity] - len(x.instances))

    with fileobj:
        fileobj.write(template.render(
            title='Bandit Report',
            alerts=sorted_alerts,
            metrics={
                'high': manager.metrics.data["_totals"]["SEVERITY.HIGH"],
                'medium': manager.metrics.data["_totals"]["SEVERITY.MEDIUM"],
                'low': manager.metrics.data["_totals"]["SEVERITY.LOW"],
                'undefined': manager.metrics.data["_totals"]["SEVERITY.UNDEFINED"],
                'loc': manager.metrics.data["_totals"]["loc"],
                'nosec': manager.metrics.data["_totals"]["nosec"],
            },
        ))


__TEMPLATE__ = """# {{ title }}

## Summary of Alerts

| Risk Level |        Number of Alerts |
|:-----------|------------------------:|
| High       | {{ (metrics.high | string).rjust(23) }} |
| Medium     | {{ (metrics.medium | string).rjust(23) }} |
| Low        | {{ (metrics.low | string).rjust(23) }} |
| Undefined  | {{ (metrics.undefined | string).rjust(23) }} |

| Test | Number of Alerts | Severity |
|:---|---|---:|
{% for alert in alerts -%}
| {{ alert.test | replace('_', ' ') | title }} | {{ alert.instances | length | string }} | {{ alert.severity }} |
{% endfor %}

## Alert Details

{% for alert in alerts -%}
### {{ alert.test | replace('_', ' ') | title }} ({{ alert.test_id }}) ({{ alert.severity }})

{{ alert.title }}

[CWE-{{ alert.cwe.id }}]({{ alert.cwe.link() }})

#### Instances
{% for instance in alert.instances %}
`{{ instance.fname }}` (With a {{ instance.confidence | title }} confidence)
```python
{{ instance.get_code().strip("\n").lstrip(" ") }}
```
{% endfor %}
{% endfor %}
"""
