# Synthetic web vulnerability dataset v1

This dataset is a local AI knowledge/training source for web vulnerability
explanations. It contains ten CWE-labelled synthetic scenarios with server
logs, detection logic and secure remediation examples.

It is intentionally separate from the endpoint entropy dataset because its
features are text and structured web telemetry rather than file measurements.
The records are not executed. Before a classifier is enabled, each category
needs additional independently generated examples and a held-out evaluation
set.
