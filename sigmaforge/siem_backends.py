"""
SIEM backend mapping for SigmaForge.

Maps user-facing SIEM names to sigma-cli backend IDs and pip package names.
Based on SigmaHQ pySigma plugin directory and community backends.
"""

# Display name -> (sigma-cli backend id, pip package for optional install hint)
SIEM_BACKENDS = {
    "splunk": ("splunk", "pysigma-backend-splunk"),
    "elasticsearch": ("elasticsearch", "pysigma-backend-elasticsearch"),
    "elk": ("elasticsearch", "pysigma-backend-elasticsearch"),  # alias
    "azure-sentinel": ("kusto", "pysigma-backend-kusto"),
    "microsoft-sentinel": ("kusto", "pysigma-backend-kusto"),  # alias
    "kusto": ("kusto", "pysigma-backend-kusto"),
    "ibm-qradar": ("qradar", "pysigma-backend-qradar"),
    "qradar": ("qradar", "pysigma-backend-qradar"),
    "ibm-qradar-aql": ("ibm-qradar-aql", "pysigma-backend-qradar-aql"),
    "logpoint": ("logpoint", "pysigma-backend-logpoint"),
    "sentinelone": ("sentinelone", "pysigma-backend-sentinelone"),
    "crowdstrike": ("crowdstrike", "pysigma-backend-crowdstrike"),
    "trellix-helix": ("trellix_helix", "pysigma-backend-helix"),
    "helix": ("trellix_helix", "pysigma-backend-helix"),
    "opensearch": ("opensearch", "pysigma-backend-opensearch"),
    "rapid7-insightidr": ("insightidr", "pysigma-backend-insightidr"),
    "insightidr": ("insightidr", "pysigma-backend-insightidr"),
    "cortex-xdr": ("cortexxdr", "pysigma-backend-cortexxdr"),
    "cortexxdr": ("cortexxdr", "pysigma-backend-cortexxdr"),
    "carbon-black": ("carbonblack", "pysigma-backend-carbonblack"),
    "carbonblack": ("carbonblack", "pysigma-backend-carbonblack"),
    "panther": ("panther", "pysigma-backend-panther"),
    "datadog": ("datadog", "pysigma-backend-datadog"),
    "loki": ("loki", "pysigma-backend-loki"),
    "grafana-loki": ("loki", "pysigma-backend-loki"),
    "netwitness": ("netwitness", "pysigma-backend-netwitness"),
    "wazuh": ("elasticsearch", "pysigma-backend-elasticsearch"),  # Wazuh indexer is Elastic-based
    "graylog": ("elasticsearch", "pysigma-backend-elasticsearch"),  # Lucene-style queries
}

# Human-readable list for --list-siem
SIEM_DISPLAY_ORDER = [
    "splunk",
    "elasticsearch",
    "azure-sentinel",
    "ibm-qradar",
    "crowdstrike",
    "sentinelone",
    "logpoint",
    "trellix-helix",
    "opensearch",
    "rapid7-insightidr",
    "cortex-xdr",
    "carbon-black",
    "panther",
    "datadog",
    "loki",
    "netwitness",
    "wazuh",
    "graylog",
]

# SIEMs that don't have a native pySigma backend yet (documented for roadmap)
SIEM_COMING_SOON = [
    "exabeam",
    "logrhythm",
    "securonix",
    "arcsight",
    "fortinet-fortisiem",
    "fortisiem",
]
