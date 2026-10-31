# PS-033 Project Report

## 1. Problem statement
Describe the challenge of discovering diagnostic services without hardcoding every endpoint.

## 2. Proposed solution
Explain DNS TXT metadata discovery, DNSSEC RRSIG verification against the pinned local DNSKEY, metadata validation and authenticated invocation.

## 3. Architecture
Insert the architecture diagram from the README and describe each component.

## 4. Implementation
Summarize `dns_lab.py`, `discovery.py`, `services.py` and `app.py`.

## 5. Test results
Record results for the three successful service calls and the four negative cases. Attach screenshots where appropriate.

## 6. Limitations
State clearly that this is a localhost educational prototype, uses a locally pinned trust anchor, and simulates latency/traceroute results.

## 7. Future improvements
Discuss full DNSSEC chain validation, stronger credential provisioning, deployment hardening and real diagnostic integrations (outside this safe demo).
