# W6-004 application rollback record

## Result

Operation `application-rollback-001` is classified
**PASS_WITH_TELEMETRY_GAP**.

## Exercise

1. Recorded the final Stage 6/Stage 7 application digest as known-good:
   `sha256:efaafe47204afbd4a092f675f3a60fc3575abad288e89e8f73692b053d22dd55`.
2. Deployed regression digest:
   `sha256:e188ad90268763165d9acf46eae0a238f45245242637435ad15a4e6b2ef339cc`.
3. Verified two ready replicas ran the regression digest.
4. Restored the exact known-good digest using validated UTF-8 patch files.
5. Verified two ready replicas ran the restored digest.
6. Re-ran health, authentication, retrieval, Bedrock and security-denial
   checks.

## Restored behavior

| Check | Result |
|---|---|
| Known-good digest and two ready replicas | **PASS** |
| Health | **PASS** |
| Authentication | **PASS** |
| Retrieval | **PASS** |
| Approved Bedrock model | **PASS** |
| Security denials | **PASS** |

## Telemetry limitation

X-Ray contained 626 traces, 31,312 CloudWatch log events were retained, no
unsafe log match was found and two SNS subscriptions were confirmed. However,
the queried application and alarm metric windows contained zero datapoints;
the availability-burn and safety alarms remained `INSUFFICIENT_DATA`.
Telemetry is therefore `PARTIAL`, not PASS.

Authoritative result:
`E:\AI\evidence\enterprise_ai_platform\w6-004\application-rollback-001\rollback-final-result.json`

SHA-256:
`348588e79b4a4624b30547d94fe70dfe4884c5233ab75d63c05ed61983cfa833`.

## Final Owner Approval

- Reviewer, decision and timestamp: **PENDING COLUMN N**.
- Tracker update responsibility: **Owner**.
