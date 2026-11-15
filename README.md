# Access Governance Control Checks

A small work sample built by Araf Abubakar, an applicant for Plaid's Security Engineer, GRC role. It shows the shape of continuous controls monitoring for access governance: take an access dataset, run a fixed set of controls against it on a schedule, and produce an evidence report that names exactly what failed and why.

The script uses Python and access review work, two things I use in my current security work, along with control mapping to ISO/IEC 27001:2022 Annex A and SOC 2. The full write up of my background is in my application; this sample is only about the monitoring idea itself.

## What it does

`ccm_access_governance.py` loads a JSON dataset of user accounts, group memberships, cloud IAM policies, and the organization authentication policy. It evaluates six controls and prints a report with a PASS or FAIL per control, the counts behind each result, and the specific items that failed.

| Control | What it checks | ISO/IEC 27001:2022 | SOC 2 |
| --- | --- | --- | --- |
| AG-01 | MFA enabled on every active account | A.5.17, A.8.5 | CC6.1 |
| AG-02 | No active accounts for terminated users | A.5.15 | CC6.1 |
| AG-03 | Dormant accounts (no login in 90 or more days) flagged for review | A.5.15 | CC6.1 |
| AG-04 | Privileged group memberships have a review on record | A.8.2 | CC6.3 |
| AG-05 | No IAM policy grants wildcard actions such as `*` or `s3:*` | A.8.9 | CC6.6 |
| AG-06 | Authentication policy meets a baseline (length, complexity, lockout, MFA for remote access) | A.5.17 | CC6.1 |

The point of the exercise is the pattern, not the size. Access reviews done by hand tend to happen once a quarter and go stale within weeks. The same checks, written as code and run on a schedule, catch a terminated user's live account or a new wildcard policy grant close to when it happens, and each run leaves dated evidence an auditor can follow.

## How to run it

Python 3, standard library only. Nothing to install.

```bash
python3 ccm_access_governance.py
```

That reads `sample_access_data.json` from the same folder. To check a different dataset with the same shape:

```bash
python3 ccm_access_governance.py path/to/another_dataset.json
```

The script exits with code 1 when any control fails and 0 when all controls pass, so a scheduled job can alert on a failing run.

## Results on the sample data

The sample dataset describes a fictional company, Example Financial Services, with 25 user records, 23 active accounts, and 5 IAM policies. Failures were planted on purpose so the report has something to show. The full captured output is in `sample_output.txt`.

* AG-01 MFA coverage: FAIL. 4 of 23 active accounts have no MFA (Marcus Webb, Tom Becker, Victor Santos, Chris Novak).
* AG-02 Terminated users: FAIL. 2 terminated users still hold active accounts (James Okafor, Kevin Ortiz).
* AG-03 Dormant accounts: PASS. 4 dormant accounts found, and all 4 are flagged for review.
* AG-04 Privileged access reviews: FAIL. 2 of 6 privileged group memberships have no review on record.
* AG-05 Wildcard IAM grants: FAIL. 2 policies grant wildcard actions (LegacyAdminAccess grants `*`, DataExportService grants `s3:*`).
* AG-06 Authentication policy: PASS. The policy meets all four baseline requirements.

Summary: 6 controls checked, 2 passed, 4 failed, 10 failing items in total.

## Scope and honesty notes

* All data is fictional. The company, people, accounts, and policies were invented for this sample. Nothing here comes from any employer or real system.
* This is a prototype. It reads one static JSON file, checks six controls, and prints a text report. It is not connected to any identity provider or cloud account.
* The framework references are a mapping aid, the way a GRC engineer would line a technical check up with the control it supports. Passing one of these checks on its own does not make an organization compliant with ISO 27001 or SOC 2.

## How this would extend in production

These are next steps I would take with a sample like this, stated as a plan rather than experience. First, replace the static file with scheduled pulls from the identity provider and cloud accounts, so the dataset is fresh each run. Second, store every run's report in an evidence store with timestamps, so an auditor can see control performance over time instead of a single snapshot. Third, open a ticket automatically for each failing item, assigned to the team that owns the fix, and close it only when a later run shows the item resolved. Fourth, add trend reporting, since a control that fails a little more each month is a different problem from one bad week. None of that changes the core idea: controls written as checks, run often, with evidence saved every time.

## Files

* `ccm_access_governance.py`: the control checks and report generator.
* `sample_access_data.json`: the fictional dataset, with the planted failures described above.
* `sample_output.txt`: the real output captured from running the script on the sample data.
