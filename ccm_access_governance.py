#!/usr/bin/env python3
"""Access governance control checks over a fictional access dataset.

Reads a JSON export of user accounts, group memberships, IAM policies,
and the organization authentication policy, then evaluates six access
governance controls and prints an evidence report with a PASS or FAIL
per control. Each control is mapped to ISO/IEC 27001:2022 Annex A and
to SOC 2 (CC6 and CC7).

Standard library only. Run it with:

    python3 ccm_access_governance.py [path-to-dataset.json]

With no argument it reads sample_access_data.json next to this script.
Exit code is 1 when any control fails and 0 when all controls pass,
so the script can sit in a scheduled job and alert on failure.
"""

import json
import sys
from pathlib import Path

DORMANT_THRESHOLD_DAYS = 90
BASELINE_MIN_PASSWORD_LENGTH = 12


def is_active_account(user):
    return user.get("account_status") == "active"


def check_mfa(users):
    """MFA enforced for all active accounts."""
    scoped = [u for u in users if is_active_account(u)]
    failing = [u for u in scoped if not u.get("mfa_enabled")]
    items = [
        f"{u['name']} ({u['user_id']}, {u['department']}): MFA not enabled"
        for u in failing
    ]
    return {
        "id": "AG-01",
        "name": "MFA enforced for all active accounts",
        "iso": "A.5.17, A.8.5",
        "soc2": "CC6.1",
        "checked_label": "active accounts checked",
        "checked": len(scoped),
        "items_label": "Accounts without MFA",
        "items": items,
    }


def check_terminated(users):
    """No active accounts remain for terminated users."""
    failing = [
        u
        for u in users
        if u.get("employment_status") == "terminated" and is_active_account(u)
    ]
    items = [
        f"{u['name']} ({u['user_id']}, {u['department']}): employment status "
        f"is terminated but the account is still active"
        for u in failing
    ]
    return {
        "id": "AG-02",
        "name": "No active accounts for terminated users",
        "iso": "A.5.15",
        "soc2": "CC6.1",
        "checked_label": "user records checked",
        "checked": len(users),
        "items_label": "Terminated users with active accounts",
        "items": items,
    }


def check_dormant(users):
    """Dormant accounts are identified and flagged for review."""
    dormant = [
        u
        for u in users
        if is_active_account(u)
        and u.get("last_login_days_ago", 0) >= DORMANT_THRESHOLD_DAYS
    ]
    unflagged = [u for u in dormant if not u.get("dormant_review_flagged")]
    items = [
        f"{u['name']} ({u['user_id']}, {u['department']}): last login "
        f"{u['last_login_days_ago']} days ago, not flagged for review"
        for u in unflagged
    ]
    evidence = [
        f"{u['name']} ({u['user_id']}): last login {u['last_login_days_ago']} "
        f"days ago, flagged for review"
        for u in dormant
        if u.get("dormant_review_flagged")
    ]
    return {
        "id": "AG-03",
        "name": f"Dormant accounts (no login in {DORMANT_THRESHOLD_DAYS}+ days) "
        "identified for review",
        "iso": "A.5.15",
        "soc2": "CC6.1",
        "checked_label": "active accounts checked",
        "checked": len([u for u in users if is_active_account(u)]),
        "items_label": "Dormant accounts not flagged for review",
        "items": items,
        "evidence": evidence,
    }


def check_privileged(users, privileged_groups):
    """Privileged group membership is limited and review evidence exists."""
    members = []
    for u in users:
        if not is_active_account(u):
            continue
        for group in u.get("groups", []):
            if group in privileged_groups:
                members.append((u, group))
    failing = [(u, g) for (u, g) in members if not u.get("privileged_access_reviewed")]
    items = [
        f"{u['name']} ({u['user_id']}, {u['department']}): member of {g}, "
        f"no privileged access review on record"
        for (u, g) in failing
    ]
    return {
        "id": "AG-04",
        "name": "Privileged group membership limited and reviewed",
        "iso": "A.8.2",
        "soc2": "CC6.3",
        "checked_label": "privileged group memberships checked",
        "checked": len(members),
        "items_label": "Privileged memberships without a review on record",
        "items": items,
    }


def check_wildcard_policies(policies):
    """No IAM policy grants wildcard admin actions."""
    findings = []
    for policy in policies:
        for statement in policy.get("statements", []):
            if statement.get("effect") != "Allow":
                continue
            for action in statement.get("actions", []):
                if action == "*" or action.endswith(":*"):
                    findings.append(
                        f"{policy['policy_name']} (attached to "
                        f"{policy.get('attached_to', 'unknown')}): Allow on "
                        f"action '{action}'"
                    )
    return {
        "id": "AG-05",
        "name": "No wildcard admin actions in IAM policies",
        "iso": "A.8.9",
        "soc2": "CC6.6",
        "checked_label": "IAM policies checked",
        "checked": len(policies),
        "items_label": "Wildcard grants",
        "items": findings,
    }


def check_auth_policy(data):
    """Authentication policy evidence exists and meets the baseline."""
    policy = data.get("authentication_policy")
    if not policy:
        return {
            "id": "AG-06",
            "name": "Authentication policy meets baseline requirements",
            "iso": "A.5.17",
            "soc2": "CC6.1",
            "checked_label": "policy requirements checked",
            "checked": 0,
            "items_label": "Baseline gaps",
            "items": ["No authentication policy present in the dataset"],
        }
    gaps = []
    min_length = policy.get("minimum_password_length", 0)
    if min_length < BASELINE_MIN_PASSWORD_LENGTH:
        gaps.append(
            f"Minimum password length is {min_length}, baseline is "
            f"{BASELINE_MIN_PASSWORD_LENGTH}"
        )
    if not policy.get("complexity_required"):
        gaps.append("Password complexity is not required")
    if not policy.get("account_lockout_threshold_attempts"):
        gaps.append("No account lockout threshold is set")
    if not policy.get("mfa_required_for_remote_access"):
        gaps.append("MFA is not required for remote access")
    evidence = [
        f"Minimum password length: {policy.get('minimum_password_length')}",
        f"Complexity required: {policy.get('complexity_required')}",
        f"Account lockout threshold (attempts): "
        f"{policy.get('account_lockout_threshold_attempts')}",
        f"MFA required for remote access: "
        f"{policy.get('mfa_required_for_remote_access')}",
        f"Maximum password age (days): {policy.get('maximum_password_age_days')}",
    ]
    return {
        "id": "AG-06",
        "name": "Authentication policy meets baseline requirements",
        "iso": "A.5.17",
        "soc2": "CC6.1",
        "checked_label": "policy requirements checked",
        "checked": 4,
        "items_label": "Baseline gaps",
        "items": gaps,
        "evidence": evidence,
    }


def print_report(data, results):
    users = data.get("users", [])
    policies = data.get("iam_policies", [])
    lines = []
    lines.append("Access Governance Control Check")
    lines.append("================================")
    lines.append(f"Organization: {data.get('organization', 'unknown')}")
    lines.append(f"Dataset exported at: {data.get('exported_at', 'unknown')}")
    lines.append(
        f"Scope: {len(users)} user records, "
        f"{len([u for u in users if is_active_account(u)])} active accounts, "
        f"{len(policies)} IAM policies"
    )
    lines.append("")
    passed = 0
    total_failing_items = 0
    for result in results:
        status = "FAIL" if result["items"] else "PASS"
        if status == "PASS":
            passed += 1
        total_failing_items += len(result["items"])
        compliant = result["checked"] - len(result["items"])
        lines.append(f"[{status}] {result['id']}: {result['name']}")
        lines.append(
            f"    Mapping: ISO/IEC 27001:2022 {result['iso']} | SOC 2 {result['soc2']}"
        )
        lines.append(
            f"    Checked: {result['checked']} ({result['checked_label']}); "
            f"compliant: {compliant}; failing: {len(result['items'])}"
        )
        if result.get("evidence"):
            lines.append("    Evidence:")
            for entry in result["evidence"]:
                lines.append(f"      - {entry}")
        if result["items"]:
            lines.append(f"    {result['items_label']}:")
            for entry in result["items"]:
                lines.append(f"      - {entry}")
        lines.append("")
    lines.append("Summary")
    lines.append("--------")
    lines.append(
        f"Controls checked: {len(results)}; passed: {passed}; "
        f"failed: {len(results) - passed}"
    )
    lines.append(f"Total failing items: {total_failing_items}")
    return "\n".join(lines), passed


def main(argv):
    if len(argv) > 1:
        data_path = Path(argv[1])
    else:
        data_path = Path(__file__).with_name("sample_access_data.json")
    with data_path.open() as handle:
        data = json.load(handle)

    users = data.get("users", [])
    results = [
        check_mfa(users),
        check_terminated(users),
        check_dormant(users),
        check_privileged(users, data.get("privileged_groups", [])),
        check_wildcard_policies(data.get("iam_policies", [])),
        check_auth_policy(data),
    ]
    report, passed = print_report(data, results)
    print(report)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
