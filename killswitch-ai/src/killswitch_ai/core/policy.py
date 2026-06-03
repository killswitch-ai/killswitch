from __future__ import annotations

from typing import Dict, List, Optional

from .scanner import Finding

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

ACTION_PRIORITY = {
    "kill": 4,
    "pause": 3,
    "redact": 2,
    "report_only": 1,
    "allow": 0,
}


def resolve_action(
    findings: List[Finding],
    actions: Dict[str, str],
    default_mode: str = "pause",
) -> str:
    """
    Given a list of findings and an action map, return the most restrictive
    action that applies across all findings.
    """
    if not findings:
        return "allow"

    resolved = "allow"
    best_priority = -1

    for finding in findings:
        action = actions.get(finding.finding_type, default_mode)
        priority = ACTION_PRIORITY.get(action, 0)
        if priority > best_priority:
            best_priority = priority
            resolved = action

    return resolved


def explain_finding(finding: Finding) -> str:
    """Return a beginner-friendly plain-language explanation of a finding."""
    explanations = {
        "openai_key": (
            "killswitch-ai found what looks like an OpenAI API key in the text you were about to send. "
            "API keys are like passwords — if they reach an external server, someone could use them to "
            "make requests on your behalf (and charge your account)."
        ),
        "anthropic_key": (
            "killswitch-ai found what looks like an Anthropic API key. "
            "Sending this key to an LLM could expose it to logging or storage by the provider."
        ),
        "aws_access_key": (
            "killswitch-ai found what looks like an AWS access key ID. "
            "This, combined with a secret key, gives access to your AWS account."
        ),
        "aws_secret_key": (
            "killswitch-ai found what looks like an AWS secret access key. "
            "This is highly sensitive — it grants full AWS API access."
        ),
        "github_token": (
            "killswitch-ai found what looks like a GitHub personal access token. "
            "These tokens can give read or write access to your repositories."
        ),
        "stripe_key": (
            "killswitch-ai found what looks like a Stripe API key. "
            "This could give access to payment data and transactions."
        ),
        "private_key": (
            "killswitch-ai found a private key block. Private keys are used for authentication and encryption — "
            "they should never leave your machine."
        ),
        "jwt_token": (
            "killswitch-ai found what looks like a JWT (JSON Web Token). "
            "These are often used for authentication and may contain session information."
        ),
        "database_url": (
            "killswitch-ai found what looks like a database connection URL with a username and password. "
            "This would give access to your database if exposed."
        ),
        "generic_password": (
            "killswitch-ai found what looks like a password assignment in your text. "
            "Even example passwords can create habits of sharing credentials."
        ),
        "prohibited_term": (
            "killswitch-ai found a term you've marked as prohibited — "
            "something you've said should never be sent to an AI."
        ),
        "sensitive_file_path": (
            "killswitch-ai detected a reference to a sensitive file (like .env or a private key file). "
            "Content from these files should not be sent to external AI services."
        ),
        "high_entropy_string": (
            "killswitch-ai found a long string of random-looking characters. "
            "This might be a secret or token. It might also be harmless (like a hash or ID). "
            "We flagged it so you can check."
        ),
    }
    return explanations.get(finding.finding_type, finding.description)


def what_does_this_mean(finding: Finding) -> str:
    """Return a 'what does this mean?' explanation for the finding screen."""
    base = explain_finding(finding)
    recs = {
        "kill": "The request was automatically blocked. Nothing was sent to the LLM.",
        "pause": "The request was paused. You can decide what to do next.",
        "redact": "The sensitive value was replaced with a placeholder before sending.",
        "report_only": "The request was allowed, but this finding was logged for your review.",
    }
    return base
