from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from .normalizer import ScanUnit

SENSITIVE_FILE_PATTERNS = [
    re.compile(r"(^|[\s/\"'])\.env(\b|\.|\s|['\"]|$)", re.IGNORECASE),
    re.compile(r"\.env\.(local|prod|production|staging|development)", re.IGNORECASE),
    re.compile(r"\.(pem|key|p12|pfx|cer|crt)(\b|[\"'\s]|$)", re.IGNORECASE),
    re.compile(r"(^|[\s/\"'])(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\b|[\"'\s]|$)", re.IGNORECASE),
    re.compile(r"credentials\.json", re.IGNORECASE),
    re.compile(r"service[_-]?account\.json", re.IGNORECASE),
    re.compile(r"(^|[\s/])\.npmrc(\b|\s|$)", re.IGNORECASE),
    re.compile(r"(^|[\s/])\.netrc(\b|\s|$)", re.IGNORECASE),
    re.compile(r"kubeconfig", re.IGNORECASE),
    re.compile(r"(~|home)/\.aws/credentials", re.IGNORECASE),
    re.compile(r"(~|home)/\.ssh/", re.IGNORECASE),
]

SECRET_PATTERNS: List[tuple[str, str, str, re.Pattern]] = [
    ("openai_key",       "critical", "Possible OpenAI API key",           re.compile(r"sk-(?:proj-|o1-)?[A-Za-z0-9_\-]{20,}")),
    ("anthropic_key",    "critical", "Possible Anthropic API key",         re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("aws_access_key",   "critical", "Possible AWS access key ID",         re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",   "critical", "Possible AWS secret access key",     re.compile(r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("github_token",     "critical", "Possible GitHub token",              re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("stripe_key",       "critical", "Possible Stripe API key",            re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("private_key",      "critical", "Private key block detected",         re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("jwt_token",        "high",     "Possible JWT token",                 re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("database_url",     "high",     "Possible database URL with credentials", re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^:\s]+:[^@\s]+@[^\s]+")),
    ("generic_password", "medium",   "Password assignment detected",       re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?")),
]

PROHIBITED_TERM_PATTERNS = [
    re.compile(r"\bAPI[_\-\s]?KEY\b", re.IGNORECASE),
    re.compile(r"\bSECRET[_\-\s]?KEY\b", re.IGNORECASE),
    re.compile(r"\bAWS[_\-\s]?SECRET[_\-\s]?ACCESS[_\-\s]?KEY\b", re.IGNORECASE),
    re.compile(r"\bPRIVATE\s+KEY\b", re.IGNORECASE),
    re.compile(r"\bDO[_\-\s]?NOT[_\-\s]?SEND[_\-\s]?TO[_\-\s]?AI\b", re.IGNORECASE),
    re.compile(r"\bCONFIDENTIAL\b", re.IGNORECASE),
]

DUMMY_VALUES = {
    "your_api_key_here", "sk-example", "sk-test", "dummy-token",
    "your-key-here", "replace-me", "placeholder", "xxxx", "1234",
    "test", "example", "changeme", "your_secret_here",
}


def _generate_finding_id() -> str:
    now = datetime.now(timezone.utc)
    short = uuid.uuid4().hex[:6]
    return f"KAI-F-{now.strftime('%Y%m%d')}-{short}"


@dataclass
class Finding:
    finding_id: str = field(default_factory=_generate_finding_id)
    severity: str = "medium"
    category: str = "unknown"
    finding_type: str = "unknown"
    description: str = ""
    recommendation: str = "Review and remove this content before sending to an LLM."
    scan_path: str = ""
    match_start: int = 0
    match_end: int = 0
    matched_text_preview: str = ""

    def plain_description(self) -> str:
        desc = self.description
        if self.matched_text_preview:
            preview = self.matched_text_preview
            if len(preview) > 30:
                preview = preview[:15] + "..." + preview[-5:]
            desc += f" (matched: {preview})"
        return desc


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    scanned_units: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> Optional[str]:
        order = ["critical", "high", "medium", "low"]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s
        return None


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_dummy(value: str) -> bool:
    return value.lower().strip() in DUMMY_VALUES


def scan_text(
    text: str,
    path: str = "",
    extra_prohibited_terms: Optional[List[str]] = None,
    entropy_enabled: bool = True,
    entropy_min_length: int = 24,
    entropy_threshold: float = 4.2,
    source_file: Optional[str] = None,
) -> List[Finding]:
    from .. import verbose as _v

    findings: List[Finding] = []

    if _is_dummy(text):
        _v.v2(f"  Text looks like a placeholder/example — skipping scan.")
        return findings

    # ── Step 1: known secret patterns ────────────────────────────────────────
    _v.v2(f"  Step 1: Checking {len(SECRET_PATTERNS)} known secret patterns...")
    _v.v2(f"          (OpenAI keys, AWS keys, GitHub tokens, Stripe keys, JWTs, etc.)")

    for pattern_type, severity, description, pattern in SECRET_PATTERNS:
        found = False
        for m in pattern.finditer(text):
            matched = m.group(0)
            if _is_dummy(matched):
                continue
            found = True
            findings.append(Finding(
                severity=severity,
                category="secret_pattern",
                finding_type=pattern_type,
                description=description,
                recommendation=f"Remove the {pattern_type.replace('_', ' ')} from the prompt and rotate it if it may have been exposed.",
                scan_path=path,
                match_start=m.start(),
                match_end=m.end(),
                matched_text_preview=matched[:40] if matched else "",
            ))
        if _v.is_super():
            status = f"MATCH → {severity.upper()}: \"{description}\"" if found else "no match"
            _v.v2(f"    {pattern_type:<22} ... {status}")

    # ── Step 2: prohibited terms ──────────────────────────────────────────────
    prohibited = list(PROHIBITED_TERM_PATTERNS)
    if extra_prohibited_terms:
        for term in extra_prohibited_terms:
            try:
                prohibited.append(re.compile(re.escape(term), re.IGNORECASE))
            except re.error:
                pass

    custom_count = len(extra_prohibited_terms) if extra_prohibited_terms else 0
    _v.v2(f"  Step 2: Checking prohibited terms "
          f"({len(PROHIBITED_TERM_PATTERNS)} built-in + {custom_count} custom)...")
    _v.v2(f"          (Words like API_KEY, SECRET_KEY, CONFIDENTIAL, or your own custom terms)")

    for pattern in prohibited:
        for m in pattern.finditer(text):
            matched = m.group(0)
            if not any(f.match_start == m.start() and f.scan_path == path for f in findings):
                findings.append(Finding(
                    severity="medium",
                    category="prohibited_term",
                    finding_type="prohibited_term",
                    # NOTE: description must NOT include the matched substring
                    # because it is persisted to disk in findings.jsonl.  The
                    # finding_type field already identifies the category.
                    description="Prohibited term detected in prompt",
                    recommendation="Remove or replace this term before sending to an LLM.",
                    scan_path=path,
                    match_start=m.start(),
                    match_end=m.end(),
                    matched_text_preview=matched,  # in-memory only; not written to disk
                ))
                if _v.is_super():
                    _v.v2(f"    Prohibited term found: \"{matched}\"")

    # ── Step 3: sensitive file references ────────────────────────────────────
    _v.v2(f"  Step 3: Checking for sensitive file references (.env, .pem, id_rsa, etc.)...")

    file_finding_added = False
    if source_file:
        for fp in SENSITIVE_FILE_PATTERNS:
            if fp.search(source_file):
                findings.append(Finding(
                    severity="high",
                    category="sensitive_file",
                    finding_type="sensitive_file_path",
                    description=f"Content from sensitive file: {source_file}",
                    recommendation=f"Do not send content from {source_file} to an LLM.",
                    scan_path=path,
                ))
                file_finding_added = True
                if _v.is_super():
                    _v.v2(f"    Source file is sensitive: {source_file}")
                break

    for fp in SENSITIVE_FILE_PATTERNS:
        if fp.search(text):
            if not any(f.finding_type == "sensitive_file_path" for f in findings):
                findings.append(Finding(
                    severity="high",
                    category="sensitive_file",
                    finding_type="sensitive_file_path",
                    description="Reference to a sensitive file path detected in text",
                    recommendation="Avoid including file paths for sensitive files in LLM prompts.",
                    scan_path=path,
                ))
                file_finding_added = True
                if _v.is_super():
                    _v.v2(f"    Text contains a reference to a sensitive file path.")
            break

    if _v.is_super() and not file_finding_added:
        _v.v2(f"    No sensitive file references found.")

    # ── Step 4: entropy analysis ──────────────────────────────────────────────
    if entropy_enabled:
        _v.v2(f"  Step 4: Entropy analysis — scanning for random-looking strings "
              f"(min length: {entropy_min_length}, threshold: {entropy_threshold})...")
        _v.v2(f"          (High entropy = looks random = might be a secret even without a known pattern)")

        words = re.findall(r"[A-Za-z0-9+/=_\-]{" + str(entropy_min_length) + r",}", text)
        entropy_hits = 0
        for word in words:
            if _is_dummy(word):
                continue
            entropy = _shannon_entropy(word)
            already_matched = any(
                word in (f.matched_text_preview or "") for f in findings
            )
            if _v.is_super():
                preview = word[:24] + ("…" if len(word) > 24 else "")
                above = entropy >= entropy_threshold
                status = f"entropy={entropy:.2f} (threshold={entropy_threshold})"
                if already_matched:
                    _v.v2(f"    \"{preview}\" → {status} — already captured by pattern match, skipping")
                elif above:
                    _v.v2(f"    \"{preview}\" → {status} — HIGH ENTROPY → flagged")
                else:
                    _v.v2(f"    \"{preview}\" → {status} — below threshold, OK")
            if entropy >= entropy_threshold and not already_matched:
                findings.append(Finding(
                    severity="low",
                    category="entropy",
                    finding_type="high_entropy_string",
                    description=f"High-entropy string detected (entropy={entropy:.2f})",
                    recommendation="Verify this is not a secret or token before sending to an LLM.",
                    scan_path=path,
                    # Store the full word (not truncated) so that the redactor
                    # can do an exact substring replacement across the payload.
                    # matched_text_preview is in-memory only; it is never
                    # written to findings.jsonl.
                    matched_text_preview=word,
                ))
                entropy_hits += 1

        if _v.is_super() and not words:
            _v.v2(f"    No long strings found to check for entropy.")
    else:
        _v.v2(f"  Step 4: Entropy analysis is disabled in your config — skipping.")

    return findings


def scan_units(
    units: Sequence[ScanUnit],
    extra_prohibited_terms: Optional[List[str]] = None,
    entropy_enabled: bool = True,
    entropy_min_length: int = 24,
    entropy_threshold: float = 4.2,
) -> ScanResult:
    from .. import verbose as _v

    result = ScanResult(scanned_units=len(units))

    # Level-1 headline
    _v.v1(f"Scanning {len(units)} unit(s) for secrets, API keys, and sensitive content...")

    # Level-2 explanation of what "units" are
    if _v.is_super():
        _v.v2(f"  (A 'unit' is one piece of text — e.g. a single message, system prompt,")
        _v.v2(f"   or tool argument. killswitch scans each unit independently.)")
        _v.blank()

    for i, unit in enumerate(units, start=1):
        if _v.is_super():
            _v.sep()
            preview = unit.content[:60].replace("\n", " ")
            ellipsis = "…" if len(unit.content) > 60 else ""
            _v.v2(f"UNIT {i} / {len(units)}  →  path: {unit.path}  ({len(unit.content)} chars)")
            _v.v2(f"  Preview: \"{preview}{ellipsis}\"")
            _v.blank()

        findings = scan_text(
            text=unit.content,
            path=unit.path,
            extra_prohibited_terms=extra_prohibited_terms,
            entropy_enabled=entropy_enabled,
            entropy_min_length=entropy_min_length,
            entropy_threshold=entropy_threshold,
            source_file=unit.source_file,
        )
        result.findings.extend(findings)

        if _v.is_super():
            _v.blank()
            if findings:
                _v.v2(f"  Unit result: {len(findings)} finding(s) — {', '.join(f.severity.upper() for f in findings)}")
            else:
                _v.v2(f"  Unit result: ✓ All checks passed — this unit is clean.")
            _v.blank()

    # Level-1 summary
    if result.findings:
        sev = result.max_severity or "unknown"
        _v.v1(f"⚠  {len(result.findings)} finding(s) — max severity: {sev.upper()}")
        if _v.is_super():
            _v.sep()
            _v.v2(f"FINDINGS SUMMARY:")
            for idx, f in enumerate(result.findings, start=1):
                _v.v2(f"  #{idx}  {f.finding_type:<22}  {f.severity.upper():<8}  {f.description}")
                _v.v2(f"       Recommendation: {f.recommendation}")
            _v.blank()
    else:
        _v.v1(f"✓ No issues found. The prompt looks clean.")

    return result
