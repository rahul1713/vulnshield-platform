"""Static application security testing — pattern-based analysis without LLM."""

from __future__ import annotations

import re
from typing import Any

RULES: list[dict[str, Any]] = [
    {
        "id": "SAST-001",
        "pattern": re.compile(r"\beval\s*\(", re.I),
        "title": "Use of eval()",
        "severity": "critical",
        "category": "Code Injection",
        "owasp": "A03:2021",
        "cwe": "CWE-95",
        "description": "eval() executes arbitrary code and enables remote code execution if input is attacker-controlled.",
        "remediation": "Remove eval(). Use safe parsing (ast.literal_eval for data-only), JSON schema validation, or dedicated parsers.",
    },
    {
        "id": "SAST-002",
        "pattern": re.compile(r"\bexec\s*\(", re.I),
        "title": "Use of exec()",
        "severity": "critical",
        "category": "Code Injection",
        "owasp": "A03:2021",
        "cwe": "CWE-94",
        "description": "exec() allows dynamic code execution.",
        "remediation": "Refactor to eliminate dynamic code execution. Never pass user input to exec().",
    },
    {
        "id": "SAST-003",
        "pattern": re.compile(r"(password|api[_-]?key|secret|token)\s*=\s*['\"][^'\"]{4,}['\"]", re.I),
        "title": "Hardcoded credential or secret",
        "severity": "critical",
        "category": "Secrets Management",
        "owasp": "A07:2021",
        "cwe": "CWE-798",
        "description": "Hardcoded secrets in source code can be extracted from repositories and binaries.",
        "remediation": "Use environment variables, secret managers (Vault, AWS Secrets Manager), or CI-injected secrets. Rotate exposed credentials immediately.",
    },
    {
        "id": "SAST-004",
        "pattern": re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*%s|\.format\s*\(|f['\"].*\{.*\}.*(SELECT|INSERT)", re.I),
        "title": "Potential SQL injection via string concatenation",
        "severity": "high",
        "category": "Injection",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "description": "Dynamic SQL built via string formatting may allow SQL injection.",
        "remediation": "Use parameterized queries / prepared statements. ORM query builders with bound parameters.",
    },
    {
        "id": "SAST-005",
        "pattern": re.compile(r"subprocess\.(call|Popen|run).*shell\s*=\s*True", re.I),
        "title": "Shell injection via subprocess shell=True",
        "severity": "high",
        "category": "Command Injection",
        "owasp": "A03:2021",
        "cwe": "CWE-78",
        "description": "shell=True with unsanitized input enables OS command injection.",
        "remediation": "Use shell=False with argument lists. Validate and allowlist inputs.",
    },
    {
        "id": "SAST-006",
        "pattern": re.compile(r"os\.system\s*\(", re.I),
        "title": "OS command execution via os.system()",
        "severity": "high",
        "category": "Command Injection",
        "owasp": "A03:2021",
        "cwe": "CWE-78",
        "description": "os.system() invokes a shell and is vulnerable to injection.",
        "remediation": "Replace with subprocess.run() using shell=False and explicit argument arrays.",
    },
    {
        "id": "SAST-007",
        "pattern": re.compile(r"pickle\.loads?\s*\(", re.I),
        "title": "Unsafe deserialization (pickle)",
        "severity": "critical",
        "category": "Insecure Deserialization",
        "owasp": "A08:2021",
        "cwe": "CWE-502",
        "description": "pickle can execute arbitrary code during deserialization.",
        "remediation": "Use JSON or protobuf. If pickle is required, only load from trusted sources with HMAC verification.",
    },
    {
        "id": "SAST-008",
        "pattern": re.compile(r"dangerouslySetInnerHTML|innerHTML\s*=", re.I),
        "title": "DOM-based XSS sink",
        "severity": "high",
        "category": "Cross-Site Scripting",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "description": "Assigning unsanitized HTML to the DOM enables XSS attacks.",
        "remediation": "Use textContent, React escaping, or DOMPurify with strict allowlists.",
    },
    {
        "id": "SAST-009",
        "pattern": re.compile(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False", re.I),
        "title": "TLS certificate verification disabled",
        "severity": "high",
        "category": "Cryptographic Failures",
        "owasp": "A02:2021",
        "cwe": "CWE-295",
        "description": "Disabling TLS verification enables man-in-the-middle attacks.",
        "remediation": "Enable certificate verification. Pin certificates or use proper CA bundles in production.",
    },
    {
        "id": "SAST-010",
        "pattern": re.compile(r"md5\s*\(|hashlib\.md5", re.I),
        "title": "Weak cryptographic hash (MD5)",
        "severity": "medium",
        "category": "Cryptographic Failures",
        "owasp": "A02:2021",
        "cwe": "CWE-328",
        "description": "MD5 is cryptographically broken and unsuitable for security purposes.",
        "remediation": "Use SHA-256 or bcrypt/argon2 for passwords.",
    },
    {
        "id": "SAST-011",
        "pattern": re.compile(r"random\.(random|randint|choice)\s*\(", re.I),
        "title": "Insecure randomness for security context",
        "severity": "medium",
        "category": "Cryptographic Failures",
        "owasp": "A02:2021",
        "cwe": "CWE-330",
        "description": "random module is not cryptographically secure.",
        "remediation": "Use secrets module or os.urandom() for tokens, session IDs, and cryptographic values.",
    },
    {
        "id": "SAST-012",
        "pattern": re.compile(r"yaml\.load\s*\([^)]*\)(?!.*Loader)", re.I),
        "title": "Unsafe YAML deserialization",
        "severity": "high",
        "category": "Insecure Deserialization",
        "owasp": "A08:2021",
        "cwe": "CWE-502",
        "description": "yaml.load without SafeLoader can execute arbitrary Python objects.",
        "remediation": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
    },
]


def analyze_source(code: str, file_path: str = "source", language: str = "python") -> list[dict[str, Any]]:
    """Run static pattern analysis and return normalized findings."""
    findings: list[dict[str, Any]] = []
    lines = code.splitlines()
    seen: set[str] = set()

    for rule in RULES:
        for line_no, line in enumerate(lines, 1):
            if rule["pattern"].search(line):
                key = f"{rule['id']}:{line_no}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "owasp_category": rule["owasp"],
                        "cwe_id": rule["cwe"],
                        "description": rule["description"],
                        "recommended_fix": rule["remediation"],
                        "remediation": rule["remediation"],
                        "root_cause": f"Pattern {rule['id']} matched on line {line_no}",
                        "file_path": file_path,
                        "line_start": line_no,
                        "line_end": line_no,
                        "location": f"{file_path}:{line_no}",
                        "cvss_score": {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0}.get(
                            rule["severity"], 5.0
                        ),
                    }
                )

    if not findings and len(code.strip()) > 20:
        findings.append(
            {
                "title": "No critical patterns detected by static analysis",
                "severity": "info",
                "category": "Informational",
                "description": "Automated SAST did not match high-risk patterns. Manual review and dynamic testing are still recommended.",
                "recommended_fix": "Perform peer review, SCA dependency scanning, and DAST for complete coverage.",
                "file_path": file_path,
                "line_start": 1,
                "line_end": 1,
            }
        )

    return findings
