"""
Context classifier — separates "mentioning dangerous concepts" from
"issuing dangerous instructions."

The 3-factor rule for high-risk classification:
  OVERRIDE language  +  DANGEROUS ACTION  +  AGENT-DIRECTED IMPERATIVE  →  real attack

Hard benign negatives typically contain one or two of these factors
(usually override language in a quoted/educational context) but NOT all three.

Multipliers are applied to individual signals BEFORE combining:
  If likely_hard_benign:
    heuristic_score  ×= h_mult   (drops regex signal for educational text)
    semantic_drift   ×= s_mult   (drops semantic signal for discussion)

This preserves the architecture — the context classifier is a pre-processing
adjustment that any existing code path can opt into.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ── Pattern libraries ─────────────────────────────────────────────────────────

# Educational/analytical framing — text is ABOUT a concept, not issuing it
_EDUCATIONAL_VERBS = re.compile(
    r"\b(explain|describe|analyze|analyse|understand|discuss|compare|"
    r"write (a|an)? (brief |short |concise |detailed )?(security )?(report|summary|overview|analysis)|"
    r"summarize|review|document|tell me (about|why|how)|"
    r"what (is|are|does)|how (does|do|can)|why (is|are|does)|"
    r"show (me )?examples?|illustrate|demonstrate|outline|overview)\b",
    re.I,
)

_SECURITY_TOPICS = re.compile(
    r"\b(prompt injection|jailbreak|jailbreaking|system prompt|override|bypass|"
    r"llm security|ai security|adversarial|attack pattern|threat model|"
    r"leaked (api )?key|exfiltrat|phishing|red team|penetration test|pentest|"
    r"malicious prompt|injection attack|best practices|defense|vulnerability|"
    r"incident report|breach|security (risk|report|audit|review|newsletter|researcher?))\b",
    re.I,
)

# Documentation / lookup framing — searching for or referencing content
_DOCUMENTATION_LOOKUP = re.compile(
    r"\b(find|search (for)?|look up|fetch|get|retrieve|what does .{1,40}say about|"
    r"where (is|can)|locate|show me)\b.{0,60}"
    r"\b(documentation|docs|api( reference)?|guide|manual|reference|"
    r"endpoint|examples?|cases|test cases|integration|specification|spec|"
    r"policy document|the paper|blog post)\b",
    re.I,
)

# Organizational search — looking up emails, tickets, or files about an internal program/initiative
_ORG_SEARCH = re.compile(
    r"\b(find|search (for)?|look (up|for)|fetch|retrieve|get|show me|list)\b"
    r".{0,60}"
    r"\b(emails?|messages?|threads?|tickets?|issues?|slack messages?|slack threads?)\b"
    r".{0,80}"
    r"\b(about|regarding|concerning|from|related to|mentioning|on|initiative|"
    r"testing|program|project|effort|q[1-4]|quarter)\b",
    re.I,
)

# Incident/review framing — reviewing past events, not issuing commands
_INCIDENT_REVIEW = re.compile(
    r"\b(review|summarize|analyze|analyse|read|examine)\b.{0,80}"
    r"\b(incident (report)?|breach|leak|exfil|api key|credential|red team report|"
    r"phishing (example|case)|penetration test|pentest result|security audit)\b",
    re.I,
)

# Quoted / code-block reference — phrase is clearly a reference, not a command
_QUOTED_PHRASE = re.compile(
    r"""(["'])(.+?)\1"""  # any text in single or double quotes
    r"|contains? the phrase"
    r"|search for ['\"]"
    r"|the phrase ['\"]"
    r"|titled? ['\"]"
    r"|requests? that say ['\"]"
    r"|example[s]? (of|like|such as|including)?\s*['\"]"
    r"|```[\s\S]*?```"  # code blocks
    r"|\[.{3,}\]",  # markdown inline code / brackets
    re.I,
)

# Title / document name reference — dangerous word is in a title
_TITLE_REFERENCE = re.compile(
    r"\b(titled?|named?|called|document|policy|article|paper|report|"
    r"playbook|runbook|procedure|guide)\s+['\"].*?['\"]"
    r"|find.{0,30}(document|policy|article|report|guide|playbook).{0,30}['\"]",
    re.I,
)

# Agent-directed imperative — the instruction is aimed AT the AI agent
_AGENT_DIRECTED = re.compile(
    r"""
    # explicit agent address
    \b(you|your|assistant|ai|model|chatbot|agent|llm|gpt)\b
    .{0,40}
    \b(ignore|disregard|override|bypass|forget|reveal|send|post|
       call|execute|transfer|exfiltrate|delete|disable|reset)\b
    |
    # sentence-opening imperative (implied "you")
    (?:^|[.!?]\s+)
    (ignore|disregard|override|forget|bypass|
     reveal|send|post|call|execute|transfer|exfiltrate)
    \b
    """,
    re.I | re.VERBOSE | re.MULTILINE,
)

# Dangerous action verbs — the request asks for a side-effecting action
_DANGEROUS_ACTION = re.compile(
    r"\b(reveal|leak|exfiltrat|send (an? )?email|post (to|a message|slack)|"
    r"transfer (money|\$|\d)|call (post_message|send_email|post_slack)|"
    r"execute|delete|disable|reset|expose|dump|extract)\b",
    re.I,
)

# Override / control-flow language
_OVERRIDE_LANGUAGE = re.compile(
    r"\b(ignore|disregard|override|bypass|forget|supersede|circumvent|"
    r"set aside|overlook|neglect|skip|nullif)\b",
    re.I,
)


# ── Result type ───────────────────────────────────────────────────────────────


@dataclass
class ContextSignals:
    """
    Evidence for whether a text is educational/referential vs an active attack.
    """

    security_discussion: bool = False
    documentation_lookup: bool = False
    incident_review: bool = False
    org_search: bool = False
    quoted_or_code_reference: bool = False
    title_reference: bool = False
    agent_directed: bool = False
    dangerous_action: bool = False
    override_language: bool = False

    @property
    def likely_hard_benign(self) -> bool:
        """
        True when the text discusses/references dangerous concepts
        but does NOT contain attack factors that indicate a real attack.

        Two gates that veto the benign classification:
          1. All three attack factors: override + dangerous action + agent-directed
          2. Two-factor shortcut: agent-directed AND dangerous action (no override needed
             for "write a summary and send" style attacks).

        Security discussion texts typically contain override vocabulary but lack
        the agent-directed component — they describe attacks in third person or quotes.
        """
        clearly_educational = (
            self.security_discussion
            or self.documentation_lookup
            or self.incident_review
            or self.org_search
            or self.quoted_or_code_reference
            or self.title_reference
        )
        all_three_attack_factors = (
            self.override_language and self.dangerous_action and self.agent_directed
        )
        # Two-factor veto: even without override language, if the request is
        # agent-directed AND asks for a side-effecting action, don't dampen.
        agent_and_dangerous = self.agent_directed and self.dangerous_action
        return clearly_educational and not all_three_attack_factors and not agent_and_dangerous

    @property
    def heuristic_multiplier(self) -> float:
        """
        Multiplier applied to heuristic_score before combining.

        Reduces the regex signal significantly when the text is clearly
        educational or referential — the dangerous words are being mentioned,
        not issued as commands to the agent.
        """
        if not self.likely_hard_benign:
            return 1.0
        if self.quoted_or_code_reference or self.title_reference:
            return 0.04  # phrase is explicitly quoted/titled — very safe to reduce
        if self.documentation_lookup or self.incident_review or self.org_search:
            return 0.05  # searching for docs/emails or reviewing past events
        if self.security_discussion:
            return 0.06  # explaining/describing attacks academically
        return 0.07

    @property
    def semantic_multiplier(self) -> float:
        """Multiplier applied to semantic_drift before combining."""
        if not self.likely_hard_benign:
            return 1.0
        if self.quoted_or_code_reference or self.title_reference:
            return 0.10
        if self.documentation_lookup or self.incident_review or self.org_search:
            return 0.15
        return 0.20

    def as_dict(self) -> dict:
        return {
            "security_discussion": self.security_discussion,
            "documentation_lookup": self.documentation_lookup,
            "incident_review": self.incident_review,
            "org_search": self.org_search,
            "quoted_or_code_reference": self.quoted_or_code_reference,
            "title_reference": self.title_reference,
            "agent_directed": self.agent_directed,
            "dangerous_action": self.dangerous_action,
            "override_language": self.override_language,
            "likely_hard_benign": self.likely_hard_benign,
            "h_mult": self.heuristic_multiplier,
            "s_mult": self.semantic_multiplier,
        }


# ── Classifier ────────────────────────────────────────────────────────────────


def classify_context(text: str) -> ContextSignals:
    """
    Classify the intent context of a text.

    Returns ContextSignals indicating whether the text is educational,
    referential, or an active attack instruction.
    """
    low = text.lower()

    # Security discussion: educational verb + security topic
    security_discussion = bool(
        _EDUCATIONAL_VERBS.search(low) and _SECURITY_TOPICS.search(low)
    ) or bool(
        # Also catches: "Write a security report explaining..."
        re.search(r"\b(security (report|analysis|newsletter|guide|blog))\b", low, re.I)
    )

    documentation_lookup = bool(_DOCUMENTATION_LOOKUP.search(low)) or bool(
        # "find X documentation for Y endpoint"
        re.search(
            r"\bfind\b.{0,40}\b(documentation|docs|api|reference|endpoint)\b",
            low,
            re.I,
        )
    )

    incident_review = bool(_INCIDENT_REVIEW.search(low))

    org_search = bool(_ORG_SEARCH.search(low))

    quoted_or_code_reference = bool(_QUOTED_PHRASE.search(text)) or bool(
        re.search(r"contains? the phrase|the phrase ['\"]|search for ['\"]", low, re.I)
    )

    title_reference = bool(_TITLE_REFERENCE.search(text))

    agent_directed = bool(_AGENT_DIRECTED.search(text))

    dangerous_action = bool(_DANGEROUS_ACTION.search(low))

    override_language = bool(_OVERRIDE_LANGUAGE.search(low))

    return ContextSignals(
        security_discussion=security_discussion,
        documentation_lookup=documentation_lookup,
        incident_review=incident_review,
        org_search=org_search,
        quoted_or_code_reference=quoted_or_code_reference,
        title_reference=title_reference,
        agent_directed=agent_directed,
        dangerous_action=dangerous_action,
        override_language=override_language,
    )
