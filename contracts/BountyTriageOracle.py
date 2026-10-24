# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
BountyTriage: Automated Vulnerability Assessment & Security Oracle
-----------------------------------------------------------------
Evaluates submitted security bug reports against live GitHub code
repositories using multi-validator AI consensus and the Equivalence Principle.
"""

from genlayer import *
from dataclasses import dataclass
import json
import typing

ERROR_EXPECTED = "[EXPECTED]"    # business logic — exact match required
ERROR_EXTERNAL = "[EXTERNAL]"    # external API 4xx — exact match required
ERROR_TRANSIENT = "[TRANSIENT]"  # network/5xx — agree if both transient
ERROR_LLM = "[LLM_ERROR]"        # malformed LLM output — always disagree


def _validate_verdict(data) -> dict:
    """Strictly validate the AI triage verdict before it reaches state."""
    if not isinstance(data, dict):
        raise ValueError("verdict must be a JSON object")

    severity = data.get("severity")
    if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INVALID"]:
        raise ValueError("severity must be a valid security tier string")

    reward = data.get("reward_multiplier")
    if not isinstance(reward, (int, float)):
        raise ValueError("reward_multiplier must be a number")

    reasoning = data.get("reasoning")
    if not isinstance(reasoning, str):
        raise ValueError("reasoning must be a string")

    return {
        "severity": severity,
        "reward_multiplier": int(reward),
        "reasoning": reasoning[:500],
    }


def _parse_llm_json(raw) -> typing.Any:
    """Normalize an LLM response into a Python object."""
    if isinstance(raw, (dict, list)):
        return raw
    if not isinstance(raw, str):
        raise ValueError("LLM response must be text or a JSON object")
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    return json.loads(text)


@allow_storage
@dataclass
class Report:
    researcher: Address
    github_url: str
    description: str
    status: str             # pending_triage | triaged
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | INVALID
    reward_multiplier: u256
    reasoning: str


class BountyTriageOracle(gl.Contract):
    reports: TreeMap[u256, Report]
    next_id: u256

    def __init__(self):
        self.next_id = u256(0)

    # ---------------------------------------------------------------
    # Submission
    # ---------------------------------------------------------------

    @gl.public.write
    def submit_vulnerability(self, github_url: str, description: str) -> int:
        """Researcher submits a vulnerability report for evaluation."""
        cleaned_url = github_url.strip().strip('"').strip("'").strip("(").strip(")").strip("`").strip("<").strip(">")
        if cleaned_url.startswith("http://"):
            cleaned_url = cleaned_url.replace("http://", "https://", 1)

        if not cleaned_url.startswith("[https://github.com/](https://github.com/)"):
            raise gl.vm.UserError(f"{ERROR_EXPECTED} GitHub URL must be a valid [https://github.com/](https://github.com/) address")
        
        cleaned_desc = description.strip().strip('"').strip("'")
        if not cleaned_desc:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Description cannot be empty")

        report_id = self.next_id
        self.reports[report_id] = Report(
            researcher=gl.message.sender_address,
            github_url=cleaned_url,
            description=cleaned_desc,
            status="pending_triage",
            severity="NONE",
            reward_multiplier=u256(0),
            reasoning="",
        )
        self.next_id = u256(int(self.next_id) + 1)
        return int(report_id)

    # ---------------------------------------------------------------
    # AI Consensus Triage Path
    # ---------------------------------------------------------------

    @gl.public.write
    def evaluate_vulnerability(self, report_id: int) -> str:
        """Triggers validator consensus to independently verify both severity and reward multiplier."""
        rep = self._get_report(report_id)
        if rep.status != "pending_triage":
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Report has already been triaged")

        url = rep.github_url
        description = rep.description

        def leader_fn():
            try:
                page = gl.nondet.web.get(url)
            except Exception as e:
                raise gl.vm.UserError(f"{ERROR_TRANSIENT} Could not fetch GitHub URL: {e}")

            prompt = f"""
You are an elite smart contract security auditor and triage engineer.
Analyze the following vulnerability report and source code reference from {url}.

Vulnerability Description:
{description}

Retrieved Code / PR Content Snippet:
{page.body[:3000]}

Task:
1. Determine if the bug/vulnerability is valid, authentic, and non-trivial.
2. Assign a severity level: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "INVALID".
3. Assign a corresponding reward multiplier percentage (e.g., Critical=100, High=50, Medium=20, Low=5, Invalid=0).

Respond strictly in JSON format only, no extra text:
{{
    "severity": "<CRITICAL/HIGH/MEDIUM/LOW/INVALID>",
    "reward_multiplier": <integer>,
    "reasoning": "<Concise citing code justification patterns technical>"
}}
"""
            response = gl.nondet.exec_prompt(prompt)
            try:
                return _validate_verdict(_parse_llm_json(response))
            except ValueError as e:
                raise gl.vm.UserError(f"{ERROR_LLM} {e}")

        def validator_fn(leaders_res) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                leader_msg = getattr(leaders_res, "message", "") or ""
                try:
                    leader_fn()
                    return False
                except gl.vm.UserError as e:
                    validator_msg = getattr(e, "message", str(e))
                    if validator_msg.startswith(ERROR_EXPECTED) or validator_msg.startswith(ERROR_EXTERNAL):
                        return validator_msg == leader_msg
                    if validator_msg.startswith(ERROR_TRANSIENT) and leader_msg.startswith(ERROR_TRANSIENT):
                        return True
                    return False
                except Exception:
                    return False

            try:
                leader_data = _validate_verdict(leaders_res.calldata)
                validator_data = leader_fn()
            except Exception:
                return False

            # STRICT CONSENSUS: BOTH severity AND reward_multiplier must match across validators
            return (
                leader_data["severity"] == validator_data["severity"]
                and leader_data["reward_multiplier"] == validator_data["reward_multiplier"]
            )

        raw_result = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        try:
            result = _validate_verdict(raw_result)
        except ValueError as e:
            raise gl.vm.UserError(f"{ERROR_LLM} Invalid consensus result: {e}")

        rep.status = "triaged"
        rep.severity = result["severity"]
        rep.reward_multiplier = u256(result["reward_multiplier"])
        rep.reasoning = result["reasoning"]

        return rep.severity

    # ---------------------------------------------------------------
    # Views
    # ---------------------------------------------------------------

    def _get_report(self, report_id: int) -> Report:
        rid = u256(report_id)
        if rid not in self.reports:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Report not found")
        return self.reports[rid]

    @gl.public.view
    def get_report(self, report_id: int) -> str:
        rid = u256(report_id)
        if rid not in self.reports:
            return json.dumps({"error": "not found"})
        r = self.reports[rid]
        return json.dumps({
            "researcher": str(r.researcher),
            "github_url": r.github_url,
            "description": r.description,
            "status": r.status,
            "severity": r.severity,
            "reward_multiplier": int(r.reward_multiplier),
            "reasoning": r.reasoning,
        })

    @gl.public.view
    def get_report_count(self) -> int:
        return int(self.next_id)
