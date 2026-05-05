"""LLM defensive agents used to review anomalous database-access events.

The application treats Gemma 3 and Qwen 2.5 as optional defensive reviewers.
The deterministic rule engine still decides whether an access is anomalous;
the LLMs only explain the risk and recommend a defensive action for auditing.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


AGENT_GEMMA = "gemma3"
AGENT_QWEN = "qwen2.5"
AGENT_BOTH = "both"
AI_DISABLED = "off"

RUNNABLE_AGENT_CHOICES = (AGENT_GEMMA, AGENT_QWEN, AGENT_BOTH)
AI_MODE_CHOICES = (AI_DISABLED, *RUNNABLE_AGENT_CHOICES)

SYSTEM_PROMPT = (
    "Voce e um agente defensivo de seguranca de banco de dados. "
    "Analise apenas sinais de auditoria e recomende uma acao defensiva. "
    "Nao gere instrucoes ofensivas, exploracao, evasao ou codigo malicioso. "
    "Responda em JSON com as chaves risco, acao, justificativa e evidencias."
)

INCIDENT_RESPONSE_PROMPT = (
    "Voce e um agente defensivo de resposta a incidentes. "
    "Explique apenas passos defensivos para conter, registrar e recuperar o "
    "servico. Nao ensine como executar ataques. Responda em JSON com as chaves "
    "resumo, passos, acoes_defensivas, shutdown_necessario e justificativa."
)


@dataclass(frozen=True)
class AiAgentConfig:
    """Configuration required to call one OpenAI-compatible LLM endpoint."""

    agent_name: str
    model_name: str
    api_base_url: str
    api_key: str


@dataclass(frozen=True)
class AgentVerdict:
    """Measured response produced by one defensive AI for one access case."""

    session_id: str
    agent_name: str
    model_name: str
    provider_url: str
    verdict: str
    started_at: str
    finished_at: str
    duration_ms: int
    error: str | None = None


class AgentRunner:
    """Runs the selected defensive AIs and measures each model interaction.

    A runner owns one `session_id`, so every model call made during the same
    command execution can be grouped for cumulative totals and session averages.
    Agents are called sequentially when `both` is selected. Use `--ai gemma3`
    or `--ai qwen2.5` in the CLI when the experiment should isolate one model.
    """

    def __init__(
        self,
        agent_configs: list[AiAgentConfig],
        *,
        timeout_seconds: int = 45,
        session_id: str | None = None,
    ):
        self.agent_configs = agent_configs
        self.timeout_seconds = timeout_seconds
        self.session_id = session_id or uuid4().hex

    @classmethod
    def disabled(cls) -> "AgentRunner":
        """Create a runner that skips all AI calls."""

        return cls([])

    @classmethod
    def from_env(cls, selected_agent: str = AGENT_BOTH) -> "AgentRunner":
        """Build an agent runner from environment variables.

        Required environment:
        - `AGENT_PROVIDER`: `ollama`, `openrouter`, `disabled`, `none` or `off`.

        Optional environment:
        - `GEMMA_MODEL`: model identifier for Gemma 3.
        - `QWEN_MODEL`: model identifier for Qwen 2.5.
        - `AGENT_TIMEOUT_SECONDS`: HTTP timeout for each model call.
        - `OLLAMA_OPENAI_BASE_URL` / `OLLAMA_API_KEY` for local Ollama.
        - `OPENROUTER_BASE_URL` / `OPENROUTER_API_KEY` for OpenRouter.
        """

        _validate_selected_agent(selected_agent)

        provider_name = os.getenv("AGENT_PROVIDER", "disabled").strip().lower()
        if provider_name in {"", "disabled", "none", AI_DISABLED}:
            return cls.disabled()

        api_base_url, api_key = _read_provider_settings(provider_name)
        all_agent_configs = [
            AiAgentConfig(
                agent_name=AGENT_GEMMA,
                model_name=os.getenv("GEMMA_MODEL", AGENT_GEMMA),
                api_base_url=api_base_url,
                api_key=api_key,
            ),
            AiAgentConfig(
                agent_name=AGENT_QWEN,
                model_name=os.getenv("QWEN_MODEL", AGENT_QWEN),
                api_base_url=api_base_url,
                api_key=api_key,
            ),
        ]
        selected_configs = _select_agent_configs(all_agent_configs, selected_agent)
        timeout_seconds = int(os.getenv("AGENT_TIMEOUT_SECONDS", "45"))
        return cls(selected_configs, timeout_seconds=timeout_seconds)

    def enabled(self) -> bool:
        """Return whether this runner has at least one configured AI."""

        return bool(self.agent_configs)

    def review_access(self, access_event_payload: dict[str, Any]) -> list[AgentVerdict]:
        """Ask each selected AI to review one anomalous access event."""

        return [
            self._review_access_with_agent(agent_config, access_event_payload)
            for agent_config in self.agent_configs
        ]

    def review_incident_response(
        self,
        incident_payload: dict[str, Any],
    ) -> list[AgentVerdict]:
        """Ask each selected AI for a defensive response plan."""

        return [
            self._review_incident_with_agent(agent_config, incident_payload)
            for agent_config in self.agent_configs
        ]

    def _review_access_with_agent(
        self,
        agent_config: AiAgentConfig,
        access_event_payload: dict[str, Any],
    ) -> AgentVerdict:
        """Call one model and always return a measured verdict or error."""

        user_content = (
            "Analise este evento de acesso ao banco e recomende uma "
            "acao defensiva:\n"
            + json.dumps(access_event_payload, ensure_ascii=False, indent=2)
        )
        return self._request_model_verdict(
            agent_config=agent_config,
            system_prompt=SYSTEM_PROMPT,
            user_content=user_content,
        )

    def _review_incident_with_agent(
        self,
        agent_config: AiAgentConfig,
        incident_payload: dict[str, Any],
    ) -> AgentVerdict:
        """Call one model for a step-by-step defensive response plan."""

        user_content = (
            "Gere um plano de resposta defensiva para este incidente:\n"
            + json.dumps(incident_payload, ensure_ascii=False, indent=2)
        )
        return self._request_model_verdict(
            agent_config=agent_config,
            system_prompt=INCIDENT_RESPONSE_PROMPT,
            user_content=user_content,
        )

    def _request_model_verdict(
        self,
        *,
        agent_config: AiAgentConfig,
        system_prompt: str,
        user_content: str,
    ) -> AgentVerdict:
        """Call one model and always return a measured verdict or error."""

        started_at = _utc_now()
        started_counter = time.perf_counter()

        if not agent_config.api_key:
            return _build_error_verdict(
                session_id=self.session_id,
                agent_config=agent_config,
                started_at=started_at,
                started_counter=started_counter,
                error_message="API key nao configurada",
            )

        http_request = _build_chat_completion_request(
            agent_config=agent_config,
            system_prompt=system_prompt,
            user_content=user_content,
        )

        try:
            with urllib.request.urlopen(
                http_request,
                timeout=self.timeout_seconds,
            ) as http_response:
                response_body = json.loads(http_response.read().decode("utf-8"))
            model_response = response_body["choices"][0]["message"]["content"]
            return AgentVerdict(
                session_id=self.session_id,
                agent_name=agent_config.agent_name,
                model_name=agent_config.model_name,
                provider_url=agent_config.api_base_url,
                verdict=model_response,
                started_at=started_at,
                finished_at=_utc_now(),
                duration_ms=_elapsed_ms(started_counter),
            )
        except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
            return _build_error_verdict(
                session_id=self.session_id,
                agent_config=agent_config,
                started_at=started_at,
                started_counter=started_counter,
                error_message=str(exc),
            )


def _validate_selected_agent(selected_agent: str) -> None:
    if selected_agent not in RUNNABLE_AGENT_CHOICES:
        choices = ", ".join(RUNNABLE_AGENT_CHOICES)
        raise ValueError(f"IA invalida: {selected_agent}. Use uma destas: {choices}.")


def _read_provider_settings(provider_name: str) -> tuple[str, str]:
    if provider_name == "ollama":
        return (
            os.getenv("OLLAMA_OPENAI_BASE_URL", "http://localhost:11434/v1"),
            os.getenv("OLLAMA_API_KEY", "ollama"),
        )
    if provider_name == "openrouter":
        return (
            os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            os.getenv("OPENROUTER_API_KEY", ""),
        )
    raise ValueError("AGENT_PROVIDER invalido. Use disabled, ollama ou openrouter.")


def _select_agent_configs(
    agent_configs: list[AiAgentConfig],
    selected_agent: str,
) -> list[AiAgentConfig]:
    if selected_agent == AGENT_BOTH:
        return agent_configs
    return [
        agent_config
        for agent_config in agent_configs
        if agent_config.agent_name == selected_agent
    ]


def _build_chat_completion_request(
    *,
    agent_config: AiAgentConfig,
    system_prompt: str,
    user_content: str,
) -> urllib.request.Request:
    request_body = {
        "model": agent_config.model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.1,
    }
    chat_completion_url = agent_config.api_base_url.rstrip("/") + "/chat/completions"
    return urllib.request.Request(
        chat_completion_url,
        data=json.dumps(request_body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {agent_config.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost/tcc-access-defense",
            "X-Title": "TCC Access Defense",
        },
        method="POST",
    )


def _build_error_verdict(
    *,
    session_id: str,
    agent_config: AiAgentConfig,
    started_at: str,
    started_counter: float,
    error_message: str,
) -> AgentVerdict:
    return AgentVerdict(
        session_id=session_id,
        agent_name=agent_config.agent_name,
        model_name=agent_config.model_name,
        provider_url=agent_config.api_base_url,
        verdict="",
        started_at=started_at,
        finished_at=_utc_now(),
        duration_ms=_elapsed_ms(started_counter),
        error=error_message,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _elapsed_ms(started_counter: float) -> int:
    return max(0, round((time.perf_counter() - started_counter) * 1000))
