"""CrewAI adapter for Tenzro.

Integrates via CrewAI's native extension points (bridge doc Layer 4):
the ``@task`` decorator from ``crewai.project`` and the ``Agent`` class
from ``crewai``. ``TenzroAgent`` subclasses ``Agent`` and wraps
``execute_task`` in mandate-validate (before) + reputation-submit (after);
``tenzro_task`` is a thin decorator that does the same around a
``@task``-decorated crew method.

Current API (verified against the crewAI source tree
``lib/crewai/src/crewai/``):

* ``from crewai import Agent`` — ``Agent.execute_task(self, task,
  context=None, tools=None) -> str`` (the override point, declared on
  ``BaseAgent`` in ``agents/agent_builder/base_agent.py``).
* ``from crewai.project import task`` — ``task(meth)`` marks a crew method
  as a task (``project/annotations.py``).

Docs: https://docs.crewai.com/en/concepts/crews and
https://github.com/crewAIInc/crewAI

``crewai`` is imported lazily so the package imports without it.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Sequence
from typing import Any

from .core import ReputationHook, TenzroClient


def _crewai_agent() -> type:
    try:
        from crewai import Agent
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "TenzroAgent requires crewai. Install with: pip install crewai"
        ) from exc
    return Agent


def tenzro_task(
    client: TenzroClient,
    *,
    subject_agent_id: int | None = None,
    mandate_factory: Callable[..., Any] | None = None,
) -> Callable[[Callable], Callable]:
    """Decorator wrapping a CrewAI ``@task`` method.

    Validates an AP2 mandate pair before the task body runs (when
    ``mandate_factory(*args, **kwargs) -> (checkout, payment)`` is given)
    and submits ERC-8004 feedback after it finishes. Stack it *outside*
    ``crewai.project.task`` so the Tenzro wrapper is the outer call::

        @tenzro_task(client, subject_agent_id=0x4A2)
        @task
        def research(self):
            return Task(...)
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if mandate_factory is not None:
                checkout, payment = mandate_factory(*args, **kwargs)
                client.validate_mandate_pair(checkout, payment)
            outcome = "success"
            try:
                return func(*args, **kwargs)
            except Exception:
                outcome = "failure"
                raise
            finally:
                if subject_agent_id is not None:
                    ReputationHook(client, subject_agent_id).on_finish(outcome)

        return wrapper

    return decorator


def make_tenzro_agent(
    client: TenzroClient,
    did: str,
    *,
    subject_agent_id: int | None = None,
    mandate_factory: Callable[[Any], Any] | None = None,
    **agent_kwargs: Any,
):
    """Construct a ``TenzroAgent`` (an ``Agent`` subclass).

    Factory because ``crewai.Agent`` is resolved lazily. ``agent_kwargs``
    are forwarded to the ``Agent`` constructor (``role`` / ``goal`` /
    ``backstory`` / ``tools`` / ...).
    """
    Agent = _crewai_agent()

    class TenzroAgent(Agent):
        """``Agent`` whose ``execute_task`` is wrapped by Tenzro.

        Before each task: validate the AP2 mandate pair (if a
        ``mandate_factory(task) -> (checkout, payment)`` was supplied).
        After each task: submit ERC-8004 reputation feedback.
        """

        # pydantic models back CrewAI agents; stash Tenzro state off-model.
        _tenzro_client = client
        _tenzro_did = did
        _tenzro_subject_agent_id = subject_agent_id
        _tenzro_mandate_factory = staticmethod(mandate_factory) if mandate_factory else None

        def execute_task(
            self,
            task: Any,
            context: str | None = None,
            tools: Sequence[Any] | None = None,
        ) -> str:
            if self._tenzro_mandate_factory is not None:
                checkout, payment = self._tenzro_mandate_factory(task)
                self._tenzro_client.validate_mandate_pair(checkout, payment)
            outcome = "success"
            try:
                return super().execute_task(task, context=context, tools=tools)
            except Exception:
                outcome = "failure"
                raise
            finally:
                if self._tenzro_subject_agent_id is not None:
                    ReputationHook(
                        self._tenzro_client, self._tenzro_subject_agent_id
                    ).on_finish(outcome)

    return TenzroAgent(**agent_kwargs)


__all__ = ["make_tenzro_agent", "tenzro_task"]
