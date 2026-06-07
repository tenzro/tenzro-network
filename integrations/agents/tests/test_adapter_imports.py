"""Import smoke tests for each framework adapter.

Each adapter module must import cleanly even when its framework is not
installed (lazy/guarded imports). When the framework *is* installed, the
factory should produce the expected object; when it is not, calling the
factory must raise a clear ``ImportError`` (skipped gracefully here).
"""

from __future__ import annotations

import importlib

import pytest

from tenzro_agents.core import TenzroClient

ADAPTERS = [
    "tenzro_agents.langgraph",
    "tenzro_agents.crewai",
    "tenzro_agents.letta",
    "tenzro_agents.openai_sdk",
    "tenzro_agents.adk",
    "tenzro_agents.agent_framework",
]


@pytest.mark.parametrize("module_name", ADAPTERS)
def test_adapter_module_imports_without_framework(module_name):
    """The adapter module itself imports regardless of framework presence."""
    mod = importlib.import_module(module_name)
    assert mod is not None


def test_package_imports_clean():
    import tenzro_agents

    assert hasattr(tenzro_agents, "TenzroClient")
    assert hasattr(tenzro_agents, "TenzroDidEnvelope")
    assert tenzro_agents.__version__


# -- Per-framework: exercise the real API only if installed --------------


def test_langgraph_callback_if_installed():
    pytest.importorskip("langchain_core")
    from tenzro_agents.langgraph import make_langgraph_callback

    cb = make_langgraph_callback(TenzroClient(), "did:tenzro:machine:0x1")
    # It is a real BaseCallbackHandler subclass instance.
    from langchain_core.callbacks.base import BaseCallbackHandler

    assert isinstance(cb, BaseCallbackHandler)


def test_crewai_agent_if_installed():
    pytest.importorskip("crewai")
    from tenzro_agents.crewai import make_tenzro_agent

    agent = make_tenzro_agent(
        TenzroClient(),
        "did:tenzro:machine:0x1",
        role="researcher",
        goal="research",
        backstory="b",
    )
    from crewai import Agent

    assert isinstance(agent, Agent)


def test_letta_tools_callable_without_letta():
    # The three tool funcs import without letta; only registration needs it.
    from tenzro_agents.letta import (
        tenzro_memory_archive,
        tenzro_memory_grant,
        tenzro_memory_recall,
    )

    assert callable(tenzro_memory_grant)
    assert callable(tenzro_memory_recall)
    assert callable(tenzro_memory_archive)


def test_openai_hooks_if_installed():
    pytest.importorskip("agents")
    from tenzro_agents.openai_sdk import TenzroOpenAIWrapper

    wrapper = TenzroOpenAIWrapper(TenzroClient(), "did:tenzro:machine:0x1")
    hooks = wrapper.run_hooks()
    from agents import RunHooks

    assert isinstance(hooks, RunHooks)


def test_adk_plugin_if_installed():
    pytest.importorskip("google.adk")
    from tenzro_agents.adk import tenzro_adk_plugin

    plugin = tenzro_adk_plugin(TenzroClient(), "did:tenzro:machine:0x1")
    from google.adk.plugins.base_plugin import BasePlugin

    assert isinstance(plugin, BasePlugin)


def test_agent_framework_middleware_if_installed():
    pytest.importorskip("agent_framework")
    from tenzro_agents.agent_framework import make_agent_framework_middleware

    mw = make_agent_framework_middleware(TenzroClient(), "did:tenzro:machine:0x1")
    from agent_framework import AgentMiddleware

    assert isinstance(mw, AgentMiddleware)


# -- When a framework is NOT installed, the factory raises ImportError ----


def test_langgraph_factory_raises_without_framework():
    if importlib.util.find_spec("langchain_core") is not None:
        pytest.skip("langchain_core installed; negative path not applicable")
    from tenzro_agents.langgraph import make_langgraph_callback

    with pytest.raises(ImportError):
        make_langgraph_callback(TenzroClient(), "did:tenzro:machine:0x1")
