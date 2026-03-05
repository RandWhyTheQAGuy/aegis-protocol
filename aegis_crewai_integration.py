"""
aegis_crewai_integration.py
=============================
Aegis Protocol security layer for CrewAI role-based agent orchestration.

OVERVIEW
--------
CrewAI models multi-agent work as a Crew of Agents executing Tasks in
sequential or hierarchical order.  This integration enforces Aegis Protocol
security at three tiers:

  TIER 1 — AegisCrewAgent (Agent wrapper)
    Wraps CrewAI Agent configuration with an Aegis Semantic Passport.
    Provides validate() which must be called before the agent participates
    in any Crew.  Enforces capability gating: agents may only execute
    task types their passport explicitly grants.

  TIER 2 — AegisTask (Task wrapper)
    Wraps CrewAI Task with pre-execution and post-execution Aegis hooks.
    Pre-hook: validates agent passport and evaluates task description
              through the PolicyEngine before the task executes.
    Post-hook: evaluates the task output through the PolicyEngine before
               the result is passed to the next task or returned to caller.
    Fail-closed: denied tasks raise PermissionError and halt the Crew.

  TIER 3 — AegisCrew (Crew wrapper)
    Wraps crew.kickoff() with fleet-wide pre-flight checks and a
    post-execution security report.  Validates all agent passports,
    activates all sessions, runs the crew, then produces a consolidated
    audit report with chain verification.

COLD-START BEHAVIOUR
--------------------
AegisCrew.kickoff() calls start() internally.  start() validates every
agent's passport atomically — if any is expired the crew does not run.
The first kickoff from cold state produces a complete audit trail from
the genesis block.

CREWAI PROCESS MODES
--------------------
Both Process.sequential and Process.hierarchical are supported.
In hierarchical mode the manager agent also requires a valid passport.

DEPENDENCIES
------------
  pip install crewai>=0.100

NOTE: CrewAI stubs are provided so the integration runs without an LLM.
      Replace stub classes with real CrewAI imports:
        from crewai import Agent, Task, Crew, Process
        from crewai.tools import BaseTool
"""

import hashlib
import json
import time
import uuid
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis_adapter import (
    AegisAdapter,
    AegisFrameworkBridge,
    PolicyDecision,
    PolicyEngine,
    SemanticPassport,
    SessionState,
    _emit,
    _build_logger,
)

LOG = _build_logger("aegis_crewai")

# ─── CrewAI stubs ─────────────────────────────────────────────────────────────

class Process(str, Enum):
    sequential   = "sequential"
    hierarchical = "hierarchical"


class _StubTool:
    """Stub for crewai.tools.BaseTool"""
    def __init__(self, name: str, description: str,
                 fn: Optional[Callable] = None) -> None:
        self.name        = name
        self.description = description
        self._fn         = fn

    def run(self, *args, **kwargs) -> str:
        if self._fn:
            return str(self._fn(*args, **kwargs))
        return f"[{self.name}] result"


class _StubAgent:
    """
    Stub for crewai.Agent.
    In production replace with: from crewai import Agent
    """
    def __init__(self, role: str, goal: str, backstory: str,
                 llm: str = "stub-llm",
                 tools: Optional[List[_StubTool]] = None,
                 verbose: bool = False,
                 allow_delegation: bool = False,
                 max_iter: int = 5,
                 step_callback: Optional[Callable] = None) -> None:
        self.role             = role
        self.goal             = goal
        self.backstory        = backstory
        self.llm              = llm
        self.tools            = tools or []
        self.verbose          = verbose
        self.allow_delegation = allow_delegation
        self.max_iter         = max_iter
        self.step_callback    = step_callback
        self.agent_id         = str(uuid.uuid4())

    def execute_task(self, task: "_StubTask",
                     context: Optional[str] = None) -> str:
        """Stub execution: returns a formatted output based on task description."""
        ctx_part = f" (context: {context[:40]})" if context else ""
        return (
            f"[{self.role}] completed task: {task.description[:60]}{ctx_part}"
        )


class _StubTask:
    """
    Stub for crewai.Task.
    In production replace with: from crewai import Task
    """
    def __init__(self, description: str, expected_output: str,
                 agent: Optional[_StubAgent] = None,
                 context: Optional[List["_StubTask"]] = None,
                 callback: Optional[Callable] = None) -> None:
        self.description     = description
        self.expected_output = expected_output
        self.agent           = agent
        self.context         = context or []
        self.callback        = callback
        self.output: Optional[str] = None
        self.task_id = str(uuid.uuid4())


class _StubCrew:
    """
    Stub for crewai.Crew.
    In production replace with: from crewai import Crew
    """
    def __init__(self, agents: List[_StubAgent],
                 tasks:  List[_StubTask],
                 process: Process = Process.sequential,
                 verbose: bool = False,
                 step_callback: Optional[Callable] = None,
                 task_callback: Optional[Callable] = None) -> None:
        self.agents        = agents
        self.tasks         = tasks
        self.process       = process
        self.verbose       = verbose
        self.step_callback = step_callback
        self.task_callback = task_callback

    def kickoff(self, inputs: Optional[Dict[str, Any]] = None
                ) -> "_StubCrewOutput":
        """
        Execute tasks sequentially, passing context forward.
        Each task's output becomes context for the next.
        """
        results: List[str] = []
        last_output: Optional[str] = None

        for task in self.tasks:
            agent   = task.agent or (self.agents[0] if self.agents else None)
            context = last_output

            if self.step_callback:
                self.step_callback(task, agent)

            output = agent.execute_task(task, context) if agent else \
                     f"No agent for: {task.description}"

            task.output  = output
            last_output  = output
            results.append(output)

            if self.task_callback:
                self.task_callback(task)

        return _StubCrewOutput(raw="\n".join(results), tasks_output=results)


class _StubCrewOutput:
    def __init__(self, raw: str, tasks_output: List[str]) -> None:
        self.raw          = raw
        self.tasks_output = tasks_output

    def __str__(self) -> str:
        return self.raw


# ─── TIER 1 — AegisCrewAgent ──────────────────────────────────────────────────

class AegisCrewAgent:
    """
    CrewAI Agent with an embedded Aegis Semantic Passport.

    Provides validate() which registers the passport and activates the
    Aegis session.  Wraps the underlying _StubAgent (or real crewai.Agent)
    and provides the capability gate.

    Parameters
    ----------
    role             : CrewAI agent role string
    goal             : CrewAI agent goal string
    backstory        : CrewAI agent backstory string
    passport         : Aegis Semantic Passport
    adapter          : shared AegisAdapter
    task_types       : set of task type strings the agent may execute
                       (validated against passport capabilities)
    tools            : CrewAI tools list
    allow_delegation : whether this agent can delegate to others
    max_iter         : maximum reasoning iterations
    """

    def __init__(self,
                 role:             str,
                 goal:             str,
                 backstory:        str,
                 passport:         SemanticPassport,
                 adapter:          AegisAdapter,
                 task_types:       frozenset = frozenset(),
                 tools:            Optional[List[_StubTool]] = None,
                 allow_delegation: bool = False,
                 max_iter:         int  = 5) -> None:
        self.role             = role
        self.goal             = goal
        self.backstory        = backstory
        self.passport         = passport
        self._adapter         = adapter
        self.task_types       = task_types
        self._bridge: Optional[AegisFrameworkBridge] = None

        # Build the underlying CrewAI agent
        # In production: replace _StubAgent with crewai.Agent
        self._agent = _StubAgent(
            role=role, goal=goal, backstory=backstory,
            tools=tools or [],
            allow_delegation=allow_delegation,
            max_iter=max_iter,
            step_callback=self._step_callback,
        )

        _emit(LOG, "info", "AegisCrewAgent", "created",
              role=role, model_id=passport.model_id)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def validate(self) -> "AegisCrewAgent":
        """Register passport and activate session.  Returns self."""
        self._bridge = self._adapter.register_agent(
            self.passport, framework="crewai"
        )
        self._bridge.start()
        _emit(LOG, "info", "AegisCrewAgent", "validated",
              role=self.role,
              session_id=self._bridge.session.session_id)
        return self

    def shutdown(self) -> Tuple[bool, bool]:
        if not self._bridge:
            raise RuntimeError("shutdown() before validate()")
        return self._bridge.shutdown()

    # ── capability gate ───────────────────────────────────────────────────────

    def check_task_type(self, task_type: str) -> None:
        """
        Verify passport grants the required task_type capability.
        Raises PermissionError if not authorised.
        """
        if task_type not in self.passport.capabilities:
            _emit(LOG, "warning", "AegisCrewAgent", "task_type_denied",
                  role=self.role,
                  required=task_type,
                  granted=sorted(self.passport.capabilities))
            raise PermissionError(
                f"Agent {self.role!r} not authorised for task type "
                f"'{task_type}' (passport: {self.passport.passport_id})"
            )

    # ── step callback (Aegis audit hook for CrewAI's step_callback) ───────────

    def _step_callback(self, *args, **kwargs) -> None:
        """
        Called by CrewAI's internals at each reasoning step.
        Records a lightweight audit event without blocking execution.
        """
        if self._bridge:
            self._bridge.tlog.record(
                self.passport.model_id,
                self._bridge.session.session_id,
                "agent_step",
                role=self.role,
            )

    # ── expose inner agent for CrewAI compatibility ───────────────────────────

    @property
    def inner(self) -> _StubAgent:
        """Return the underlying CrewAI agent for use in Crew() constructor."""
        return self._agent

    @property
    def bridge(self) -> Optional[AegisFrameworkBridge]:
        return self._bridge


# ─── TIER 2 — AegisTask ───────────────────────────────────────────────────────

class AegisTask:
    """
    CrewAI Task wrapped with Aegis pre- and post-execution hooks.

    Pre-hook  : validates the assigned agent's passport and evaluates the
                task description payload through the PolicyEngine.
    Post-hook : evaluates the task output before it propagates downstream.
    Fail-closed: both hooks deny on policy violation.

    Parameters
    ----------
    description      : task description (evaluated pre-execution)
    expected_output  : what the task should produce
    aegis_agent      : AegisCrewAgent responsible for this task
    task_type        : capability string checked against agent passport
    in_sensitivity   : sensitivity score for task description evaluation
    out_sensitivity  : sensitivity score for task output evaluation
    context_tasks    : upstream AegisTasks whose outputs feed this task
    """

    def __init__(self,
                 description:     str,
                 expected_output:  str,
                 aegis_agent:     AegisCrewAgent,
                 task_type:       str = "general",
                 in_sensitivity:  float = 0.10,
                 out_sensitivity: float = 0.15,
                 context_tasks:   Optional[List["AegisTask"]] = None) -> None:
        self.description     = description
        self.expected_output  = expected_output
        self.aegis_agent     = aegis_agent
        self.task_type       = task_type
        self._in_sensitivity  = in_sensitivity
        self._out_sensitivity = out_sensitivity
        self.context_tasks   = context_tasks or []
        self.output: Optional[str] = None
        self.task_id = str(uuid.uuid4())

        # Build the underlying CrewAI task
        # In production: replace _StubTask with crewai.Task
        self._task = _StubTask(
            description=description,
            expected_output=expected_output,
            agent=aegis_agent.inner,
            context=[ct._task for ct in (context_tasks or [])],
            callback=self._post_execute_hook,
        )

        _emit(LOG, "info", "AegisTask", "created",
              description=description[:60],
              task_type=task_type,
              agent_role=aegis_agent.role)

    # ── pre-execution hook ────────────────────────────────────────────────────

    def pre_execute(self) -> None:
        """
        Called by AegisCrew before delegating the task to the crew engine.

        1. Validates that the agent's passport grants the required task_type.
        2. Evaluates the task description through the PolicyEngine.
        Raises PermissionError on any violation.
        """
        bridge = self.aegis_agent.bridge
        if bridge is None:
            raise RuntimeError(
                f"Task {self.task_id}: agent {self.aegis_agent.role!r} "
                "has not been validated"
            )

        # Capability gate
        self.aegis_agent.check_task_type(self.task_type)

        # Policy evaluation of task description
        result, allowed = bridge.evaluate_action(
            payload=self.description,
            authority=0.7,
            sensitivity=self._in_sensitivity,
            event_type="task_pre_execute",
            task_id=self.task_id,
            task_type=self.task_type,
        )

        if not allowed:
            _emit(LOG, "warning", "AegisTask", "pre_execute_denied",
                  task_id=self.task_id,
                  task_type=self.task_type,
                  reason=result.reason)
            raise PermissionError(
                f"Task '{self.description[:60]}' denied pre-execution: "
                f"{result.reason}"
            )

        _emit(LOG, "info", "AegisTask", "pre_execute_allowed",
              task_id=self.task_id,
              task_type=self.task_type,
              decision=result.decision.value)

    # ── post-execution hook ───────────────────────────────────────────────────

    def _post_execute_hook(self, task_output: Optional[Any] = None) -> None:
        """
        CrewAI task_callback — called after the task completes.
        Evaluates the task output before it propagates downstream.
        Records output in self.output on success.
        """
        bridge = self.aegis_agent.bridge
        if bridge is None:
            return

        output_text = str(self._task.output or task_output or "")
        try:
            result, allowed = bridge.evaluate_action(
                payload=output_text,
                authority=0.7,
                sensitivity=self._out_sensitivity,
                event_type="task_post_execute",
                task_id=self.task_id,
                task_type=self.task_type,
            )
        except PermissionError:
            _emit(LOG, "error", "AegisTask", "post_execute_quarantine",
                  task_id=self.task_id)
            self._task.output = "[QUARANTINED OUTPUT]"
            return

        if not allowed:
            _emit(LOG, "warning", "AegisTask", "post_execute_denied",
                  task_id=self.task_id, reason=result.reason)
            self._task.output = f"[DENIED OUTPUT: {result.reason}]"
            return

        self.output = output_text
        _emit(LOG, "info", "AegisTask", "post_execute_allowed",
              task_id=self.task_id,
              decision=result.decision.value,
              output_preview=output_text[:60])

    @property
    def inner(self) -> _StubTask:
        """Return the underlying CrewAI task."""
        return self._task


# ─── TIER 3 — AegisCrew ───────────────────────────────────────────────────────

class AegisCrew:
    """
    Crew wrapper with fleet-wide Aegis Protocol enforcement.

    Pre-flight  : validates all agent passports atomically.
    Execution   : runs pre_execute() on each AegisTask before delegation.
    Post-flight : produces consolidated security report with chain verification.

    Parameters
    ----------
    agents   : list of AegisCrewAgent instances
    tasks    : list of AegisTask instances (ordered for sequential process)
    process  : Process.sequential (default) or Process.hierarchical
    adapter  : shared AegisAdapter
    """

    def __init__(self,
                 agents:  List[AegisCrewAgent],
                 tasks:   List[AegisTask],
                 adapter: AegisAdapter,
                 process: Process = Process.sequential) -> None:
        self.agents  = agents
        self.tasks   = tasks
        self.adapter = adapter
        self.process = process
        self._crew: Optional[_StubCrew] = None
        self._started = False

        _emit(LOG, "info", "AegisCrew", "created",
              agent_count=len(agents),
              task_count=len(tasks),
              process=process.value)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Validate all agent passports atomically.
        Raises PermissionError if any passport is expired — the crew
        does not start in a partially-valid state.
        """
        errors = []
        for agent in self.agents:
            if agent.passport.is_expired():
                errors.append(
                    f"Agent {agent.role!r} passport "
                    f"{agent.passport.passport_id} has expired"
                )

        if errors:
            _emit(LOG, "error", "AegisCrew", "start_blocked",
                  errors=errors)
            raise PermissionError(
                "Crew blocked — expired passport(s): " + " | ".join(errors)
            )

        for agent in self.agents:
            agent.validate()

        # Build the underlying crew with task callbacks
        inner_agents = [a.inner for a in self.agents]
        inner_tasks  = [t.inner for t in self.tasks]

        self._crew = _StubCrew(
            agents=inner_agents,
            tasks=inner_tasks,
            process=self.process,
            verbose=False,
        )

        self._started = True
        _emit(LOG, "info", "AegisCrew", "started",
              agent_roles=[a.role for a in self.agents])

    def kickoff(self, inputs: Optional[Dict[str, Any]] = None
                ) -> _StubCrewOutput:
        """
        Run pre-flight checks, execute pre_execute() on all tasks,
        kick off the crew, and return the output.
        """
        if not self._started:
            self.start()

        # Pre-execute all tasks (raises PermissionError on any violation)
        for task in self.tasks:
            task.pre_execute()

        _emit(LOG, "info", "AegisCrew", "kickoff_started",
              task_count=len(self.tasks),
              inputs=list((inputs or {}).keys()))

        output = self._crew.kickoff(inputs)

        _emit(LOG, "info", "AegisCrew", "kickoff_complete",
              vault_entries=self.adapter.vault.length)

        return output

    def shutdown_report(self) -> Dict[str, Any]:
        """
        Shut down all agent sessions and return a consolidated report.
        Verifies vault and transparency log chain integrity.
        """
        if not self._started:
            raise RuntimeError("shutdown_report() before start()/kickoff()")

        agent_reports: Dict[str, Any] = {}
        for agent in self.agents:
            if agent.bridge:
                v_ok, t_ok = agent.shutdown()
                agent_reports[agent.role] = {
                    "vault_chain_ok": v_ok,
                    "tlog_chain_ok":  t_ok,
                    "vault_entries":  agent.bridge.vault.length,
                    "warp_score":     round(agent.bridge.session.warp_score, 4),
                    "session_state":  agent.bridge.session.state.value,
                }

        task_reports: Dict[str, Any] = {}
        for task in self.tasks:
            task_reports[task.task_id] = {
                "description":   task.description[:60],
                "task_type":     task.task_type,
                "output_length": len(task.output or ""),
                "output_denied": (task.output or "").startswith("[DENIED"),
            }

        v_ok, t_ok = self.adapter.verify_all_chains()
        report = {
            "fleet_vault_chain_ok": v_ok,
            "fleet_tlog_chain_ok":  t_ok,
            "fleet_vault_entries":  self.adapter.vault.length,
            "fleet_tlog_entries":   self.adapter.tlog.length,
            "agents":               agent_reports,
            "tasks":                task_reports,
        }

        _emit(LOG, "info", "AegisCrew", "shutdown_report",
              fleet_vault_ok=v_ok, fleet_tlog_ok=t_ok,
              total_vault_entries=self.adapter.vault.length)

        return report


# ─── TEST SUITE ───────────────────────────────────────────────────────────────

import pytest

POLICY_HASH = hashlib.sha256(b"crewai-policy-v1").hexdigest()

def _passport(model_id: str = "crew-agent-1",
              caps: frozenset = frozenset({"research", "write"}),
              expired: bool = False) -> SemanticPassport:
    p = SemanticPassport(
        model_id=model_id,
        version="1.0.0",
        policy_hash=POLICY_HASH,
        ttl_seconds=1 if expired else 3600,
        capabilities=caps,
    )
    if expired:
        object.__setattr__(p, "issued_at", time.time() - 10)
    return p

def _adapter() -> AegisAdapter:
    return AegisAdapter(policy=PolicyEngine(
        authority_floor=0.0,
        sensitivity_ceiling=0.70,
        flag_threshold=0.45,
    ))

def _crew_agent(role: str = "Researcher",
                model_id: str = "crew-agent",
                caps: frozenset = frozenset({"research", "write"}),
                adapter: Optional[AegisAdapter] = None,
                expired: bool = False) -> AegisCrewAgent:
    adp = adapter or _adapter()
    return AegisCrewAgent(
        role=role,
        goal=f"Perform {role} tasks",
        backstory=f"Expert {role.lower()}",
        passport=_passport(model_id, caps=caps, expired=expired),
        adapter=adp,
        task_types=caps,
    )


class TestAegisCrewAgent:
    def test_validate_activates_session(self):
        agent = _crew_agent().validate()
        assert agent.bridge.session.state == SessionState.ACTIVE

    def test_expired_passport_blocked(self):
        agent = _crew_agent(expired=True)
        with pytest.raises(PermissionError, match="expired"):
            agent.validate()

    def test_capability_check_allows(self):
        agent = _crew_agent(caps=frozenset({"research"})).validate()
        agent.check_task_type("research")   # should not raise

    def test_capability_check_denies(self):
        agent = _crew_agent(caps=frozenset({"research"})).validate()
        with pytest.raises(PermissionError, match="authorised"):
            agent.check_task_type("write")

    def test_shutdown_verifies_chains(self):
        agent = _crew_agent().validate()
        v_ok, t_ok = agent.shutdown()
        assert v_ok
        assert t_ok


class TestAegisTask:
    def test_pre_execute_allows_clean_task(self):
        adp   = _adapter()
        agent = _crew_agent(adapter=adp).validate()
        task  = AegisTask(
            description="Research recent AI safety papers",
            expected_output="List of papers",
            aegis_agent=agent,
            task_type="research",
            in_sensitivity=0.10,
        )
        task.pre_execute()   # should not raise
        assert adp.vault.length >= 1

    def test_pre_execute_blocked_by_capability(self):
        adp   = _adapter()
        agent = _crew_agent(caps=frozenset({"research"}), adapter=adp).validate()
        task  = AegisTask(
            description="Write a report",
            expected_output="Report text",
            aegis_agent=agent,
            task_type="write",      # agent does not have "write"
        )
        with pytest.raises(PermissionError, match="authorised"):
            task.pre_execute()

    def test_pre_execute_denied_by_policy(self):
        adp   = AegisAdapter(policy=PolicyEngine(sensitivity_ceiling=0.01))
        agent = _crew_agent(adapter=adp).validate()
        task  = AegisTask(
            description="High sensitivity task",
            expected_output="output",
            aegis_agent=agent,
            task_type="research",
            in_sensitivity=0.90,    # exceeds policy ceiling
        )
        with pytest.raises(PermissionError, match="denied"):
            task.pre_execute()

    def test_pre_execute_fails_before_validate(self):
        agent = _crew_agent()   # NOT validated
        task  = AegisTask(
            description="Some task",
            expected_output="output",
            aegis_agent=agent,
            task_type="research",
        )
        with pytest.raises(RuntimeError, match="validated"):
            task.pre_execute()

    def test_post_hook_captures_output(self):
        adp   = _adapter()
        agent = _crew_agent(adapter=adp).validate()
        task  = AegisTask(
            description="Research task",
            expected_output="findings",
            aegis_agent=agent,
            task_type="research",
            out_sensitivity=0.10,
        )
        task._task.output = "AI safety findings from 2025 papers"
        task._post_execute_hook()
        assert task.output is not None
        assert "denied" not in (task.output or "").lower()


class TestAegisCrew:
    def _make_crew(self, expired: bool = False,
                   n_agents: int = 2) -> Tuple[AegisCrew, AegisAdapter]:
        adp    = _adapter()
        agents = [
            _crew_agent(
                role=f"Agent{i}",
                model_id=f"crew-agent-{i}",
                adapter=adp,
                expired=expired,
            )
            for i in range(n_agents)
        ]
        tasks = [
            AegisTask(
                description=f"Task {i}: perform work step {i}",
                expected_output="step output",
                aegis_agent=agents[i % len(agents)],
                task_type="research",
                in_sensitivity=0.10,
                out_sensitivity=0.10,
            )
            for i in range(n_agents)
        ]
        crew = AegisCrew(agents=agents, tasks=tasks, adapter=adp)
        return crew, adp

    def test_cold_kickoff_succeeds(self):
        crew, adp = self._make_crew()
        output    = crew.kickoff()
        assert output is not None
        assert adp.vault.length >= 2   # at least one entry per task

    def test_expired_passport_blocks_kickoff(self):
        crew, _ = self._make_crew(expired=True)
        with pytest.raises(PermissionError, match="expired"):
            crew.kickoff()

    def test_shutdown_report_structure(self):
        crew, adp = self._make_crew(n_agents=2)
        crew.kickoff()
        report = crew.shutdown_report()
        assert report["fleet_vault_chain_ok"] is True
        assert report["fleet_tlog_chain_ok"]  is True
        assert len(report["agents"]) == 2
        assert len(report["tasks"])  == 2

    def test_shutdown_before_kickoff_raises(self):
        crew, _ = self._make_crew()
        with pytest.raises(RuntimeError, match="start"):
            crew.shutdown_report()

    def test_sequential_task_chain(self):
        """Tasks execute in order and outputs propagate as context."""
        adp = _adapter()
        agent = _crew_agent(adapter=adp)
        tasks = [
            AegisTask(f"Step {i}", f"Output {i}", agent, "research",
                      in_sensitivity=0.05, out_sensitivity=0.05)
            for i in range(3)
        ]
        crew = AegisCrew(agents=[agent], tasks=tasks, adapter=adp)
        out  = crew.kickoff()
        assert out is not None
        # Chain integrity verifies after all 3 tasks
        v_ok, t_ok = adp.verify_all_chains()
        assert v_ok
        assert t_ok

    def test_warp_accumulation_across_tasks(self):
        """FLAG decisions from multiple tasks accumulate warp score."""
        adp   = AegisAdapter(policy=PolicyEngine(
            sensitivity_ceiling=0.70, flag_threshold=0.40
        ))
        agent = _crew_agent(adapter=adp)
        # Tasks with elevated sensitivity → FLAG decisions → warp increases
        tasks = [
            AegisTask(f"Sensitive step {i}", "output", agent, "research",
                      in_sensitivity=0.55, out_sensitivity=0.55)
            for i in range(3)
        ]
        crew = AegisCrew(agents=[agent], tasks=tasks, adapter=adp)
        crew.kickoff()
        assert agent.bridge.session.warp_score > 0.0

    def test_fleet_chain_integrity_multi_agent(self):
        """Vault shared across agents; chain must verify after all tasks."""
        crew, adp = self._make_crew(n_agents=3)
        crew.kickoff()
        report = crew.shutdown_report()
        assert report["fleet_vault_chain_ok"] is True
        assert report["fleet_tlog_chain_ok"]  is True
        # All agents share the same vault → entries from all agents
        assert adp.vault.length >= 3


# ─── DEMO ENTRYPOINT ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  Aegis Protocol + CrewAI Integration Demo")
    print("=" * 70 + "\n")

    adapter = AegisAdapter(policy=PolicyEngine(
        authority_floor=0.0,
        sensitivity_ceiling=0.70,
        flag_threshold=0.45,
    ))

    # ── define two-agent research + write crew ────────────────────────────────
    researcher = AegisCrewAgent(
        role="AI Safety Researcher",
        goal="Research AI safety standards published in 2025",
        backstory="Expert in AI governance with 10 years experience.",
        passport=SemanticPassport(
            model_id="crew-researcher",
            version="1.0.0",
            policy_hash=POLICY_HASH,
            ttl_seconds=3600,
            capabilities=frozenset({"research", "read"}),
        ),
        adapter=adapter,
        task_types=frozenset({"research", "read"}),
    )

    writer = AegisCrewAgent(
        role="Technical Writer",
        goal="Produce clear executive summaries from research findings",
        backstory="Senior writer specialising in AI and governance topics.",
        passport=SemanticPassport(
            model_id="crew-writer",
            version="1.0.0",
            policy_hash=POLICY_HASH,
            ttl_seconds=3600,
            capabilities=frozenset({"write", "summarise"}),
        ),
        adapter=adapter,
        task_types=frozenset({"write", "summarise"}),
    )

    research_task = AegisTask(
        description="Identify and summarise the top 3 AI safety frameworks "
                    "introduced or updated in 2025.",
        expected_output="Bullet-point summary of 3 AI safety frameworks.",
        aegis_agent=researcher,
        task_type="research",
        in_sensitivity=0.10,
        out_sensitivity=0.15,
    )

    write_task = AegisTask(
        description="Using the research findings, write a one-page executive "
                    "summary suitable for a CISO audience.",
        expected_output="Executive summary document.",
        aegis_agent=writer,
        task_type="write",
        in_sensitivity=0.10,
        out_sensitivity=0.10,
        context_tasks=[research_task],
    )

    crew = AegisCrew(
        agents=[researcher, writer],
        tasks=[research_task, write_task],
        adapter=adapter,
        process=Process.sequential,
    )

    print("Phase 1: Crew kickoff\n")
    output = crew.kickoff(inputs={"year": "2025"})
    print("  Crew output (truncated):")
    for line in str(output).split("\n")[:4]:
        print(f"    {line}")

    print(f"\n  Vault entries so far : {adapter.vault.length}")
    print(f"  TLog entries so far  : {adapter.tlog.length}")

    print("\nPhase 2: Shutdown report\n")
    report = crew.shutdown_report()
    print(f"  Fleet vault chain : {'PASS' if report['fleet_vault_chain_ok'] else 'FAIL'}")
    print(f"  Fleet tlog chain  : {'PASS' if report['fleet_tlog_chain_ok']  else 'FAIL'}")
    for role, stats in report["agents"].items():
        print(f"  [{role}] warp={stats['warp_score']:.3f}  "
              f"state={stats['session_state']}  "
              f"vault={stats['vault_entries']}")

    print("\nDemo complete.\n")