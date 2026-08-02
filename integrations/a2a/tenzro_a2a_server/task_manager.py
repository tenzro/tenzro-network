"""In-memory A2A task state machine."""

import time
import uuid


class TaskManager:
    """Manages A2A task lifecycle: submitted -> working -> completed/failed/canceled."""

    def __init__(self):
        self.tasks: dict[str, dict] = {}

    def create_task(
        self,
        message: dict,
        context_id: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Create a new task from an incoming message."""
        task_id = str(uuid.uuid4())
        task = {
            "id": task_id,
            "contextId": context_id or str(uuid.uuid4()),
            "status": {
                "state": "submitted",
                "message": message,
                "timestamp": int(time.time()),
            },
            "history": [message],
            "artifacts": [],
            "metadata": metadata or {},
        }
        self.tasks[task_id] = task
        return task

    def update_state(
        self,
        task_id: str,
        state: str,
        agent_message: dict | None = None,
    ):
        """Transition a task to a new state, optionally appending an agent message."""
        task = self.tasks[task_id]
        task["status"]["state"] = state
        task["status"]["timestamp"] = int(time.time())
        if agent_message:
            task["status"]["message"] = agent_message
            task["history"].append(agent_message)

    def add_artifact(self, task_id: str, artifact: dict):
        """Attach an artifact (file, data) to a task."""
        task = self.tasks.get(task_id)
        if task:
            task["artifacts"].append(artifact)

    def get_task(
        self,
        task_id: str,
        history_length: int | None = None,
    ) -> dict | None:
        """Retrieve a task, optionally truncating history."""
        task = self.tasks.get(task_id)
        if task and history_length:
            task = {**task, "history": task["history"][-history_length:]}
        return task

    def list_tasks(self, context_id: str | None = None) -> list:
        """List all tasks, optionally filtered by context ID."""
        tasks = list(self.tasks.values())
        if context_id:
            tasks = [t for t in tasks if t["contextId"] == context_id]
        return tasks

    def cancel_task(self, task_id: str) -> dict | None:
        """Cancel a task if it exists."""
        task = self.tasks.get(task_id)
        if task:
            task["status"]["state"] = "canceled"
            task["status"]["timestamp"] = int(time.time())
        return task
