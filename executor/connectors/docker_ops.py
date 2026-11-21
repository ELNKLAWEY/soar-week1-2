"""Container actions (isolate / restart) through the Docker CLI on a restricted socket."""

from __future__ import annotations

import subprocess


class DockerConnector:
    def __init__(self, network: str = "sentinel_lab") -> None:
        self.network = network

    def isolate_container(self, container: str) -> dict:
        self._run("network", "disconnect", self.network, container)
        return {"container": container, "isolated": True, "network": self.network}

    def restart_service(self, container: str) -> dict:
        self._run("restart", container)
        return {"container": container, "restarted": True}

    @staticmethod
    def _run(*args: str) -> None:
        proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"docker {' '.join(args)} failed: {proc.stderr.strip()}")
