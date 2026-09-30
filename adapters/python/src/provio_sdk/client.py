"""`ProvioClient`: a long-lived `provio check --stdio` child process (Contract 6).

One process serves many requests. Requests carry ids; a reader thread routes
each response line to the waiting caller. The client is thread-safe, and
:class:`AsyncProvioClient` shares the same machinery without blocking the
event loop.

Fail-closed rules (every one raises a :class:`~provio_sdk.errors.ProvioError`):

* binary missing or not startable            -> ``ProvioUnavailable``
* process exits with requests in flight      -> ``ProvioGatewayCrashed``
* no answer within ``timeout``               -> ``ProvioTimeout`` (process is killed)
* non-JSON line, unknown id, contradiction   -> ``ProvioProtocolError`` (process is killed)
* ``{"error": ...}`` response                -> ``ProvioGatewayError``
* too many restarts in ``restart_window``    -> ``ProvioUnavailable``

A request is never retried automatically: a retried ``decide`` could write a
second Decision record for one tool call (Contract 3). A crashed gateway is
restarted lazily on the *next* request, within the restart budget.
"""

from __future__ import annotations

import asyncio
import atexit
import collections
import concurrent.futures
import itertools
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import weakref
from typing import Any, Literal, Mapping, Sequence

from .errors import (
    ProvioClosed,
    ProvioError,
    ProvioGatewayCrashed,
    ProvioProtocolError,
    ProvioTimeout,
    ProvioUnavailable,
)
from .types import (
    PROTOCOL_VERSION,
    Completion,
    Decision,
    ToolCall,
    check_envelope,
    parse_completion,
    parse_decision,
)

AskMode = Literal["deny", "defer", "ui"]

#: Response timeout when ``ask="ui"`` and none is given: longer than the
#: console's default approval window (120 s), since `decide` waits for it.
UI_ASK_TIMEOUT = 180.0

_STDERR_TAIL_LINES = 40
_LIVE_CLIENTS: "weakref.WeakSet[ProvioClient]" = weakref.WeakSet()


def _close_all_at_exit() -> None:
    for client in list(_LIVE_CLIENTS):
        try:
            client.close()
        except Exception:
            pass


atexit.register(_close_all_at_exit)


def bundled_provio_binary() -> str | None:
    """The ``provio`` executable installed by the ``provio`` package, if any.

    ``provio-sdk`` depends on ``provio``, whose platform wheels carry the
    compiled binary as an installed script. Resolving it through the package
    metadata finds it even when the environment's scripts directory is not on
    ``PATH`` (an unactivated virtualenv, ``pip install --user``).
    """
    try:
        from importlib import metadata

        dist = metadata.distribution("provio")
    except Exception:
        return None
    names = {"provio", "provio.exe"}
    for entry in dist.files or ():
        if entry.name.lower() in names:
            path = os.path.abspath(str(dist.locate_file(entry)))
            if os.path.isfile(path):
                return path
    return None


def find_provio_binary(binary: str | os.PathLike[str] | None = None) -> list[str]:
    """Resolve the argv prefix that starts provio.

    Order: explicit ``binary`` argument, then the ``PROVIO_BIN`` environment
    variable, then the binary bundled by the ``provio`` package, then
    ``provio`` on ``PATH``. A path ending in ``.py`` is run with the current
    interpreter (useful for protocol test doubles).
    """
    candidate = os.fspath(binary) if binary is not None else os.environ.get("PROVIO_BIN")
    source = "binary argument" if binary is not None else "PROVIO_BIN"
    if candidate:
        has_sep = os.sep in candidate or (os.altsep is not None and os.altsep in candidate)
        if has_sep or os.path.isfile(candidate):
            if not os.path.isfile(candidate):
                raise ProvioUnavailable(f"provio binary from {source} not found: {candidate}")
            path = os.path.abspath(candidate)
        else:
            found = shutil.which(candidate)
            if not found:
                raise ProvioUnavailable(f"provio binary from {source} not found on PATH: {candidate}")
            path = found
    else:
        found = bundled_provio_binary() or shutil.which("provio")
        if not found:
            raise ProvioUnavailable(
                "provio binary not found: install provio-cli (`pip install provio`), "
                "set PROVIO_BIN, or put `provio` on PATH "
                "(tool calls are blocked until provio is available)"
            )
        path = found
    if path.lower().endswith(".py"):
        return [sys.executable, path]
    return [path]


class _Gateway:
    """One running `provio check --stdio` process."""

    def __init__(self, argv: Sequence[str], cwd: str | None, env: Mapping[str, str] | None) -> None:
        self.argv = list(argv)
        self._pending: dict[str, concurrent.futures.Future[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._dead: ProvioError | None = None
        self._stderr: collections.deque[str] = collections.deque(maxlen=_STDERR_TAIL_LINES)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        try:
            self.proc = subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=dict(env) if env is not None else None,
                bufsize=-1,
                creationflags=creationflags,
            )
        except OSError as e:
            raise ProvioUnavailable(f"cannot start provio ({self.argv[0]}): {e}") from e
        self._reader = threading.Thread(target=self._read_stdout, name="provio-check-stdout", daemon=True)
        self._err_reader = threading.Thread(target=self._read_stderr, name="provio-check-stderr", daemon=True)
        self._reader.start()
        self._err_reader.start()

    # -- state -------------------------------------------------------------

    @property
    def alive(self) -> bool:
        return self._dead is None and self.proc.poll() is None

    def stderr_tail(self) -> str:
        return "\n".join(self._stderr)

    def _fail(self, err: ProvioError) -> None:
        """Mark dead, kill the process, fail every pending request with ``err``."""
        with self._lock:
            if self._dead is None:
                self._dead = err
            pending = list(self._pending.values())
            self._pending.clear()
        for fut in pending:
            if not fut.done():
                try:
                    fut.set_exception(err)
                except concurrent.futures.InvalidStateError:
                    pass
        self._kill()

    def _kill(self) -> None:
        try:
            if self.proc.poll() is None:
                self.proc.kill()
        except OSError:
            pass

    # -- I/O ---------------------------------------------------------------

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        stream = self.proc.stdout
        try:
            for raw in iter(stream.readline, b""):
                line = raw.rstrip(b"\r\n")
                try:
                    msg = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    self._fail(ProvioProtocolError(f"malformed line from provio check: {line[:200]!r}"))
                    return
                rid = msg.get("id") if isinstance(msg, dict) else None
                with self._lock:
                    fut = self._pending.pop(rid, None) if isinstance(rid, str) else None
                if fut is None:
                    self._fail(ProvioProtocolError(f"response for unknown request id {rid!r}"))
                    return
                if not fut.done():
                    try:
                        fut.set_result(msg)
                    except concurrent.futures.InvalidStateError:
                        pass
        except (OSError, ValueError):
            pass
        code = self.proc.wait()
        self._err_reader.join(timeout=0.5)  # let the exit reason reach the message
        detail = self.stderr_tail()
        self._fail(
            ProvioGatewayCrashed(
                f"provio check exited (code {code})" + (f": {detail}" if detail else "")
            )
        )

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        try:
            for raw in iter(self.proc.stderr.readline, b""):
                self._stderr.append(raw.decode("utf-8", "replace").rstrip())
        except (OSError, ValueError):
            pass

    def submit(self, request: dict[str, Any]) -> concurrent.futures.Future[dict[str, Any]]:
        # Serialize first: an unserializable request must not leave a pending entry.
        data = (json.dumps(request, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        fut: concurrent.futures.Future[dict[str, Any]] = concurrent.futures.Future()
        rid = request["id"]
        with self._lock:
            if self._dead is not None:
                raise ProvioGatewayCrashed(f"provio check is not running: {self._dead}")
            self._pending[rid] = fut
        try:
            with self._write_lock:
                assert self.proc.stdin is not None
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
        except (OSError, ValueError) as e:
            self._fail(ProvioGatewayCrashed(f"cannot write to provio check: {e}"))
            raise ProvioGatewayCrashed(f"cannot write to provio check: {e}") from e
        return fut

    def close(self, grace: float = 2.0) -> None:
        with self._lock:
            if self._dead is None:
                self._dead = ProvioClosed("provio client closed")
            pending = list(self._pending.values())
            self._pending.clear()
        for fut in pending:
            if not fut.done():
                try:
                    fut.set_exception(ProvioClosed("provio client closed"))
                except concurrent.futures.InvalidStateError:
                    pass
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self._kill()
            try:
                self.proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass
        for stream in (self.proc.stdout, self.proc.stderr):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass


class ProvioClient:
    """Synchronous, thread-safe client for `provio check --stdio`.

    Args:
        binary: path or name of the provio binary (default: ``PROVIO_BIN``, then PATH).
        policy: ``--policy`` path (default: provio's own default, ``./provio.yaml``).
        ledger: ``--ledger`` path (default: provio's own default).
        ask: ``--ask`` mode. ``"deny"`` (default) fails every ask closed;
            ``"defer"`` returns asks for an approver to resolve; ``"ui"``
            waits for a human decision on the ``provio ui`` Approvals screen
            (no console, a denial or a timeout all deny).
        timeout: seconds to wait for each response (default 30; 180 with
            ``ask="ui"``, where a ``decide`` waits for the console).
        command: argv prefix that replaces the binary lookup entirely
            (e.g. ``["python", "fake_provio.py"]``). Flags are appended.
        cwd, env: working directory and environment for the child.
        max_restarts: restarts allowed within ``restart_window`` seconds after
            crashes/timeouts before the client refuses to start provio again.
    """

    def __init__(
        self,
        *,
        binary: str | os.PathLike[str] | None = None,
        policy: str | os.PathLike[str] | None = None,
        ledger: str | os.PathLike[str] | None = None,
        ask: AskMode = "deny",
        timeout: float | None = None,
        command: Sequence[str] | None = None,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        max_restarts: int = 3,
        restart_window: float = 60.0,
    ) -> None:
        if ask not in ("deny", "defer", "ui"):
            raise ValueError("ask must be 'deny', 'defer' or 'ui'")
        if timeout is None:
            timeout = UI_ASK_TIMEOUT if ask == "ui" else 30.0
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.ask: AskMode = ask
        self.timeout = float(timeout)
        self._binary = binary
        self._command = list(command) if command is not None else None
        self._policy = os.fspath(policy) if policy is not None else None
        self._ledger = os.fspath(ledger) if ledger is not None else None
        self._cwd = os.fspath(cwd) if cwd is not None else None
        self._env = dict(env) if env is not None else None
        self._max_restarts = max_restarts
        self._restart_window = restart_window
        self._spawns: collections.deque[float] = collections.deque()
        self._gateway: _Gateway | None = None
        self._spawn_lock = threading.Lock()
        self._ids = itertools.count(1)
        self._id_prefix = f"py{os.getpid()}-{id(self) & 0xFFFFFF:x}"
        self._closed = False
        _LIVE_CLIENTS.add(self)

    # -- lifecycle ---------------------------------------------------------

    def argv(self) -> list[str]:
        """The full command line used to start the gateway."""
        prefix = self._command if self._command is not None else find_provio_binary(self._binary)
        argv = list(prefix)
        if self._policy is not None:
            argv += ["--policy", self._policy]
        if self._ledger is not None:
            argv += ["--ledger", self._ledger]
        argv += ["check", "--stdio", "--ask", self.ask]
        return argv

    def start(self) -> None:
        """Start the gateway now instead of on the first request."""
        self._ensure_gateway()

    def _ensure_gateway(self) -> _Gateway:
        with self._spawn_lock:
            if self._closed:
                raise ProvioClosed("provio client closed")
            gw = self._gateway
            if gw is not None and gw.alive:
                return gw
            if gw is not None:
                gw.close(grace=0.5)
                self._gateway = None
            now = time.monotonic()
            while self._spawns and now - self._spawns[0] > self._restart_window:
                self._spawns.popleft()
            # First spawn is free; after that, at most max_restarts per window.
            if len(self._spawns) > self._max_restarts:
                raise ProvioUnavailable(
                    f"provio check restarted more than {self._max_restarts} times in "
                    f"{self._restart_window:.0f}s; refusing to start it again"
                )
            self._gateway = _Gateway(self.argv(), self._cwd, self._env)
            self._spawns.append(now)
            return self._gateway

    def close(self) -> None:
        """Close stdin, let provio flush and exit, kill it after a grace period."""
        with self._spawn_lock:
            self._closed = True
            gw, self._gateway = self._gateway, None
        if gw is not None:
            gw.close()
        _LIVE_CLIENTS.discard(self)

    def __enter__(self) -> ProvioClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- request plumbing --------------------------------------------------

    def _next_id(self) -> str:
        return f"{self._id_prefix}-{next(self._ids)}"

    def _submit(self, body: dict[str, Any]) -> tuple[str, _Gateway, concurrent.futures.Future[dict[str, Any]]]:
        rid = self._next_id()
        request = {"v": PROTOCOL_VERSION, "id": rid, **body}
        gw = self._ensure_gateway()
        return rid, gw, gw.submit(request)

    def _on_timeout(self, gw: _Gateway, rid: str, timeout: float) -> ProvioTimeout:
        err = ProvioTimeout(f"provio check did not answer request {rid} within {timeout:g}s")
        # Responses are ordered; everything behind a stuck request is stuck too.
        gw._fail(err)
        return err

    def _request(self, body: dict[str, Any], timeout: float | None) -> Mapping[str, Any]:
        t = self.timeout if timeout is None else timeout
        rid, gw, fut = self._submit(body)
        try:
            msg = fut.result(timeout=t)
        except concurrent.futures.TimeoutError:
            raise self._on_timeout(gw, rid, t) from None
        except ProvioError:
            raise
        except Exception as e:  # pragma: no cover - defensive
            raise ProvioProtocolError(f"unexpected gateway failure: {e!r}") from e
        return check_envelope(msg, rid)

    # -- operations --------------------------------------------------------

    @staticmethod
    def _decide_body(call: ToolCall | Mapping[str, Any]) -> dict[str, Any]:
        wire = call.to_wire() if isinstance(call, ToolCall) else dict(call)
        return {"op": "decide", "call": wire}

    @staticmethod
    def _resolve_body(ref: str, approved: bool, approver: str | None) -> dict[str, Any]:
        if not ref:
            raise ProvioProtocolError("resolve needs the ref from decide")
        body: dict[str, Any] = {"op": "resolve", "ref": ref, "approved": bool(approved)}
        if approver:
            body["approver"] = approver
        return body

    @staticmethod
    def _complete_body(ref: str, ok: bool, exit: int | None, output: str | None) -> dict[str, Any]:
        if not ref:
            raise ProvioProtocolError("complete needs the ref from decide")
        body: dict[str, Any] = {"op": "complete", "ref": ref, "ok": bool(ok)}
        if exit is not None:
            body["exit"] = int(exit)
        if output is not None:
            body["output"] = output
        return body

    def decide(self, call: ToolCall | Mapping[str, Any], *, timeout: float | None = None) -> Decision:
        """Ask provio whether ``call`` may dispatch."""
        return parse_decision(self._request(self._decide_body(call), timeout))

    def resolve(
        self, ref: str, approved: bool, approver: str | None = None, *, timeout: float | None = None
    ) -> Decision:
        """Send a human decision for a deferred ask; returns the final decision."""
        return parse_decision(self._request(self._resolve_body(ref, approved, approver), timeout), final=True)

    def complete(
        self,
        ref: str,
        ok: bool,
        *,
        exit: int | None = None,
        output: str | None = None,
        timeout: float | None = None,
    ) -> Completion:
        """Record the execution. For a redact verdict, returns the redacted output."""
        return parse_completion(self._request(self._complete_body(ref, ok, exit, output), timeout))


class AsyncProvioClient:
    """``asyncio`` front end over a :class:`ProvioClient` (same process, same rules).

    Awaiting a request never blocks the event loop on the gateway's reply.
    Can wrap an existing sync client so sync and async code share one process.
    """

    def __init__(self, client: ProvioClient | None = None, **kwargs: Any) -> None:
        if client is not None and kwargs:
            raise TypeError("pass either an existing ProvioClient or constructor kwargs, not both")
        self.sync = client if client is not None else ProvioClient(**kwargs)

    @property
    def ask(self) -> AskMode:
        return self.sync.ask

    async def _request(self, body: dict[str, Any], timeout: float | None) -> Mapping[str, Any]:
        t = self.sync.timeout if timeout is None else timeout
        rid, gw, fut = self.sync._submit(body)
        try:
            msg = await asyncio.wait_for(asyncio.wrap_future(fut), timeout=t)
        except asyncio.TimeoutError:
            raise self.sync._on_timeout(gw, rid, t) from None
        return check_envelope(msg, rid)

    async def start(self) -> None:
        await asyncio.to_thread(self.sync.start)

    async def decide(self, call: ToolCall | Mapping[str, Any], *, timeout: float | None = None) -> Decision:
        return parse_decision(await self._request(ProvioClient._decide_body(call), timeout))

    async def resolve(
        self, ref: str, approved: bool, approver: str | None = None, *, timeout: float | None = None
    ) -> Decision:
        body = ProvioClient._resolve_body(ref, approved, approver)
        return parse_decision(await self._request(body, timeout), final=True)

    async def complete(
        self,
        ref: str,
        ok: bool,
        *,
        exit: int | None = None,
        output: str | None = None,
        timeout: float | None = None,
    ) -> Completion:
        body = ProvioClient._complete_body(ref, ok, exit, output)
        return parse_completion(await self._request(body, timeout))

    async def aclose(self) -> None:
        await asyncio.to_thread(self.sync.close)

    def close(self) -> None:
        self.sync.close()

    async def __aenter__(self) -> AsyncProvioClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
