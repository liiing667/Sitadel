"""Shared batch lifecycle for the attack phase.

One :class:`Batch` binds together the four pieces of state that used to drift
apart:

* the *request budget* (a bounded slot set, so a cancelled/aborted batch stops
  handing work — including rate-limiter queue slots — to workers);
* the *worker futures* (every submitted task is tracked and reaped before the
  batch closes);
* the *cancel signal* (the shared ``Services["cancel"]`` event, plus any local
  failure such as a request storm);
* the *Findings submission* (a batch gate so a finding produced by a worker can
  never reach the report collector after the batch — and therefore the scan —
  has completed).

Without this coupling, a rate-limited queue could keep draining for a while
after the user cancelled the scan, and a late worker could write a finding
into the report *after* the completion event had already been published.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Callable, Iterable

from sitadel.utils.container import Services


def shared_cancel_event():
    """Return the registered scan-wide cancel event, or ``None``.

    Plain CLI scans (no TUI) never register one; in that case cancellation is
    driven only by the batch's own local failure state.
    """
    try:
        return Services.get("cancel")
    except NameError:
        return None


def is_cancelled() -> bool:
    """Whether the scan-wide cancel signal has been set (else ``False``)."""
    event = shared_cancel_event()
    return event is not None and event.is_set()


class BatchClosed(RuntimeError):
    """Raised when work is submitted to a finished batch."""


class Batch:
    """One bounded, cancellable unit of attack work.

    All access is thread-safe: worker threads call :meth:`cancelled`,
    :meth:`acquire` and the registered Findings gate concurrently while the
    owning thread drives :meth:`run` and :meth:`close`.
    """

    def __init__(self, workers: int = 20, budget: int | None = None,
                 name: str = "attack"):
        if workers < 1:
            raise ValueError("batch workers must be >= 1")
        self.name = name
        # The request budget: at most ``budget`` slots exist for the whole
        # batch. ``None`` (or a non-positive value) means unbounded, matching
        # the previous "submit every probe" behaviour.
        self._slots = (
            threading.BoundedSemaphore(budget)
            if budget and budget > 0 else None
        )
        # Futures of every task the pool accepted, so close() can reap them.
        self._futures: list = []
        self._state_lock = threading.Lock()
        self._closed = False
        self._aborted = False
        self._cancel = shared_cancel_event()
        self._executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix=name
        )
        self._workers = workers
        # Publish the Findings gate so every output.finding() made on behalf
        # of this batch is checked against the same state as its workers.
        Services.register("attack_batch", self)

    # ------------------------------------------------------------- state #
    def cancelled(self) -> bool:
        """Whether the batch must stop: external cancel or local abort."""
        if self._closed or self._aborted:
            return True
        return self._cancel is not None and self._cancel.is_set()

    def abort(self) -> None:
        """Stop the batch from inside (e.g. a request-error storm).

        Idempotent and safe to call from any worker thread. Already in-flight
        workers converge on their next :meth:`cancelled` check; queued tasks
        are refused their slot and return without touching the network.
        """
        with self._state_lock:
            if self._closed:
                return
            self._aborted = True

    def accepts_findings(self) -> bool:
        """Whether this batch still allows Findings to reach the report.

        A normally completed batch keeps accepting (its workers have all
        joined in :meth:`close`, so no late write is possible anyway); a
        cancelled or aborted batch rejects everything so a worker still
        unwinding cannot leak a finding into the finished report.
        """
        return not (
            self._aborted
            or (self._cancel is not None and self._cancel.is_set())
        )

    # ---------------------------------------------------- request budget #
    def acquire(self, timeout: float | None = None) -> bool:
        """Reserve one request-budget slot.

        Returns ``False`` — without blocking — when the batch is already over,
        so a rate-limiter queue that keeps waking after cancel converges
        immediately instead of launching another probe.
        """
        if self.cancelled():
            return False
        if self._slots is None:
            return True
        return self._slots.acquire(timeout=timeout)

    def release(self) -> None:
        """Return a slot previously taken with :meth:`acquire`."""
        if self._slots is not None:
            self._slots.release()

    # ---------------------------------------------------------- futures #
    def submit(self, fn: Callable, *args, **kwargs):
        """Schedule ``fn`` on the batch pool, tracking its future.

        Raises :class:`BatchClosed` once the batch has finished, so no task
        can be spawned against a pool that is shutting down.
        """
        with self._state_lock:
            if self._closed:
                raise BatchClosed(f"{self.name} batch is closed")
            future = self._executor.submit(fn, *args, **kwargs)
            self._futures.append(future)
            return future

    # ------------------------------------------------- findings gate #
    def finding(self, output, value: str, **kwargs) -> bool:
        """Submit a finding only while the batch still accepts them.

        Returns ``True`` when the finding reached the report collector, and
        ``False`` when it was dropped because the batch was cancelled or
        aborted. This is the single choke point that prevents late workers
        from writing into a report whose completion event already fired.
        """
        if not self.accepts_findings():
            return False
        output.finding(value, **kwargs)
        return True

    # ----------------------------------------------------------- driver #
    def run(self, tasks: Iterable[tuple[Callable, tuple]]) -> None:
        """Submit ``tasks`` as ``(callable, args)`` pairs and drain them.

        At most ``workers`` tasks are ever in flight, so the pool size doubles
        as the batch's request budget: once cancel/abort lands, only the
        current wave (≤ workers) can still touch the network — the rest of the
        queue is never submitted, instead of sitting inside the executor.
        The loop ends as soon as the signal is observed; everything is reaped
        in :meth:`close`, which the context manager guarantees runs.
        """
        in_flight: set = set()
        queue = iter(tasks)
        # Prime the window with at most ``workers`` tasks.
        for _ in range(self._workers):
            try:
                fn, args = next(queue)
            except StopIteration:
                break
            if self.cancelled():
                break
            in_flight.add(self.submit(fn, *args))
        # Slide the window: refill one slot only after one worker finished, so
        # the pool never holds more than one in-flight wave of queued work.
        while in_flight and not self.cancelled():
            done, in_flight = wait(in_flight, return_when="FIRST_COMPLETED")
            for future in done:
                exc = future.exception()
                if exc is not None and not isinstance(exc, BatchClosed):
                    raise exc
                if self.cancelled():
                    break
                try:
                    fn, args = next(queue)
                except StopIteration:
                    continue
                try:
                    in_flight.add(self.submit(fn, *args))
                except BatchClosed:
                    break
        for future in in_flight:
            future.cancel()

    def close(self) -> None:
        """Converge every worker before the batch is considered finished."""
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
        # Cancel work that never started; in-flight requests run to their own
        # (configured) timeout, then the pool shutdown joins every worker.
        for future in self._futures:
            future.cancel()
        self._executor.shutdown(wait=True, cancel_futures=True)
        # Release the Findings gate only after every worker has joined: this
        # is the happens-before edge that makes a post-completion write
        # impossible. Only unregister when this batch is still the active one
        # (nested/overlapping batches never replace each other's gate).
        if Services.services.get("attack_batch") is self:
            Services.services.pop("attack_batch", None)

    # ------------------------------------------------------- context mgr #
    def __enter__(self) -> "Batch":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # A KeyboardInterrupt is a legitimate user cancel: mark the batch so
        # workers stop, then let the original exception propagate.
        if exc_type is not None:
            self.abort()
        self.close()
