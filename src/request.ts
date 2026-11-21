// src/request.ts
import { AsyncLocalStorage } from "node:async_hooks";

/**
 * The abort signal of the MCP request a tool call is serving (issue #1).
 *
 * The SDK aborts it when the client sends `notifications/cancelled` for the
 * request, and when the transport closes. Carried in async context rather than
 * threaded through every tool signature, so the consent runner and the gate can
 * both see it without each of the ten tools re-plumbing it: `mcp.ts` sets it
 * once per `tools/call`, and every await below that call inherits it.
 *
 * Concurrent calls each get their own store, so one call's cancellation never
 * reaches another call's dialog or keystrokes.
 */
const store = new AsyncLocalStorage<AbortSignal>();

export function runWithRequestSignal<T>(signal: AbortSignal | undefined, fn: () => Promise<T>): Promise<T> {
  return signal ? store.run(signal, fn) : fn();
}

/** The current request's signal, or undefined outside a request (tests, direct calls). */
export function requestSignal(): AbortSignal | undefined {
  return store.getStore();
}

export function requestCancelled(): boolean {
  return requestSignal()?.aborted === true;
}
