/**
 * The one place a server response becomes a typed result or a typed failure.
 *
 * Everything above this module branches on `ApiError.code`, never on the
 * message: internal/httpapi/errors.go states that codes are stable and messages
 * are for humans and may change.
 */

export type ApiErrorCode =
  | "bad_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "internal";

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  /** The whole parsed envelope. A 409 carries a sibling `item`; discarding it
   *  would leave the client unable to build a conflicted copy. */
  readonly body: unknown;

  constructor(code: ApiErrorCode, status: number, message: string, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.body = body;
  }
}

/** The server was not reached at all. Distinct from every ApiError, because
 *  design spec 9 forbids a network blip reading as a wrong password. */
export class NetworkError extends Error {
  constructor(cause: unknown) {
    super("Could not reach the server");
    this.name = "NetworkError";
    this.cause = cause;
  }
}

export interface ApiClient {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
  put<T>(path: string, body: unknown): Promise<T>;
  patch<T>(path: string, body: unknown): Promise<T>;
  del<T>(path: string): Promise<T>;
}

export interface ApiClientOptions {
  baseUrl?: string;
  getAccessToken: () => string | null;
  /** Attempt to refresh. Resolves true if the request is worth retrying.
   *  Called at most once per request — see the loop note below. */
  onUnauthorized: () => Promise<boolean>;
  fetchImpl?: typeof fetch;
}

const KNOWN_CODES: readonly string[] = [
  "bad_request",
  "unauthorized",
  "forbidden",
  "not_found",
  "conflict",
  "rate_limited",
  "internal",
];

function toApiError(status: number, body: unknown): ApiError {
  const envelope = body as { error?: { code?: string; message?: string } } | null;
  const rawCode = envelope?.error?.code;
  // An unrecognised or absent code is treated as `internal` rather than trusted:
  // a proxy error page or a truncated body must not be reported as the caller's
  // fault, and must not crash the branch that reads it.
  const code = (rawCode && KNOWN_CODES.includes(rawCode) ? rawCode : "internal") as ApiErrorCode;
  const message = envelope?.error?.message ?? "The server returned an error";
  return new ApiError(code, status, message, body);
}

export function createApiClient(opts: ApiClientOptions): ApiClient {
  const baseUrl = opts.baseUrl ?? "";
  const doFetch = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);

  async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const send = async (): Promise<Response> => {
      const headers: Record<string, string> = {};
      const token = opts.getAccessToken();
      if (token !== null) {
        headers.Authorization = `Bearer ${token}`;
      }
      const init: RequestInit = { method, headers };
      if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
      }
      try {
        return await doFetch(`${baseUrl}${path}`, init);
      } catch (cause) {
        throw new NetworkError(cause);
      }
    };

    let response = await send();

    // Exactly one retry. The refresh token is single-use server-side —
    // RotateSession matches on the old hash and replaces it — so a loop would
    // spend the session and turn one expiry into a confusing cascade.
    if (response.status === 401 && (await opts.onUnauthorized())) {
      response = await send();
    }

    if (response.status === 204 || response.headers.get("Content-Length") === "0") {
      return null as T;
    }

    let parsed: unknown = null;
    const text = await response.text();
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text);
      } catch {
        // A non-JSON body from a proxy or gateway. Not the caller's fault.
        if (response.ok) {
          throw new ApiError("internal", response.status, "Malformed response", text);
        }
      }
    }

    if (!response.ok) {
      throw toApiError(response.status, parsed);
    }
    return parsed as T;
  }

  return {
    get: (path) => request("GET", path),
    post: (path, body) => request("POST", path, body),
    put: (path, body) => request("PUT", path, body),
    patch: (path, body) => request("PATCH", path, body),
    del: (path) => request("DELETE", path),
  };
}
