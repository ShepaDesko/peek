/** Typed client for the Peek API. Same-origin only: there is no other host. */

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    field?: string;
    attempts_left?: number;
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly field?: string;
  readonly attemptsLeft?: number;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.error?.message ?? fallback);
    this.status = status;
    this.code = body?.error?.code ?? "unknown";
    this.field = body?.error?.field;
    this.attemptsLeft = body?.error?.attempts_left;
  }
}

async function request<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["X-Peek-Token"] = token;

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      // A secret must never be served from a cache, including the browser's.
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  } catch (cause) {
    throw new ApiError(0, null, cause instanceof Error ? cause.message : "network error");
  }

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }
  if (!response.ok) {
    throw new ApiError(response.status, parsed as ApiErrorBody | null, response.statusText);
  }
  return parsed as T;
}

export interface Branding {
  service_name: string;
  primary_color: string;
  accent_color: string;
  hide_powered_by: boolean;
  support_url: string;
  legal_url: string;
  privacy_url: string;
  language: string;
  palette: Record<string, string>;
  warnings?: string[];
}

export interface Policy {
  max_ttl_seconds: number;
  default_ttl_seconds: number;
  max_views: number;
  default_views: number;
  require_passphrase: boolean;
  force_retrieval_step: boolean;
  allowed_kinds: string[];
  max_file_bytes: number;
  max_secret_bytes: number;
  max_recipients: number;
  max_passphrase_attempts: number;
  kdf: { memory_kib: number; iterations: number; parallelism: number };
}

export interface SecretMeta {
  id: string;
  kind: string;
  has_passphrase: boolean;
  retrieval_step: boolean;
  deletable_by_recipient: boolean;
  views_remaining: number;
  views_max: number;
  expires_at: string;
  size_bytes: number;
  attempts_left: number;
  kdf: { salt: string; memory_kib: number; iterations: number; parallelism: number };
}

export interface CreateResponse {
  id: string;
  kind: string;
  views_max: number;
  expires_at: string;
  created_at: string;
  url: string;
}

export interface RevealResponse {
  kind: string;
  ciphertext: string;
  views_remaining: number;
  destroyed: boolean;
  size_bytes: number;
}

export interface Receipt {
  id: string;
  status: "active" | "viewed" | "expired" | "burned" | "deleted" | "locked";
  kind: string;
  views_used: number;
  views_max: number;
  views_remaining: number;
  created_at: string;
  expires_at: string | null;
  last_viewed_at: string | null;
  has_passphrase: boolean;
  url: string;
}

export interface CreateRequest {
  id: string;
  kind: string;
  ciphertext: string;
  read_token_hash: string;
  receipt_token_hash: string;
  kdf: { salt: string; memory_kib: number; iterations: number; parallelism: number };
  has_passphrase: boolean;
  ttl_seconds: number;
  views: number;
  retrieval_step: boolean;
  deletable_by_recipient: boolean;
  label_enc?: string;
}

export const api = {
  branding: () => request<Branding>("GET", "/api/v1/branding"),
  policy: () => request<Policy>("GET", "/api/v1/policy"),
  create: (body: CreateRequest) => request<CreateResponse>("POST", "/api/v1/secrets", body),
  meta: (id: string) => request<SecretMeta>("GET", `/api/v1/secrets/${encodeURIComponent(id)}`),
  reveal: (id: string, readToken: string) =>
    request<RevealResponse>("POST", `/api/v1/secrets/${encodeURIComponent(id)}/reveal`, {
      read_token: readToken,
    }),
  receipt: (id: string, receiptToken: string) =>
    request<Receipt>("GET", `/api/v1/secrets/${encodeURIComponent(id)}/receipt`, undefined, receiptToken),
  burn: (id: string, receiptToken: string) =>
    request<void>("POST", `/api/v1/secrets/${encodeURIComponent(id)}/burn`, undefined, receiptToken),
  deleteByRecipient: (id: string, readToken: string) =>
    request<void>("DELETE", `/api/v1/secrets/${encodeURIComponent(id)}`, undefined, readToken),
};
