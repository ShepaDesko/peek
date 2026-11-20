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

/** Reads the CSRF cookie the server set. It is readable on purpose. */
export function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)peek_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["X-Peek-Token"] = token;
  if (method !== "GET" && method !== "HEAD") {
    // The double-submit token: proof that the request came from our own page.
    const csrf = csrfToken();
    if (csrf) headers["X-Peek-CSRF"] = csrf;
  }

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
    request<Receipt>(
      "GET",
      `/api/v1/secrets/${encodeURIComponent(id)}/receipt`,
      undefined,
      receiptToken,
    ),
  burn: (id: string, receiptToken: string) =>
    request<void>(
      "POST",
      `/api/v1/secrets/${encodeURIComponent(id)}/burn`,
      undefined,
      receiptToken,
    ),
  deleteByRecipient: (id: string, readToken: string) =>
    request<void>("DELETE", `/api/v1/secrets/${encodeURIComponent(id)}`, undefined, readToken),
};

// --- accounts ----------------------------------------------------------------

export type Role = "admin" | "manager" | "member" | "auditor";
export type UserStatus = "active" | "invited" | "disabled";

export interface User {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  status: UserStatus;
  has_totp: boolean;
  must_change_password: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface Me {
  authenticated: boolean;
  user?: User;
  mfa_pending?: boolean;
  needs_bootstrap?: boolean;
  anonymous_create?: boolean;
  has_totp?: boolean;
  recovery_left?: number;
  require_totp?: boolean;
  passkeys?: boolean;
  can_manage?: boolean;
  can_administer?: boolean;
  can_audit?: boolean;
  session_expires?: string;
}

export interface LoginResponse {
  mfa_required: boolean;
  must_enrol_totp: boolean;
  user: User;
}

export interface SessionInfo {
  id: string;
  current: boolean;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  ip: string;
  user_agent: string;
}

export interface PasskeyInfo {
  id: string;
  name: string;
  credential_id: string;
  created_at: string;
  last_used_at: string | null;
  backed_up: boolean;
  transports: string;
}

export interface InvitationInfo {
  id: string;
  email: string;
  role: Role;
  created_at: string;
  expires_at: string;
}

export interface DashboardSecret {
  id: string;
  kind: string;
  status: "active" | "viewed" | "expired" | "burned" | "deleted" | "locked";
  views_used: number;
  views_max: number;
  views_remaining: number;
  has_passphrase: boolean;
  size_bytes: number;
  created_at: string;
  expires_at?: string;
  last_event_at?: string;
  label_enc?: string;
}

export interface AuditEntry {
  id: number;
  org_id: string;
  secret_id?: string;
  user_id?: string;
  event: string;
  at: string;
  ip?: string;
  user_agent?: string;
  detail?: Record<string, string>;
}

/** Minimal shapes of what the WebAuthn API takes; the browser fills the rest. */
export type CredentialCreationOptionsJSON = Record<string, unknown>;
export type CredentialRequestOptionsJSON = Record<string, unknown>;

export const auth = {
  me: () => request<Me>("GET", "/api/v1/auth/me"),
  login: (email: string, password: string) =>
    request<LoginResponse>("POST", "/api/v1/auth/login", { email, password }),
  mfa: (code: string) => request<{ user: User }>("POST", "/api/v1/auth/mfa", { code }),
  logout: () => request<void>("POST", "/api/v1/auth/logout"),
  bootstrap: (email: string, password: string, display_name: string) =>
    request<{ user: User }>("POST", "/api/v1/auth/bootstrap", { email, password, display_name }),
  changePassword: (current: string, next: string) =>
    request<void>("POST", "/api/v1/auth/password", { current, next }),
  forgotPassword: (email: string) =>
    request<{ sent: boolean; mail_configured: boolean }>("POST", "/api/v1/auth/password/forgot", {
      email,
    }),
  resetPassword: (token: string, password: string) =>
    request<void>("POST", "/api/v1/auth/password/reset", { token, password }),

  startTotp: () => request<{ secret: string; uri: string }>("POST", "/api/v1/auth/totp/start"),
  confirmTotp: (code: string) =>
    request<{ recovery_codes: string[] }>("POST", "/api/v1/auth/totp/confirm", { code }),
  disableTotp: (password: string) =>
    request<void>("POST", "/api/v1/auth/totp/disable", { password }),
  regenerateRecoveryCodes: () =>
    request<{ recovery_codes: string[] }>("POST", "/api/v1/auth/recovery-codes"),

  sessions: () => request<{ sessions: SessionInfo[] }>("GET", "/api/v1/auth/sessions"),
  revokeSession: (id: string) =>
    request<void>("DELETE", `/api/v1/auth/sessions/${encodeURIComponent(id)}`),
  revokeOtherSessions: () =>
    request<{ revoked: number }>("POST", "/api/v1/auth/sessions/revoke-others"),

  passkeys: () =>
    request<{ passkeys: PasskeyInfo[]; supported: boolean }>("GET", "/api/v1/auth/passkeys"),
  passkeyRegisterStart: () =>
    request<{ options: { publicKey: CredentialCreationOptionsJSON }; challenge_id: string }>(
      "POST",
      "/api/v1/auth/passkeys/register/start",
    ),
  passkeyRegisterFinish: (challenge_id: string, name: string, response: unknown) =>
    request<{ passkey: PasskeyInfo }>("POST", "/api/v1/auth/passkeys/register/finish", {
      challenge_id,
      name,
      response,
    }),
  passkeyLoginStart: () =>
    request<{ options: { publicKey: CredentialRequestOptionsJSON }; challenge_id: string }>(
      "POST",
      "/api/v1/auth/passkeys/login/start",
    ),
  passkeyLoginFinish: (challenge_id: string, response: unknown) =>
    request<{ user: User }>("POST", "/api/v1/auth/passkeys/login/finish", {
      challenge_id,
      response,
    }),
  renamePasskey: (id: string, name: string) =>
    request<void>("PATCH", `/api/v1/auth/passkeys/${encodeURIComponent(id)}`, { name }),
  deletePasskey: (id: string) =>
    request<void>("DELETE", `/api/v1/auth/passkeys/${encodeURIComponent(id)}`),
};

export const admin = {
  users: () => request<{ users: User[] }>("GET", "/api/v1/users"),
  createUser: (body: {
    email: string;
    role: Role;
    display_name?: string;
    password?: string;
    invite: boolean;
  }) =>
    request<{
      user?: User;
      invited?: boolean;
      email?: string;
      link?: string;
      mail_sent?: boolean;
      mail_error?: string;
    }>("POST", "/api/v1/users", body),
  updateUser: (id: string, body: { display_name: string; role: Role; status: UserStatus }) =>
    request<void>("PATCH", `/api/v1/users/${encodeURIComponent(id)}`, body),
  deleteUser: (id: string) => request<void>("DELETE", `/api/v1/users/${encodeURIComponent(id)}`),
  setUserPassword: (id: string, password: string) =>
    request<void>("POST", `/api/v1/users/${encodeURIComponent(id)}/password`, { password }),

  invitations: () => request<{ invitations: InvitationInfo[] }>("GET", "/api/v1/invitations"),
  revokeInvitation: (id: string) =>
    request<void>("DELETE", `/api/v1/invitations/${encodeURIComponent(id)}`),

  audit: (params: Record<string, string>) => {
    const query = new URLSearchParams(params).toString();
    return request<{ events: AuditEntry[]; count: number }>(
      "GET",
      `/api/v1/audit${query ? `?${query}` : ""}`,
    );
  },
  instance: () =>
    request<{
      version: string;
      crypto_version: string;
      uptime_seconds: number;
      driver: string;
      active_secrets: number;
      multi_org: boolean;
      public_listener: boolean;
    }>("GET", "/api/v1/instance"),
};

export const invitationApi = {
  preview: (token: string) =>
    request<{ email: string; role: Role; new_account: boolean }>(
      "POST",
      "/api/v1/invitations/preview",
      { token },
    ),
  accept: (token: string, password: string, display_name: string) =>
    request<{ user: User }>("POST", "/api/v1/invitations/accept", {
      token,
      password,
      display_name,
    }),
};

export const dashboardApi = {
  secrets: (params: Record<string, string> = {}) => {
    const query = new URLSearchParams(params).toString();
    return request<{ secrets: DashboardSecret[]; counts: { live: number; closed: number } }>(
      "GET",
      `/api/v1/dashboard/secrets${query ? `?${query}` : ""}`,
    );
  },
  burn: (id: string) =>
    request<void>("POST", `/api/v1/dashboard/secrets/${encodeURIComponent(id)}/burn`),
};

export const secretMail = {
  send: (
    id: string,
    body: { link: string; to: string; message: string; has_passphrase: boolean },
  ) => request<{ sent: boolean }>("POST", `/api/v1/secrets/${encodeURIComponent(id)}/email`, body),
};
