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
  /** dark, light, or system: what a visitor who never used the toggle sees. */
  default_theme?: string;
  palette: Record<string, string>;
  /** Uploaded images by kind, already cache-busted. Absent until one exists. */
  assets?: Record<string, string>;
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
  max_files_per_secret: number;
  max_deposits: number;
  upload_window_seconds: number;
  download_window_seconds: number;
  file_chunk_size: number;
  storage: boolean;
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
  /** Handed out by a successful reveal; the only way to fetch the blobs. */
  download_token?: string;
  download_expires_at?: string;
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
  /** Attachments, on the first recipient of a bundle: they belong to it. */
  files?: FileClaim[];
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

  /** Several links sharing one set of attachments. */
  createBundle: (recipients: CreateRequest[], files: FileClaim[] = []) =>
    request<BundleResponse>("POST", "/api/v1/secrets", { recipients, files }),

  uploadFile,
  downloadFile,

  // --- secret requests ------------------------------------------------------
  createSecretRequest: (body: CreateSecretRequest) =>
    request<SecretRequestCreated>("POST", "/api/v1/requests", body),
  requestMeta: (id: string) =>
    request<SecretRequestMeta>("GET", `/api/v1/requests/${encodeURIComponent(id)}`),
  openRequest: (id: string, readToken: string) =>
    request<SecretRequestOpened>("POST", `/api/v1/requests/${encodeURIComponent(id)}/open`, {
      read_token: readToken,
    }),
  deposit: (id: string, body: DepositRequest) =>
    request<{ id: string; created_at: string }>(
      "POST",
      `/api/v1/requests/${encodeURIComponent(id)}/deposit`,
      body,
    ),
  requestReceipt: (id: string, receiptToken: string) =>
    request<SecretRequestReceipt>("POST", `/api/v1/requests/${encodeURIComponent(id)}/receipt`, {
      receipt_token: receiptToken,
    }),
  closeRequest: (id: string, receiptToken: string) =>
    request<void>("DELETE", `/api/v1/requests/${encodeURIComponent(id)}`, {
      receipt_token: receiptToken,
    }),
  listRequests: () =>
    request<{ requests: SecretRequestSummary[] }>("GET", "/api/v1/dashboard/requests"),
};

/** One blob already uploaded, with the token proving we uploaded it. */
export interface FileClaim {
  id: string;
  token: string;
}

export interface BundleResponse {
  bundle_id: string;
  secrets: CreateResponse[];
}

export interface UploadResponse {
  id: string;
  token: string;
  size: number;
  expires_at: string;
}

export interface CreateSecretRequest {
  id: string;
  public_key: string;
  read_token_hash: string;
  receipt_token_hash: string;
  prompt_enc: string;
  kdf: { salt: string; memory_kib: number; iterations: number; parallelism: number };
  label_enc?: string;
  ttl_seconds: number;
  max_deposits: number;
  notify_email?: string;
}

export interface SecretRequestCreated {
  id: string;
  max_deposits: number;
  expires_at: string;
  created_at: string;
  url: string;
}

export interface SecretRequestMeta {
  id: string;
  deposits_remaining: number;
  expires_at: string;
  kdf: { salt: string; memory_kib: number; iterations: number; parallelism: number };
}

export interface SecretRequestOpened {
  id: string;
  prompt_enc: string;
  expires_at: string;
}

export interface DepositRequest {
  read_token: string;
  wrapped_key: string;
  secret: CreateRequest;
  files?: FileClaim[];
}

export interface DepositInfo {
  secret_id: string;
  wrapped_key: string;
  has_passphrase: boolean;
  size_bytes: number;
  created_at: string;
  views_remaining: number;
  kdf: { salt: string; memory_kib: number; iterations: number; parallelism: number };
}

export interface SecretRequestReceipt {
  id: string;
  label_enc: string;
  max_deposits: number;
  deposits_used: number;
  deposits_remaining: number;
  created_at: string;
  expires_at: string;
  deposits: DepositInfo[];
}

export interface SecretRequestSummary {
  id: string;
  label_enc: string;
  max_deposits: number;
  deposits_used: number;
  deposits_remaining: number;
  created_at: string;
  expires_at: string;
}

/**
 * uploadFile sends one already-encrypted blob.
 *
 * XMLHttpRequest rather than fetch, for one reason: fetch still has no upload
 * progress event, and a hundred-megabyte upload with no progress bar looks
 * exactly like a hung page.
 */
function uploadFile(blob: Blob, onProgress?: (sent: number, total: number) => void) {
  return new Promise<UploadResponse>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/files", true);
    xhr.withCredentials = true;
    xhr.responseType = "text";
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    const csrf = csrfToken();
    if (csrf) xhr.setRequestHeader("X-Peek-CSRF", csrf);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress?.(e.loaded, e.total);
    };
    xhr.onerror = () => reject(new ApiError(0, null, "network error"));
    xhr.onabort = () => reject(new ApiError(0, null, "upload cancelled"));
    xhr.onload = () => {
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(xhr.responseText);
      } catch {
        parsed = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(parsed as UploadResponse);
        return;
      }
      reject(new ApiError(xhr.status, parsed as ApiErrorBody | null, xhr.statusText));
    };
    xhr.send(blob);
  });
}

/**
 * downloadFile fetches one blob with a grant from a successful reveal.
 *
 * The grant travels in a header, never in the URL: proxies log URLs, and a
 * download grant in somebody's access log is a readable secret.
 */
async function downloadFile(id: string, grant: string): Promise<Blob> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/files/${encodeURIComponent(id)}`, {
      method: "GET",
      headers: { "X-Peek-Download": grant },
      credentials: "same-origin",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  } catch (cause) {
    throw new ApiError(0, null, cause instanceof Error ? cause.message : "network error");
  }
  if (!response.ok) {
    throw new ApiError(response.status, null, response.statusText);
  }
  return response.blob();
}

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
  /** True only on a multi-organisation instance, for the platform role. */
  can_platform?: boolean;
  multi_org?: boolean;
  /** The slug of the organisation this address serves. */
  org?: string;
  session_expires?: string;
}

export interface OrgDomain {
  domain: string;
  org_id: string;
  verify_token: string;
  verified_at?: string;
  primary: boolean;
  created_at: string;
  last_checked_at?: string;
  last_error?: string;
}

export interface OrgInfo {
  id: string;
  slug: string;
  name: string;
  status: string;
  created_at: string;
  counts: { users: number; secrets: number; domains: number };
  domains?: OrgDomain[];
}

export interface DnsRecord {
  type: string;
  name: string;
  value: string;
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

/** What the sign-in page needs to know before anybody has signed in. */
export interface SSOInfo {
  enabled: boolean;
  /** True when local credentials are refused, not merely hidden. */
  required: boolean;
  label?: string;
  start_url?: string;
}

export const platform = {
  orgs: () => request<{ multi_org: boolean; orgs: OrgInfo[] }>("GET", "/api/v1/orgs"),
  createOrg: (slug: string, name: string) =>
    request<{ org: OrgInfo }>("POST", "/api/v1/orgs", { slug, name }),
  updateOrg: (id: string, body: { name?: string; status?: string }) =>
    request<void>("PATCH", `/api/v1/orgs/${encodeURIComponent(id)}`, body),
  deleteOrg: (id: string) => request<void>("DELETE", `/api/v1/orgs/${encodeURIComponent(id)}`),
  addDomain: (id: string, domain: string) =>
    request<{ domain: OrgDomain; record: DnsRecord }>(
      "POST",
      `/api/v1/orgs/${encodeURIComponent(id)}/domains`,
      { domain },
    ),
  verifyDomain: (id: string, domain: string) =>
    request<{ verified: boolean; error?: string; record?: DnsRecord; domain?: OrgDomain }>(
      "POST",
      `/api/v1/orgs/${encodeURIComponent(id)}/domains/${encodeURIComponent(domain)}/verify`,
    ),
  setPrimaryDomain: (id: string, domain: string) =>
    request<void>(
      "POST",
      `/api/v1/orgs/${encodeURIComponent(id)}/domains/${encodeURIComponent(domain)}/primary`,
    ),
  removeDomain: (id: string, domain: string) =>
    request<void>(
      "DELETE",
      `/api/v1/orgs/${encodeURIComponent(id)}/domains/${encodeURIComponent(domain)}`,
    ),
};

export const auth = {
  me: () => request<Me>("GET", "/api/v1/auth/me"),
  sso: () => request<SSOInfo>("GET", "/api/v1/auth/sso"),
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

  // API tokens. The clear text comes back from createToken and from nowhere
  // else, ever: the server stores only its digest.
  tokens: () => request<{ tokens: ApiTokenInfo[]; scopes: string[] }>("GET", "/api/v1/auth/tokens"),
  createToken: (name: string, scopes: string[], ttl_seconds: number) =>
    request<ApiTokenInfo & { token: string }>("POST", "/api/v1/auth/tokens", {
      name,
      scopes,
      ttl_seconds,
    }),
  revokeToken: (id: string) =>
    request<void>("DELETE", `/api/v1/auth/tokens/${encodeURIComponent(id)}`),
};

export interface ApiTokenInfo {
  id: string;
  name: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  revoked: boolean;
  revoked_at?: string;
}

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

// --- branding administration -------------------------------------------------

export interface ResolvedTheme {
  service_name: string;
  primary_color: string;
  accent_color: string;
  background_color?: string;
  font: string;
  font_stack: string;
  corner_radius: string;
  corner_radius_value: string;
  button_style: string;
  hide_powered_by: boolean;
  support_url: string;
  legal_url: string;
  privacy_url: string;
  contact_email?: string;
  language: string;
  palette: Record<string, string>;
  texts?: Record<string, Record<string, string>>;
  assets?: Record<string, string>;
  has_custom_css: boolean;
  warnings?: string[];
  version: number;
}

export interface BrandingPayload {
  service_name: string;
  primary_color: string;
  accent_color: string;
  background_color: string;
  corner_radius: string;
  font: string;
  button_style: string;
  hide_powered_by: boolean;
  support_url: string;
  legal_url: string;
  privacy_url: string;
  contact_email: string;
  texts: Record<string, Record<string, string>>;
  custom_css: string;
}

export interface BrandingAdminState {
  theme: ResolvedTheme;
  saved: boolean;
  custom_css: string;
  texts: Record<string, Record<string, string>>;
  assets: { kind: string; content_type: string; size_bytes: number; url: string }[];
  options: {
    fonts: { id: string; label: string; stack: string }[];
    radii: { id: string; label: string; value: string }[];
    button_styles: { id: string; label: string }[];
    text_keys: string[];
    languages: string[];
    asset_kinds: string[];
    max_css_bytes: number;
    max_asset_bytes: number;
  };
  mail_configured: boolean;
}

export const brandingAdmin = {
  get: () => request<BrandingAdminState>("GET", "/api/v1/branding/admin"),
  save: (body: BrandingPayload) => request<ResolvedTheme>("PUT", "/api/v1/branding/admin", body),
  reset: () => request<ResolvedTheme>("DELETE", "/api/v1/branding/admin"),
  testEmail: (to: string) =>
    request<{ sent: boolean; to: string }>("POST", "/api/v1/branding/test-email", { to }),

  /**
   * Uploads one image as a raw body rather than a multipart form: there is
   * exactly one file, and a byte stream is a smaller target than a parser.
   */
  uploadAsset: async (kind: string, file: File) => {
    const csrf = csrfToken();
    const response = await fetch(`/api/v1/branding/assets/${encodeURIComponent(kind)}`, {
      method: "PUT",
      headers: {
        "Content-Type": file.type || "application/octet-stream",
        ...(csrf ? { "X-Peek-CSRF": csrf } : {}),
      },
      body: file,
      credentials: "same-origin",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    const text = await response.text();
    const parsed: unknown = text ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new ApiError(response.status, parsed as ApiErrorBody | null, response.statusText);
    }
    return parsed as { kind: string; url: string };
  },

  deleteAsset: (kind: string) =>
    request<void>("DELETE", `/api/v1/branding/assets/${encodeURIComponent(kind)}`),
};
