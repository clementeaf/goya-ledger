import * as ed25519 from '@noble/ed25519';

// ── Types ───────────────────────────────────────────────────

export interface PartyDefinition {
  role: string;
  did: string;
  signature_level: 'simple' | 'advanced';
}

export interface ContractDefinition {
  type: string;
  parties: PartyDefinition[];
  payload: Record<string, unknown>;
  require_notarization?: boolean;
  deadline_secs?: number;
  webhook_url?: string;
}

export interface TemplateDeployRequest {
  template: string;
  parties: Record<string, string>;
  payload?: Record<string, unknown>;
}

export type DeployRequest = ContractDefinition | TemplateDeployRequest;

export interface BiometricEvidence {
  evidence_type: 'fingerprint' | 'facial_recognition' | 'iris' | 'voice' | 'rut' | 'government_id' | 'other';
  commitment: string;
  captured_at: number;
  capture_device?: string;
}

export interface SignRequest {
  did: string;
  signature: string;
  public_key: string;
  biometric_evidence?: BiometricEvidence[];
}

export interface PartyState {
  role: string;
  did: string;
  signature_level: string;
  signed: boolean;
  envelope: {
    level: string;
    signer: string;
    content_hash: string;
    signature: string;
    public_key: string;
    signature_algorithm: string;
    biometric_evidence: BiometricEvidence[];
    signed_at: number;
  } | null;
}

export interface LexContract {
  id: string;
  definition: ContractDefinition;
  state: 'pending_signatures' | 'fully_signed' | 'notarized' | 'archived' | 'expired';
  parties: PartyState[];
  created_at: number;
  content_hash: string;
  tsa_token: Record<string, unknown> | null;
  block_height: number | null;
}

export interface ContractTemplate {
  name: string;
  contract_type: string;
  roles: { role: string; signature_level: string }[];
  require_notarization: boolean;
  deadline_secs: number | null;
}

interface ApiResponse<T> {
  status: string;
  data: T;
  trace_id: string;
}

// ── Keypair ─────────────────────────────────────────────────

export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  algorithm: 'Ed25519';
  did: string;
}

export async function generateKeypair(): Promise<Keypair> {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  const pkHex = toHex(publicKey);
  return {
    publicKey,
    privateKey,
    algorithm: 'Ed25519',
    did: `did:goya:${pkHex.slice(0, 16)}`,
  };
}

// ── Client ──────────────────────────────────────────────────

export class GoyaClient {
  private baseUrl: string;

  constructor(nodeUrl: string) {
    this.baseUrl = nodeUrl.replace(/\/$/, '') + '/api/v1';
  }

  // ── Identity ────────────────────────────────────────────

  async registerIdentity(keypair: Keypair): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await this.post('/store/identities', {
      did: keypair.did,
      public_key: toHex(keypair.publicKey),
      created_at: now,
      updated_at: now,
      status: 'active',
    });
  }

  // ── LexChain ────────────────────────────────────────────

  async deploy(request: DeployRequest): Promise<LexContract> {
    const resp = await this.post<ApiResponse<LexContract>>('/lexchain/deploy', request);
    return resp.data;
  }

  async sign(contractId: string, request: SignRequest): Promise<LexContract> {
    const resp = await this.post<ApiResponse<LexContract>>(
      `/lexchain/${contractId}/sign`,
      request,
    );
    return resp.data;
  }

  async signWithKeypair(
    contractId: string,
    keypair: Keypair,
    contentHash: string,
    biometrics?: BiometricEvidence[],
  ): Promise<LexContract> {
    const level = biometrics?.length ? 'fea' : 'fes';
    let payload: string;

    if (level === 'fes') {
      payload = `fes:${keypair.did}:${contentHash}`;
    } else {
      const bioHash = await sha256Hex(
        biometrics!.map((b) => b.commitment).sort().join(':'),
      );
      payload = `fea:${keypair.did}:${contentHash}:${bioHash}`;
    }

    const signature = await ed25519.signAsync(
      new TextEncoder().encode(payload),
      keypair.privateKey,
    );

    return this.sign(contractId, {
      did: keypair.did,
      signature: toHex(signature),
      public_key: toHex(keypair.publicKey),
      biometric_evidence: biometrics,
    });
  }

  async getContract(contractId: string): Promise<LexContract> {
    const resp = await this.get<ApiResponse<LexContract>>(`/lexchain/${contractId}`);
    return resp.data;
  }

  async listContracts(): Promise<LexContract[]> {
    const resp = await this.get<ApiResponse<LexContract[]>>('/lexchain');
    return resp.data;
  }

  async listTemplates(): Promise<ContractTemplate[]> {
    const resp = await this.get<ApiResponse<ContractTemplate[]>>('/lexchain/templates');
    return resp.data;
  }

  // ── HTTP ────────────────────────────────────────────────

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${path}: ${text}`);
    }
    return res.json() as Promise<T>;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`);
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`${res.status} ${path}: ${text}`);
    }
    return res.json() as Promise<T>;
  }
}

// ── Helpers ─────────────────────────────────────────────────

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return toHex(new Uint8Array(hash));
}
