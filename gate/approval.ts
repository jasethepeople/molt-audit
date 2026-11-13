export interface ApprovalCheck {
  token?: string;
  callerId?: string;
  target: string;
  event?: unknown;
}

export interface ApprovalGrant {
  executionId: string;
  tokenId: string;
  callerId: string;
  target: string;
  payloadHash: string;
  approvalEventId: string;
  approvalEventHash: string;
}

export interface ApprovalOutcome {
  ok: boolean;
  durationMs: number;
  attempts: number;
  result?: unknown;
  error?: string;
}

export interface ApprovalAuthority {
  consume(check: ApprovalCheck): Promise<ApprovalGrant | undefined>;
  recordExecution(grant: ApprovalGrant, outcome: ApprovalOutcome): Promise<void>;
}

export class FailClosedApprovalAuthority implements ApprovalAuthority {
  async consume(_check: ApprovalCheck): Promise<undefined> {
    return undefined;
  }

  async recordExecution(_grant: ApprovalGrant, _outcome: ApprovalOutcome): Promise<void> {}
}
