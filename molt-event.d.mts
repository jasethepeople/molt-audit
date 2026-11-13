import type { KeyObject } from 'node:crypto';

export type MoltEvent = {
  seq: number;
  ts: number;
  type: string;
  actor: string;
  payload: unknown;
  prev_hash: string;
  pub: string;
  sig: string;
  hash: string;
};

export function buildEvent(input: {
  seq: number;
  ts: number;
  type: string;
  actor: string;
  payload: unknown;
  prevHash: string;
  publicHex: string;
  privateKey: KeyObject;
}): MoltEvent;
