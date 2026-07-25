export class KeyholeCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Raised when authenticated decryption fails. Deliberately carries no detail:
 *  a GCM tag mismatch cannot distinguish a wrong key from a corrupted blob,
 *  and pretending otherwise would mislead callers. */
export class DecryptionError extends KeyholeCryptoError {
  constructor() {
    super("Decryption failed: wrong key or corrupted data");
  }
}

export class MalformedEnvelopeError extends KeyholeCryptoError {}

export class InvalidRecoveryCodeError extends KeyholeCryptoError {}
