import { describe, expect, it } from "vitest";
import { beginUnlock, enrollUser, generateCollectionKey, rotateMasterPassword } from "./keys.js";
import { openSealed, sealToUser } from "./seal.js";
import { decryptItem, encryptItem, type LoginItem } from "./item.js";
import { createRecoveryBlob, generateRecoveryCode, recoverUserKey } from "./recovery.js";
import { DecryptionError } from "./errors.js";
import { DEFAULT_KDF_PARAMS, type KdfParams } from "./kdf.js";
import { toBase64 } from "./encoding.js";

const netflix: LoginItem = {
  type: "login",
  name: "Netflix",
  username: "household@example.com",
  password: "s3cret-household-pw",
  urls: ["https://netflix.com"],
  notes: "",
  favorite: false,
  folderId: null,
  passwordHistory: [],
};

describe("end-to-end lifecycle", () => {
  it("shares a collection item from one user to another", async () => {
    const alice = await enrollUser("alice-master-password");
    const bob = await enrollUser("bob-master-password");

    // Alice creates the Household collection and puts Netflix in it.
    const collectionKey = generateCollectionKey();
    const encryptedItem = await encryptItem(netflix, collectionKey);
    const aliceSealed = await sealToUser(collectionKey, alice.publicKey);

    // Alice, unlocked, fulfils the pending grant for Bob.
    const aliceCollectionKey = await openSealed(aliceSealed, alice.keyPair.privateKey);
    const bobSealed = await sealToUser(aliceCollectionKey, bob.publicKey);

    // Bob logs in on a fresh device: derive once, send the auth hash, then
    // unwrap the blobs the login response carried back.
    const bobSession = await beginUnlock("bob-master-password", bob.kdfSalt);
    expect(toBase64(bobSession.authHash)).toBe(toBase64(bob.authHash));
    const bobUnlocked = await bobSession.finish(bob.protectedUserKey, bob.encryptedPrivateKey);
    bobSession.destroy();
    const bobCollectionKey = await openSealed(bobSealed, bobUnlocked.privateKey);
    expect(await decryptItem(encryptedItem, bobCollectionKey)).toEqual(netflix);
  });

  it("keeps a non-member out of the collection", async () => {
    const alice = await enrollUser("alice-master-password");
    const carol = await enrollUser("carol-master-password");
    const collectionKey = generateCollectionKey();
    const aliceSealed = await sealToUser(collectionKey, alice.publicKey);

    await expect(openSealed(aliceSealed, carol.keyPair.privateKey)).rejects.toThrow(
      DecryptionError,
    );
  });

  it("survives a master password change without re-encrypting items", async () => {
    const user = await enrollUser("original-password");
    const item = await encryptItem(netflix, user.userKey);

    const rotated = await rotateMasterPassword("brand-new-password", user.userKey);

    // Unlocking with the new password must reach the same userKey, and the item
    // ciphertext must be byte-identical — nothing was re-encrypted.
    const session = await beginUnlock("brand-new-password", rotated.kdfSalt);
    const unlocked = await session.finish(rotated.protectedUserKey, user.encryptedPrivateKey);
    session.destroy();
    expect(toBase64(unlocked.userKey)).toBe(toBase64(user.userKey));
    expect(await decryptItem(item, unlocked.userKey)).toEqual(netflix);
  });

  it("recovers a vault from the recovery code after the master password is lost", async () => {
    const user = await enrollUser("forgotten-password");
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(user.userKey, code, user.params);
    const item = await encryptItem(netflix, user.userKey);

    const recoveredUserKey = await recoverUserKey(
      blob.recoveryProtectedUserKey,
      code,
      blob.recoverySalt,
      blob.params,
    );
    expect(toBase64(recoveredUserKey)).toBe(toBase64(user.userKey));
    expect(await decryptItem(item, recoveredUserKey)).toEqual(netflix);
  });

  // The spec says KDF params are stored per user "so they can be raised later
  // without a flag day". This is the only executable evidence for that
  // capability, and it covers recovery specifically: a recovery blob wrapped
  // under one set of params and opened under another yields a different key,
  // which is how a correct recovery code fails at the worst possible moment.
  it("enrolls, unlocks and recovers under raised KDF params", async () => {
    const raised: Readonly<KdfParams> = Object.freeze({
      algorithm: "argon2id",
      memoryKiB: 131072,
      iterations: 4,
      parallelism: 4,
    });

    const user = await enrollUser("raised-params-password", raised);
    expect(user.params).toEqual(raised);

    const item = await encryptItem(netflix, user.userKey);

    const session = await beginUnlock("raised-params-password", user.kdfSalt, user.params);
    expect(toBase64(session.authHash)).toBe(toBase64(user.authHash));
    const unlocked = await session.finish(user.protectedUserKey, user.encryptedPrivateKey);
    session.destroy();
    expect(toBase64(unlocked.userKey)).toBe(toBase64(user.userKey));

    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(user.userKey, code, user.params);
    expect(blob.params).toEqual(raised);

    const recovered = await recoverUserKey(
      blob.recoveryProtectedUserKey,
      code,
      blob.recoverySalt,
      blob.params,
    );
    expect(toBase64(recovered)).toBe(toBase64(user.userKey));
    expect(await decryptItem(item, recovered)).toEqual(netflix);
  });

  // The failure Fix 2 exists to prevent, made concrete: the blob was wrapped
  // under raised params, and the defaults are supplied at recovery time.
  it("fails recovery when the blob's params are not the ones supplied", async () => {
    const raised: Readonly<KdfParams> = Object.freeze({
      algorithm: "argon2id",
      memoryKiB: 131072,
      iterations: 4,
      parallelism: 4,
    });
    const user = await enrollUser("params-mismatch-password", raised);
    const code = generateRecoveryCode();
    const blob = await createRecoveryBlob(user.userKey, code, raised);

    await expect(
      recoverUserKey(blob.recoveryProtectedUserKey, code, blob.recoverySalt, DEFAULT_KDF_PARAMS),
    ).rejects.toThrow(DecryptionError);
  });
});
