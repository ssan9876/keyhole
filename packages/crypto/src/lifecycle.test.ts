import { describe, expect, it } from "vitest";
import { beginUnlock, enrollUser, generateCollectionKey, rotateMasterPassword } from "./keys.js";
import { openSealed, sealToUser } from "./seal.js";
import { decryptItem, encryptItem, type LoginItem } from "./item.js";
import { createRecoveryBlob, generateRecoveryCode, recoverUserKey } from "./recovery.js";
import { DecryptionError } from "./errors.js";
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
});
