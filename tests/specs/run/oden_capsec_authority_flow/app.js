// Oden capsec authority-flow (ENG-23784): a package attenuates a capability it
// holds into an unforgeable handle and hands the narrower one across a package
// boundary. Enforcement is bounded by the attenuated scope; over-broad
// re-widening and mints are denied; revocation cascades through derived
// handles. Root (this entry) is ambient, so every check below is exercised
// through the grantor/recipient *package* frames, not root.
import * as grantor from "./node_modules/grantor-dep/index.js";
import * as recipient from "./node_modules/recipient-dep/index.js";

// 1) Happy path: grantor mints a narrow handle and hands it to recipient, who
//    reads within the attenuated scope. recipient has no fs grant of its own.
const h = grantor.makeShareHandle();
console.log(
  "pub-via-handle:",
  recipient.readWith(h, "./shared/pub/ok.txt").trim(),
);

// 2) Attenuation is enforced: the same handle does NOT reach ./shared/secret,
//    even though the grantor itself holds fs:read on all of ./shared.
try {
  recipient.readWith(h, "./shared/secret.txt");
  console.log("secret-via-handle: LEAKED");
} catch {
  console.log("secret-via-handle: DENIED");
}

// 3) No handle, no authority: recipient reading without a window denies.
try {
  recipient.readWithout("./shared/pub/ok.txt");
  console.log("no-handle: LEAKED");
} catch {
  console.log("no-handle: DENIED");
}

// 4) Possession is scoped to an active use() window: merely holding the carrier
//    confers nothing.
try {
  recipient.readHolding(h, "./shared/pub/ok.txt");
  console.log("holding-not-using: LEAKED");
} catch {
  console.log("holding-not-using: DENIED");
}

// 5) A mint cannot exceed what the minter holds.
try {
  grantor.tryMintTooWide();
  console.log("mint-too-wide: MINTED");
} catch {
  console.log("mint-exceeds-holding: DENIED");
}

// 6) scoped() only narrows: re-widening is denied.
try {
  recipient.tryWiden(h);
  console.log("rewiden: WIDENED");
} catch {
  console.log("rewiden: DENIED");
}

// 7) Genuine narrowing works, and the derived child is usable within its scope.
const child = recipient.scopeDeeper(h);
console.log(
  "deep-via-child:",
  recipient.readWith(child, "./shared/pub/sub/deep.txt").trim(),
);

// 8) Revocation cascades: revoking the parent revokes the derived child, so a
//    use-after-revoke through the child denies.
grantor.revoke(h);
try {
  recipient.readWith(child, "./shared/pub/sub/deep.txt");
  console.log("use-after-revoke-cascade: LEAKED");
} catch {
  console.log("use-after-revoke-cascade: DENIED");
}
