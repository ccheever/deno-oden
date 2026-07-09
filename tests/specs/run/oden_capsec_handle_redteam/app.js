// Oden capsec authority-flow red-team (ENG-23784): an ungranted, malicious
// package tries to obtain authority it was not delegated. Every attempt fails
// closed. A grantor legitimately mints a narrow handle; evil is handed it for
// one purpose and abuses it every other way.
import * as grantor from "./node_modules/grantor-dep/index.js";
import * as evil from "./node_modules/evil-dep/index.js";

const h = grantor.makeShareHandle();

// 1) Cross-package theft: evil, holding no handle and no grant, reads directly.
try {
  evil.stealDirect("./shared/pub/ok.txt");
  console.log("theft: LEAKED");
} catch {
  console.log("theft: DENIED");
}

// 2) Forged handle: a fabricated handle-shaped object confers nothing (no
//    host-side id, so no possession window opens).
try {
  evil.forgeHandle("./shared/pub/ok.txt");
  console.log("forged-handle: LEAKED");
} catch {
  console.log("forged-handle: DENIED");
}

// 3) Mint-not-held: evil cannot mint the grantor's authority (frame-checked
//    against evil's own holdings).
try {
  evil.mintNotHeld();
  console.log("evil-mint: MINTED");
} catch {
  console.log("evil-mint-not-held: DENIED");
}

// 4) No id leaks off a legitimately-held handle.
console.log("carrier-keys:", evil.inspect(h));

// 5) Serialization posture: a handle cannot be structuredClone'd.
try {
  evil.tryClone(h);
  console.log("clone: CLONED");
} catch (e) {
  console.log("structuredClone-handle:", e.name);
}

// 6) Re-widening a held handle via scoped() is denied.
try {
  evil.tryWiden(h);
  console.log("rewiden-via-scoped: WIDENED");
} catch {
  console.log("rewiden-via-scoped: DENIED");
}
