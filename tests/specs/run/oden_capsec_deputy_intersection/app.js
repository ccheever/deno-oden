import { launder } from "./node_modules/evil-dep/index.js";
import { readEnv } from "./node_modules/deputy-dep/index.js";

// 1) evil-dep launders through the deputy: the granted deputy reads SECRET on
//    evil-dep's behalf. Nearest-frame attribution (row 1) sees only the granted
//    deputy and ALLOWS; stack-intersection (row 3) sees evil-dep deeper on the
//    stack -- the set is [deputy-dep, evil-dep], evil-dep is ungranted -> DENY.
try {
  console.log("evil-via-deputy:", launder("SECRET"));
} catch (e) {
  console.log("evil-via-deputy:", e.name);
}

// 2) root calls the same granted deputy directly. Only ambient root is on the
//    stack beneath the deputy, and ambient principals impose no constraint, so
//    the intersection collapses to [deputy-dep] -> ALLOW. No false denial.
console.log("root-via-deputy:", readEnv("SECRET"));
