import { forgeRootLookingRequest } from "./node_modules/forger-dep/index.js";
import { attackViaDeputy } from "./node_modules/evil-dep/index.js";
import { directRead } from "./node_modules/deputy-dep/index.js";
import { mapAndFlood } from "./node_modules/mapper-dep/index.js";
import { requestConflict } from "./node_modules/conflicted-dep/index.js";
import { attemptOverlayTamper } from "./node_modules/tamper-dep/index.js";

console.log(`frame-forged: ${forgeRootLookingRequest()}`);
const deputy = attackViaDeputy();
console.log(`deputy-request: ${deputy.request}`);
console.log(`deputy-launder: ${deputy.read}`);
console.log(`deputy-direct: ${directRead()}`);
const mapping = mapAndFlood();
console.log(`mapping: ${mapping.inside}/${mapping.outside}`);
console.log(`fatigue: ${mapping.first}/${mapping.second}`);
console.log(`conflict: ${requestConflict()}`);
const tamper = attemptOverlayTamper();
console.log(`overlay-legit: ${tamper.legit}`);
console.log(`overlay-forged-status: ${tamper.forgedStatus}`);
console.log(`overlay-tamper-read: ${tamper.read}`);

const rows = Deno.readTextFileSync("redteam-audit.ndjson").trim().split("\n")
  .map((line) => JSON.parse(line));
const requests = rows.filter((row) => row.event === "dynamic_request");
console.log(`codes: ${requests.map((row) => row.code).join(",")}`);
const fatigue = requests.filter((row) => row.code === "OD-CAP-REQ-UNANSWERED");
console.log(
  `fatigue-memoized: ${fatigue.map((row) => row.memoized).join(",")}`,
);
const mappingQueries = rows.filter((row) =>
  row.event === "dynamic_permission" && row.operation === "query" &&
  row.principal === "mapper-dep"
);
console.log(`mapping-audit: ${mappingQueries.length}`);
