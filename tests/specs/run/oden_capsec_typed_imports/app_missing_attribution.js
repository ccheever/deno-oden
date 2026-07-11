const target = new URL("./missing-attribution.txt", import.meta.url).href;
const source = `try {
  await import(${JSON.stringify(target)}, { with: { type: "text" } });
  console.log("MISSING-ATTRIBUTION:REACHED");
} catch { console.log("MISSING-ATTRIBUTION:DENIED"); }`;
await import("data:text/javascript," + encodeURIComponent(source));
