try {
  Deno.env.get("HOME");
  console.log("op ran");
} catch (e) {
  console.log("REFUSED:", e.name);
}
