try {
  Deno.env.get("SECRET_KEY");
  console.log("READ ok");
} catch (e) {
  console.log("DENIED:", e.name);
}
