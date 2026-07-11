try {
  Deno.removeSync("./node_modules/typed-denied/link.txt");
} catch {}
Deno.symlinkSync("../../outside.txt", "./node_modules/typed-denied/link.txt");
const { symlinkEscape } = await import(
  "./node_modules/typed-denied/symlink.js"
);
console.log(await symlinkEscape());
