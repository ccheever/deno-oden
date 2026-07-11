process.once("uncaughtException", (error, origin) => {
  console.log(`trusted exception delivered: ${origin} ${error.message}`);
  process.exitCode = 0;
});

require("exception-probe");
