import inspector from "node:inspector";
import { Buffer } from "node:buffer";
import { createRequire } from "node:module";
import { Readable, Writable } from "node:stream";

const port = Number(Deno.args[0]);
if (!inspector.url()) throw new Error("startup inspector URL missing");
const require = createRequire(import.meta.url);
const deniedProbe = require("scalar-state-denied");
const httpUrl = `http://127.0.0.1:${port}/json/list`;
const streams = new Set();

async function protectedReadable() {
  const response = await fetch(httpUrl);
  const readable = Readable.fromWeb(response.body);
  streams.add(readable);
  return readable;
}

const result = {};
try {
  const readable = await protectedReadable();
  const readablePoison = deniedProbe.poisonReadableScalars(readable);
  try {
    void readable.readable;
    void readable.readableHighWaterMark;
    Readable.toWeb(readable);
    result.readableAdapterScalars = readablePoison.outcome();
    readable.read(0);
    result.readableEngineScalars = readablePoison.outcome();
  } finally {
    readablePoison.restore();
  }

  const source = await protectedReadable();
  source.pause();
  // Prevent pipe's compatibility resume tick from starting an unrelated
  // actorless network read; this fixture only needs the synchronous guard
  // propagation onto the Writable.
  source._readableState.reading = true;
  const writable = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  writable.on("error", () => {});
  streams.add(writable);
  source.pipe(writable);
  source.unpipe(writable);
  source.pause();

  const writablePoison = deniedProbe.poisonWritableScalars(writable);
  try {
    void writable.writable;
    void writable.writableHighWaterMark;
    Writable.toWeb(writable);
    result.writableAdapterScalars = writablePoison.outcome();
    writable.write(Buffer.from("root-owned bytes"));
    result.writableEngineScalars = writablePoison.outcome();
  } finally {
    writablePoison.restore();
  }

  console.log(JSON.stringify(result));
} finally {
  for (const stream of streams) {
    try {
      stream.destroy();
    } catch {
      // Best-effort cleanup cannot replace the fixture outcome.
    }
  }
  try {
    inspector.close();
  } catch {
    // The endpoint may already be closed during error cleanup.
  }
}
