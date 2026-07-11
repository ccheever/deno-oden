import inspector from "node:inspector";
import { createRequire } from "node:module";
import { Readable, Writable } from "node:stream";

const port = Number(Deno.args[0]);
if (!inspector.url()) throw new Error("startup inspector URL missing");
const httpUrl = `http://127.0.0.1:${port}/json/list`;
const require = createRequire(import.meta.url);
const deniedProbe = require("writable-callback-denied");
const streams = new Set();

function nextTurn() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function actorOutcome() {
  try {
    return Deno.env.get("ODEN_WRITABLE_CALLBACK_SENTINEL") === "root-visible"
      ? "ALLOWED"
      : "BROKEN";
  } catch (error) {
    return error instanceof Deno.errors.NotCapable ||
        error instanceof Deno.errors.PermissionDenied
      ? "DENIED"
      : "BROKEN";
  }
}

function errorOutcome(error) {
  if (error == null) return "OK";
  if (error.code === "ERR_STREAM_DESTROYED") return "DESTROYED";
  if (error.code === "ERR_STREAM_WRITE_AFTER_END") return "WRITE_AFTER_END";
  if (error.code === "ERR_STREAM_ALREADY_FINISHED") return "ALREADY_FINISHED";
  if (error.message === "boom") return "BOOM";
  return error.code ?? error.name ?? "ERROR";
}

function receiverOutcome(receiver) {
  if (receiver === undefined) return "UNDEFINED";
  if (Array.isArray(receiver)) return `ARRAY:${receiver.length}`;
  if (receiver?.chunk !== undefined) {
    return `ENTRY:${Buffer.from(receiver.chunk).toString()}`;
  }
  return "OTHER";
}

function rootCallback(results, label) {
  return function rootWritableCompletion(error) {
    results.push(
      `${label}:${actorOutcome()}:${errorOutcome(error)}:${
        receiverOutcome(this)
      }`,
    );
  };
}

function streamDenialOutcome(error) {
  return error instanceof Deno.errors.NotCapable ||
      error instanceof Deno.errors.PermissionDenied ||
      error instanceof Error && error.code === "EACCES" &&
        error.errno === -13 &&
        error.syscall === "node:net.Socket protected stream use"
    ? "DENIED"
    : "BROKEN";
}

function makeControlledWritable(
  { final = false, sync = false, writev = false } = {},
) {
  const pending = [];
  const writes = [];
  let finalCallback;
  const options = {
    autoDestroy: false,
    write(chunk, _encoding, callback) {
      writes.push(`write:${Buffer.from(chunk).toString()}`);
      if (sync) callback();
      else pending.push(callback);
    },
  };
  if (writev) {
    options.writev = (chunks, callback) => {
      writes.push(
        `writev:${
          chunks.map(({ chunk }) => Buffer.from(chunk).toString()).join("+")
        }`,
      );
      if (sync) callback();
      else pending.push(callback);
    };
  }
  if (final) {
    options.final = (callback) => {
      finalCallback = callback;
    };
  }
  const writable = new Writable(options);
  writable.on("error", () => {});
  streams.add(writable);
  return {
    complete(error) {
      const callback = pending.shift();
      if (callback === undefined) throw new Error("missing pending write");
      callback(error);
    },
    completeFinal(error) {
      if (finalCallback === undefined) throw new Error("missing pending final");
      const callback = finalCallback;
      finalCallback = undefined;
      callback(error);
    },
    pending: () => pending.length,
    writable,
    writes,
  };
}

async function prepareProtection() {
  const response = await fetch(httpUrl);
  const source = Readable.fromWeb(response.body);
  streams.add(source);
  source.pause();
  return (writable) => {
    source.pipe(writable, { end: false });
    source.unpipe(writable);
    source.pause();
    // The guard is now attached to the destination. Do not leave an inspector
    // response's internal read-ahead continuation live across unrelated
    // callback-provenance cases.
    source.destroy();
  };
}

const result = {};
let completed = false;

try {
  {
    const control = makeControlledWritable();
    const attach = await prepareProtection();
    attach(control.writable);
    const values = [];
    const probe = deniedProbe.makeProbe(values, "direct");
    control.writable.write(Buffer.from("direct"), probe.callback);
    control.complete();
    result.direct = { calls: probe.calls(), values };
  }

  {
    const control = makeControlledWritable();
    const attach = await prepareProtection();
    attach(control.writable);
    const values = [];
    const probe = deniedProbe.makeProbe(values, "buffered");
    control.writable.write(Buffer.from("head"));
    control.writable.write(Buffer.from("buffered"), probe.callback);
    control.complete();
    control.complete();
    result.buffered = { calls: probe.calls(), values, writes: control.writes };
  }

  {
    const control = makeControlledWritable();
    const attach = await prepareProtection();
    attach(control.writable);
    control.writable.cork();
    const values = [];
    const first = deniedProbe.makeProbe(values, "corked-a");
    const second = deniedProbe.makeProbe(values, "corked-b");
    control.writable.write(Buffer.from("a"), first.callback);
    control.writable.write(Buffer.from("b"), second.callback);
    control.writable.uncork();
    control.complete();
    control.complete();
    result.corked = {
      calls: [first.calls(), second.calls()],
      values,
      writes: control.writes,
    };
  }

  {
    const control = makeControlledWritable({ writev: true });
    const attach = await prepareProtection();
    attach(control.writable);
    control.writable.cork();
    const rootValues = [];
    const packageValues = [];
    let rootCalls = 0;
    const root = function rootWritevCompletion(error) {
      rootCalls++;
      rootValues.push(
        `root:${actorOutcome()}:${errorOutcome(error)}:${
          receiverOutcome(this)
        }`,
      );
    };
    const packageProbe = deniedProbe.makeProbe(packageValues, "package");
    control.writable.write(Buffer.from("root"), root);
    control.writable.write(Buffer.from("package"), packageProbe.callback);
    control.writable.uncork();
    let completion = "ALLOWED";
    try {
      control.complete();
    } catch (error) {
      completion = streamDenialOutcome(error);
    }
    result.writevCompleteSet = {
      completion,
      packageCalls: packageProbe.calls(),
      packageValues,
      rootCalls,
      rootValues,
      writes: control.writes,
    };
  }

  {
    const control = makeControlledWritable({ writev: true });
    const attach = await prepareProtection();
    attach(control.writable);
    control.writable.cork();
    const values = [];
    control.writable.write(
      Buffer.from("one"),
      rootCallback(values, "root-a"),
    );
    control.writable.write(
      Buffer.from("two"),
      rootCallback(values, "root-b"),
    );
    control.writable.uncork();
    control.complete();
    result.writevRootReceiver = { values, writes: control.writes };
  }

  {
    const control = makeControlledWritable();
    const attach = await prepareProtection();
    attach(control.writable);
    const values = [];
    const probe = deniedProbe.makeProbe(values, "error");
    control.writable.write(Buffer.from("error"), probe.callback);
    control.complete(new Error("boom"));
    result.error = { calls: probe.calls(), values };
  }

  {
    const control = makeControlledWritable();
    const attach = await prepareProtection();
    attach(control.writable);
    control.writable.cork();
    const values = [];
    const probe = deniedProbe.makeProbe(values, "destroy");
    control.writable.write(Buffer.from("destroy"), probe.callback);
    control.writable.destroy();
    await nextTurn();
    result.destroy = { calls: probe.calls(), values };
  }

  {
    const control = makeControlledWritable({ sync: true });
    const attach = await prepareProtection();
    const values = [];
    const probe = deniedProbe.makeProbe(values, "pre-protection-tick");
    control.writable.write(Buffer.from("tick"), probe.callback);
    attach(control.writable);
    await nextTurn();
    result.preProtectionTick = { calls: probe.calls(), values };
  }

  {
    const control = makeControlledWritable();
    const attach = await prepareProtection();
    const values = [];
    const probe = deniedProbe.makeProbe(values, "pre-protection-async");
    deniedProbe.registerWrite(
      control.writable,
      Buffer.from("async"),
      probe.callback,
    );
    attach(control.writable);
    control.complete();
    result.preProtectionAsync = { calls: probe.calls(), values };
  }

  {
    const control = makeControlledWritable({ sync: true });
    const attach = await prepareProtection();
    const values = [];
    const probe = deniedProbe.makeProbe(values, "same");
    control.writable.write(Buffer.from("first"), probe.callback);
    attach(control.writable);
    control.writable.write(Buffer.from("second"), probe.callback);
    await nextTurn();
    result.sameFunctionCoalescing = { calls: probe.calls(), values };
  }

  {
    const control = makeControlledWritable({ writev: true });
    const attach = await prepareProtection();
    const values = [];
    let calls = 0;
    const callback = function sameRootWritevCallback(error) {
      calls++;
      values.push(
        `same-writev:${actorOutcome()}:${errorOutcome(error)}:${
          receiverOutcome(this)
        }`,
      );
    };
    control.writable.cork();
    deniedProbe.registerWrite(
      control.writable,
      Buffer.from("package-registration"),
      callback,
    );
    control.writable.write(Buffer.from("root-registration"), callback);
    control.writable.uncork();
    attach(control.writable);
    let completion = "ALLOWED";
    try {
      control.complete();
    } catch (error) {
      completion = streamDenialOutcome(error);
    }
    result.sameFunctionWritevCompleteSet = { calls, completion, values };
  }

  {
    const control = makeControlledWritable({ final: true });
    const attach = await prepareProtection();
    attach(control.writable);
    const values = [];
    const probe = deniedProbe.makeProbe(values, "end");
    control.writable.end(probe.callback);
    control.completeFinal();
    await nextTurn();
    result.end = { calls: probe.calls(), values };
  }

  {
    const control = makeControlledWritable({ final: true });
    const attach = await prepareProtection();
    attach(control.writable);
    const values = [];
    const probe = deniedProbe.makeProbe(values, "end-error");
    control.writable.end(probe.callback);
    control.completeFinal(new Error("boom"));
    await nextTurn();
    result.endError = { calls: probe.calls(), values };
  }

  {
    const empty = makeControlledWritable();
    const attachEmpty = await prepareProtection();
    attachEmpty(empty.writable);
    const emptyValues = [];
    const emptyProbe = deniedProbe.makeProbe(emptyValues, "cleanup-end");
    let emptyAdmission = "ALLOWED";
    try {
      deniedProbe.registerEnd(empty.writable, emptyProbe.callback);
    } catch (error) {
      emptyAdmission = streamDenialOutcome(error);
    }
    await nextTurn();

    const queued = makeControlledWritable();
    const attachQueued = await prepareProtection();
    attachQueued(queued.writable);
    queued.writable.cork();
    queued.writable.write(Buffer.from("queued"));
    const queuedProbe = deniedProbe.makeProbe([], "queued-end");
    let queuedAdmission = "ALLOWED";
    try {
      deniedProbe.registerEnd(queued.writable, queuedProbe.callback);
    } catch (error) {
      queuedAdmission = streamDenialOutcome(error);
    }

    const unsafeFinal = makeControlledWritable({ final: true });
    const attachUnsafeFinal = await prepareProtection();
    attachUnsafeFinal(unsafeFinal.writable);
    const finalProbe = deniedProbe.makeProbe([], "unsafe-final-end");
    let finalAdmission = "ALLOWED";
    try {
      deniedProbe.registerEnd(unsafeFinal.writable, finalProbe.callback);
    } catch (error) {
      finalAdmission = streamDenialOutcome(error);
    }
    result.cleanupEndAdmission = {
      emptyAdmission,
      emptyCalls: emptyProbe.calls(),
      emptyValues,
      finalAdmission,
      finalCalls: finalProbe.calls(),
      queuedAdmission,
      queuedCalls: queuedProbe.calls(),
    };
  }

  {
    const control = makeControlledWritable({ final: true });
    const attach = await prepareProtection();
    const values = [];
    const probe = deniedProbe.makeProbe(values, "same-end");
    deniedProbe.registerEnd(control.writable, probe.callback);
    control.writable.end(probe.callback);
    attach(control.writable);
    control.completeFinal();
    await nextTurn();
    result.sameFunctionEnd = { calls: probe.calls(), values };
  }

  {
    const control = makeControlledWritable();
    const attach = await prepareProtection();
    attach(control.writable);
    const finished = new Promise((resolve) =>
      control.writable.once("finish", resolve)
    );
    control.writable.end();
    await finished;
    const endValues = [];
    const endProbe = deniedProbe.makeProbe(endValues, "end-immediate");
    control.writable.end(endProbe.callback);
    const writeValues = [];
    const writeProbe = deniedProbe.makeProbe(writeValues, "write-immediate");
    control.writable.write(Buffer.from("late"), writeProbe.callback);
    await nextTurn();
    result.immediate = {
      endCalls: endProbe.calls(),
      endValues,
      writeCalls: writeProbe.calls(),
      writeValues,
    };
  }

  {
    const control = makeControlledWritable({ sync: true });
    const values = [];
    const callback = rootCallback(values, "ordinary-same");
    control.writable.write(Buffer.from("one"), callback);
    control.writable.write(Buffer.from("two"), callback);
    await nextTurn();
    result.ordinarySameFunction = values;
  }

  {
    const control = makeControlledWritable({ writev: true });
    const values = [];
    control.writable.cork();
    control.writable.write(
      Buffer.from("ordinary-one"),
      rootCallback(values, "ordinary-a"),
    );
    control.writable.write(
      Buffer.from("ordinary-two"),
      rootCallback(values, "ordinary-b"),
    );
    control.writable.uncork();
    control.complete();
    result.ordinaryWritevReceiver = values;
  }

  {
    const control = makeControlledWritable({ final: true });
    const values = [];
    control.writable.end(rootCallback(values, "ordinary-end-a"));
    control.writable.end(rootCallback(values, "ordinary-end-b"));
    control.completeFinal();
    await nextTurn();
    result.ordinaryEndReceiver = values;
  }

  {
    const control = makeControlledWritable({ sync: true });
    const values = [];
    const target = rootCallback(values, "ordinary-proxy");
    const callback = new Proxy(target, {
      apply(inner, receiver, args) {
        return Reflect.apply(inner, receiver, args);
      },
    });
    control.writable.write(Buffer.from("proxy"), callback);
    await nextTurn();
    result.ordinaryCallableProxy = values;
  }

  console.log(JSON.stringify(result));
  completed = true;
} finally {
  for (const stream of streams) {
    try {
      stream.destroy();
    } catch {
      // Cleanup must not replace the fixture result.
    }
  }
  try {
    inspector.close();
  } catch {
    // Best effort after the isolated endpoint fixture.
  }
  if (completed) Deno.exit(0);
}
