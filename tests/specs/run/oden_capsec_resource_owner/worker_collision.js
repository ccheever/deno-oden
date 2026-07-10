class Inbox {
  #queue = [];
  #waiters = [];

  constructor(worker) {
    worker.onmessage = (event) => {
      const waiter = this.#waiters.shift();
      if (waiter) waiter(event.data);
      else this.#queue.push(event.data);
    };
  }

  next() {
    if (this.#queue.length) return Promise.resolve(this.#queue.shift());
    return new Promise((resolve) => this.#waiters.push(resolve));
  }
}

const workerA = new Worker(new URL("./worker_a.js", import.meta.url).href, {
  type: "module",
});
const inboxA = new Inbox(workerA);
let workerB;
const eventPath = "./watchdir/worker-collision.tmp";

try {
  const readyA = await inboxA.next();
  if (readyA !== "worker-a:ready") {
    throw new Error(`unexpected worker-a ready message: ${readyA}`);
  }

  // Open sequentially so this fixture isolates resource-table identity from
  // simultaneous worker bootstrap attribution. Both workers still allocate
  // the same first watcher rid in independent tables.
  workerB = new Worker(new URL("./worker_b.js", import.meta.url).href, {
    type: "module",
  });
  const inboxB = new Inbox(workerB);
  const readyB = await inboxB.next();
  if (readyB !== "worker-b:ready") {
    throw new Error(`unexpected worker-b ready message: ${readyB}`);
  }

  workerA.postMessage("poll");
  workerB.postMessage("poll");
  const polling = await Promise.all([inboxA.next(), inboxB.next()]);
  if (!polling.every((message) => String(message).endsWith(":polling"))) {
    throw new Error(`unexpected polling messages: ${polling}`);
  }

  await Deno.writeTextFile(eventPath, "collision\n");
  const results = await Promise.race([
    Promise.all([inboxA.next(), inboxB.next()]),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("worker polls timed out")), 5_000)
    ),
  ]);
  console.log(results.sort().join(","));
} finally {
  workerA.terminate();
  workerB?.terminate();
  await Deno.remove(eventPath).catch(() => {});
}
