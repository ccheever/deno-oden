process.on("message", (_message, handle) => {
  process.send({ receivedHandle: handle !== undefined });
});

// Keep the IPC receiver alive until the parent disconnects it.
setInterval(() => {}, 1_000);
