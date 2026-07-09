setTimeout(() => console.log("runtime-unarmed: timer-ok"), 0);
await new Promise((resolve) => setTimeout(resolve, 20));
