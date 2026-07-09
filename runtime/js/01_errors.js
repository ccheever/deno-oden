// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const { BadResource, Interrupted, NotCapable } = core;
const { Error, ObjectDefineProperty } = primordials;

// Define (not assign) `name` on error instances: under Oden capsec lockdown
// Error.prototype is frozen, so the inherited `name` is non-writable and a
// plain `this.name = ...` assignment in a constructor throws (the SES
// "override mistake"). ObjectDefineProperty keeps the exact semantics the
// assignment had (own, writable, enumerable, configurable) with or without
// lockdown. Part of the lockdown lazy-write audit (ENG-23781).
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Compartments and lockdown)
function defineName(err, name) {
  ObjectDefineProperty(err, "name", {
    __proto__: null,
    value: name,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

class NotFound extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "NotFound");
  }
}

class ConnectionRefused extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "ConnectionRefused");
  }
}

class ConnectionReset extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "ConnectionReset");
  }
}

class ConnectionAborted extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "ConnectionAborted");
  }
}

class NotConnected extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "NotConnected");
  }
}

class AddrInUse extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "AddrInUse");
  }
}

class AddrNotAvailable extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "AddrNotAvailable");
  }
}

class BrokenPipe extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "BrokenPipe");
  }
}

class AlreadyExists extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "AlreadyExists");
  }
}

class InvalidData extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "InvalidData");
  }
}

class TimedOut extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "TimedOut");
  }
}

class WriteZero extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "WriteZero");
  }
}

class WouldBlock extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "WouldBlock");
  }
}

class UnexpectedEof extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "UnexpectedEof");
  }
}

class Http extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "Http");
  }
}

class Busy extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "Busy");
  }
}

class PermissionDenied extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "PermissionDenied");
  }
}

class NotSupported extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "NotSupported");
  }
}

class FilesystemLoop extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "FilesystemLoop");
  }
}

class IsADirectory extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "IsADirectory");
  }
}

class NetworkUnreachable extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "NetworkUnreachable");
  }
}

class NotADirectory extends Error {
  constructor(msg, opts) {
    super(msg, opts);
    defineName(this, "NotADirectory");
  }
}

const errors = {
  NotFound,
  PermissionDenied,
  ConnectionRefused,
  ConnectionReset,
  ConnectionAborted,
  NotConnected,
  AddrInUse,
  AddrNotAvailable,
  BrokenPipe,
  AlreadyExists,
  InvalidData,
  TimedOut,
  Interrupted,
  WriteZero,
  WouldBlock,
  UnexpectedEof,
  BadResource,
  Http,
  Busy,
  NotSupported,
  FilesystemLoop,
  IsADirectory,
  NetworkUnreachable,
  NotADirectory,
  NotCapable,
};

return { errors };
})();
