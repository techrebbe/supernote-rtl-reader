"use strict";

// This script has no process-discovery path. It is loaded only in the host's
// newly spawned fake_service.exe child.
const target = Process.getModuleByName("fake_service.exe");
const setter = target.getExportByName("fake_setter");
let hits = 0;
const listener = Interceptor.attach(setter, {
  onEnter(args) {
    hits += 1;
    send({ kind: "hit", value: args[0].toInt32(), ordinal: hits });
  }
});

rpc.exports = {
  stop() {
    listener.detach();
    return hits;
  }
};

send({ kind: "armed" });
