import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { resolve, sep } from "node:path";

const MODES = new Set(["ordinary", "static-fifo", "swap-fifo"]);
const SIDECARS = new Set(["manifest.json", "manifest.sig"]);

const [directory, mode, sidecar] = process.argv.slice(2);
if (!MODES.has(mode) || !SIDECARS.has(sidecar)) {
  throw new Error("fixture invoked with unexpected mode or sidecar");
}
// Confine every filesystem touch to the caller-provided fixture directory,
// which itself must live under the OS temp root.
const root = resolve(directory ?? "");
const tempRoot = resolve(tmpdir());
if (root !== tempRoot && !root.startsWith(tempRoot + sep)) {
  throw new Error("fixture directory escapes the temp root");
}
function confined(name) {
  const resolved = resolve(root, name);
  if (resolved !== root && !resolved.startsWith(root + sep)) {
    throw new Error("fixture path escapes its directory");
  }
  return resolved;
}
const payloadPath = confined("release.sqlite");
const target = confined(`release.${sidecar}`);
const envelope = {
  manifestJson: "{}",
  signature: { algorithm: "Ed25519", keyId: "fixture", signature: "fixture" },
};
fs.writeFileSync(payloadPath, "completion gate fixture");
fs.writeFileSync(confined("release.manifest.json"), envelope.manifestJson); // nosemgrep -- path validated by confined() helper
fs.writeFileSync(
  confined("release.manifest.sig"),
  JSON.stringify(envelope.signature),
);

function replaceWithFifo() {
  fs.renameSync(target, `${target}.original`);
  execFileSync("mkfifo", [target]);
}

if (mode === "static-fifo") replaceWithFifo();
if (mode === "swap-fifo") {
  const nativeOpen = fs.openSync;
  fs.openSync = (path, ...args) => {
    if (path === target) {
      // Interpose only at the lstat/open race boundary. The actual native
      // open below receives production flags and blocks if O_NONBLOCK is lost.
      replaceWithFifo();
    }
    return nativeOpen(path, ...args);
  };
  syncBuiltinESMExports();
}

const { releaseFileIdentity, verifyReleaseCompletion } = await import(
  "../../src/sqlite/release-completion.ts"
);
const { DEFAULT_RUNTIME_LIMITS } = await import(
  "../../src/runtime/versions.ts"
);
try {
  verifyReleaseCompletion(
    payloadPath,
    releaseFileIdentity(payloadPath),
    envelope,
    DEFAULT_RUNTIME_LIMITS,
  );
  process.stdout.write(JSON.stringify({ outcome: "completed" }));
} catch (error) {
  process.stdout.write(
    JSON.stringify({ outcome: "rejected", code: error.code }),
  );
}
