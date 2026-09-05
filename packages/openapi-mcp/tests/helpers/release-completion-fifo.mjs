import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";

const [directory, mode, sidecar] = process.argv.slice(2);
const payloadPath = join(directory, "release.sqlite");
const target = join(directory, `release.${sidecar}`);
const envelope = {
  manifestJson: "{}",
  signature: { algorithm: "Ed25519", keyId: "fixture", signature: "fixture" },
};
fs.writeFileSync(payloadPath, "completion gate fixture");
fs.writeFileSync(
  join(directory, "release.manifest.json"),
  envelope.manifestJson,
);
fs.writeFileSync(
  join(directory, "release.manifest.sig"),
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
