// Replace only the release operation. Keep the entrypoint and installed plugin
// normalization/loading real, including dynamic imports of configured plugins.
import { registerHooks } from "node:module";

const pluginsUrl = new URL(
  "./lib/plugins/index.js",
  import.meta.resolve("semantic-release"),
).href;
const boundaryUrl = "test:semantic-release-operation";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "semantic-release") {
      return { url: boundaryUrl, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url !== boundaryUrl) return nextLoad(url, context);
    return {
      format: "module",
      shortCircuit: true,
      source: `
import assert from "node:assert/strict";
import normalizePlugins from ${JSON.stringify(pluginsUrl)};

export default async function release(options, context) {
  // Select the configured npm adapter without executing unrelated release hooks.
  const adapterEntries = options.plugins.filter(entry => Array.isArray(entry) && entry[1]?.npmPublish === true);
  assert.equal(adapterEntries.length, 1);
  const logger = { log() {}, success() {}, warn() {}, error() {}, scope() { return this; } };
  const input = { ...context, env: {}, options: { ...options, plugins: adapterEntries, dryRun: false }, logger };
  const plugins = await normalizePlugins(input, {});
  const expected = {
    verifyConditions: "Protected npmrelease GitHub OIDC context and observed publisher readiness are required",
    prepare: "Protected npmrelease GitHub OIDC context and observed publisher readiness are required",
    publish: "No tested tarball is available for publication",
  };
  for (const [hook, message] of Object.entries(expected)) {
    await assert.rejects(() => plugins[hook](input), error => {
      const errors = error.errors ?? [error];
      return errors.length === 1 && errors[0].message === message;
    });
  }
  console.log("adapter guards reached: verifyConditions, prepare, publish");
}
`,
    };
  },
});
