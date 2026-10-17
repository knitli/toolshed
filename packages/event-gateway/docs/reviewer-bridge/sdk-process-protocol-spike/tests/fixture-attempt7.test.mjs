import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { PassThrough } from "node:stream";
import { finished } from "node:stream/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

const source = await readFile(
  new URL("../fixture.mjs", import.meta.url),
  "utf8",
);
const classStart = source.indexOf("class FakeProcess extends EventEmitter {");
const classEnd = source.indexOf("\n\nconst results = [];", classStart);
assert(
  classStart >= 0 && classEnd > classStart,
  "candidate FakeProcess class must exist",
);
const sandbox = { EventEmitter, assert, Buffer };
runInNewContext(
  `${source.slice(classStart, classEnd)}\nglobalThis.FakeProcess = FakeProcess;`,
  sandbox,
);
const { FakeProcess } = sandbox;

test("actual candidate emitter preserves an astral character split across byte chunks", async () => {
  const value = "😀";
  const expected = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  const stdout = new PassThrough();
  const writes = [];
  const joined = [];
  const write = stdout.write.bind(stdout);
  stdout.write = (chunk, ...args) => {
    writes.push(Buffer.from(chunk));
    return write(chunk, ...args);
  };
  stdout.on("data", (chunk) => joined.push(Buffer.from(chunk)));
  const complete = finished(stdout);

  FakeProcess.prototype.emitFrame.call({ stdout }, value);
  stdout.end();
  await complete;

  const actual = Buffer.concat(joined);
  assert.equal(writes.length, 2);
  assert.equal(
    writes[0].at(-1) & 0xc0,
    0x80,
    "first chunk ends inside UTF-8 sequence",
  );
  assert.equal(
    writes[1][0] & 0xc0,
    0x80,
    "second chunk starts inside UTF-8 sequence",
  );
  assert.deepEqual(actual, expected);
  assert.equal(JSON.parse(actual.toString("utf8")), value);
});

test("actual candidate emitter preserves the 64 KiB byte cap", () => {
  const writes = [];
  const stdout = { write: (chunk) => writes.push(Buffer.from(chunk)) };
  const exactLimit = "x".repeat(64 * 1024 - 3);
  assert.equal(
    Buffer.byteLength(`${JSON.stringify(exactLimit)}\n`, "utf8"),
    64 * 1024,
  );

  FakeProcess.prototype.emitFrame.call({ stdout }, exactLimit);
  assert.equal(writes.length, 2);
  assert.equal(Buffer.concat(writes).byteLength, 64 * 1024);

  const oversized = "x".repeat(64 * 1024 - 2);
  assert.throws(
    () => FakeProcess.prototype.emitFrame.call({ stdout }, oversized),
    /fake output frame bound/,
  );
  assert.equal(
    writes.length,
    2,
    "oversized frames are rejected before any write",
  );
});
