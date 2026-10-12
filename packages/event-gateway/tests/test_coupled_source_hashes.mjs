import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {registerHooks} from 'node:module';
import {test} from 'node:test';
import {sourceHashes} from '../docs/native-bridge/coupled-workerd-source-hashes.mjs';

// Static dependency doubles for importing the unchanged TypeScript fixture.
export let AgentCoordinator;
export class OwnerRegistry {}
export const signedEventRequest=async()=>({text:async()=>'signed',headers:new Map()});
export const eventFetch=()=>{throw new Error('unexpected event fetch');};
export const ownerRegistryName=()=>{throw new Error('unexpected registry lookup');};
export const coordinatorName=()=>{throw new Error('unexpected coordinator lookup');};

test('hashes only resolved sources inside qualified roots, before reading contents', t => {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  const temporary = fs.mkdtempSync(join(tmpdir(), 'native-source-hashes-'));
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  t.after(() => fs.rmSync(temporary, {recursive: true, force: true}));
  const root = join(temporary, 'qualified');
  const fixture = join(temporary, 'fixture');
  const outside = join(temporary, 'qualified-other');
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  for (const directory of [root, fixture, outside]) fs.mkdirSync(directory); // nosemgrep: javascript_pathtraversal_rule-non-literal-fs-filename
  const source = join(root, 'module.ts');
  const fixtureSource = join(fixture, 'worker.ts');
  const escaped = join(outside, 'outside.ts');
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  for (const path of [source, fixtureSource, escaped]) fs.writeFileSync(path, 'synthetic source'); // nosemgrep: javascript_pathtraversal_rule-non-literal-fs-filename
  const symlink = join(root, 'escape.ts');
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Owned disposable test tree only; no user paths.
  fs.symlinkSync(escaped, symlink); // nosemgrep: javascript_pathtraversal_rule-non-literal-fs-filename
  const sha = createHash('sha256').update('synthetic source').digest('hex');
  assert.deepEqual(sourceHashes([source, fixtureSource], [root, fixture]), {
    [source]: sha, [fixtureSource]: sha,
  });
  const read = t.mock.method(fs, 'readFileSync');
  for (const path of [escaped, join(root, '..', 'qualified-other', 'outside.ts'), symlink]) {
    assert.throws(() => sourceHashes([source, path], [root, fixture]), /outside qualified source roots/);
    assert.equal(read.mock.callCount(), 0, 'validate all paths before any content read');
  }
});


test('fixture ports are fixed, configurable, bounded, and distinct', async () => {
  const {fixturePorts}=await import('../docs/native-bridge/coupled-workerd-broker.mjs');
  assert.deepEqual(fixturePorts({}), {ENTRY:49732,LOOPBACK:49733,BROKER:49734});
  assert.equal(fixturePorts({FIXTURE_ENTRY_PORT:'50100'}).ENTRY,50100);
  for(const value of ['0','1023','65536','12x','1.5',''])assert.throws(()=>fixturePorts({FIXTURE_ENTRY_PORT:value}),/Invalid/);
  assert.throws(()=>fixturePorts({FIXTURE_ENTRY_PORT:'49733'}),/distinct/);
});

test('Miniflare HTTP interception rewrites only one exact loopback listen and restores prototype', async t => {
  const {Server}=await import('node:net');
  const {createServer}=await import('node:http');
  const {interceptLoopbackPort}=await import('../docs/native-bridge/coupled-workerd-broker.mjs');
  const listen=t.mock.method(Server.prototype,'listen',function(){return this;});
  const server=createServer();
  const prototype=Object.getPrototypeOf(server);
  const before=Object.getOwnPropertyDescriptor(prototype,'listen');
  const restore=interceptLoopbackPort(49733);
  const callback=()=>{};
  try {
    assert.throws(()=>server.listen(0,'0.0.0.0',callback),/Unexpected/);
    assert.throws(()=>server.listen({port:0,host:'127.0.0.1'},callback),/Unexpected/);
    assert.equal(listen.mock.callCount(),0);
    assert.equal(server.listen(0,'127.0.0.1',callback),server);
    assert.deepEqual(listen.mock.calls[0].arguments,[49733,'127.0.0.1',callback]);
    assert.throws(()=>server.listen(0,'127.0.0.1',callback),/Unexpected/);
  } finally {restore();}
  assert.deepEqual(Object.getOwnPropertyDescriptor(prototype,'listen'),before);
  // Failed startup must restore the actual HTTP prototype without masking its error.
  assert.doesNotThrow(()=>interceptLoopbackPort(49733)(false));
  assert.deepEqual(Object.getOwnPropertyDescriptor(prototype,'listen'),before);
  assert.throws(interceptLoopbackPort(49733),/exactly one/);
  assert.deepEqual(Object.getOwnPropertyDescriptor(prototype,'listen'),before);
});

test('fixture setup requires prior admission and cannot seed runtime SQL', async t => {
  let admitted=false,published=0,claimed=0;
  const statements=[];
  AgentCoordinator=class {
    constructor(ctx){this.ctx=ctx;}
    async setEnabled(){}
    async publishManual(){if(!admitted)throw new Error('runtime_not_admitted');published++;return {runtimeId:'fixture-runtime'};}
    async claimTransport(){claimed++;return {envelope:{}};}
  };
  const worker=new URL('../docs/native-bridge/coupled-workerd-worker.ts',import.meta.url).href;
  const dependencies=new Set(['delivery.ts','api.ts','coordinator.ts','registry.ts','contracts.ts']
    .map(name=>'fixture-event-runtime/'+name));
  const hooks=registerHooks({resolve(specifier,context,nextResolve){
    if(context.parentURL===worker&&dependencies.has(specifier))return {url:import.meta.url,shortCircuit:true};
    return nextResolve(specifier,context);
  }});
  t.after(()=>hooks.deregister());
  const {FixtureCoordinator}=await import('../docs/native-bridge/coupled-workerd-worker.ts');
  const coordinator=new FixtureCoordinator({storage:{sql:{exec(sql){
    statements.push(sql);
    if(/INSERT\s+INTO\s+runtimes/i.test(sql))admitted=true;
    return {toArray:()=>[]};
  }}}},{});
  const setup={runtimeId:'fixture-runtime',nodeId:'fixture-node',transportPrivateKey:'synthetic'};
  await assert.rejects(coordinator.fixtureSetup(setup),/runtime_not_admitted/);
  assert.deepEqual(statements,[],'setup must not write admission SQL');
  assert.equal(published,0);assert.equal(claimed,0);
  admitted=true;
  const result=await coordinator.fixtureSetup(setup);
  assert.equal(result.signedDelivery.body,'signed');
  assert.equal(published,1);assert.equal(claimed,1);
  assert.deepEqual(statements,[]);
});
