import {createServer,Server as HttpServer} from 'node:http';
import {randomUUID,createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {sourceHashes} from './coupled-workerd-source-hashes.mjs';
export function fixturePorts(env=process.env) {
  const ports=Object.fromEntries(Object.entries({ENTRY:49732,LOOPBACK:49733,BROKER:49734}).map(([name,fallback])=>{
    const value=env[`FIXTURE_${name}_PORT`]??String(fallback);
    if(!/^[0-9]+$/.test(value)||Number(value)<1024||Number(value)>65535)throw new Error(`Invalid FIXTURE_${name}_PORT`);
    return [name,Number(value)];
  }));
  if(new Set(Object.values(ports)).size!==3)throw new Error('Fixture ports must be distinct');
  return ports;
}

export function interceptLoopbackPort(port) {
  const prototype=HttpServer.prototype;
  const descriptor=Object.getOwnPropertyDescriptor(prototype,'listen');
  const original=prototype.listen;
  let calls=0;
  // Miniflare has no public loopback-port option; reject drift in its private listen contract.
  prototype.listen=function(...args){
    if(calls!==0||args.length!==3||args[0]!==0||args[1]!=='127.0.0.1'||typeof args[2]!=='function')throw new Error('Unexpected Miniflare HTTP listener');
    calls++;
    return original.call(this,port,args[1],args[2]);
  };
  return (requireCall=true)=>{
    if(descriptor)Object.defineProperty(prototype,'listen',descriptor);
    else delete prototype.listen;
    if(requireCall&&calls!==1)throw new Error('Expected exactly one Miniflare HTTP loopback listener');
  };
}

async function main(){
const ports=fixturePorts();
console.log=(...args)=>console.error(...args); // stdout is solely the parent handshake.
// Explicit trusted CLI package directories anchor normal, constant-name resolution.
const esbuildRequire=createRequire(join(process.env.FIXTURE_ESBUILD,'package.json'));
const miniflareRequire=createRequire(join(process.env.FIXTURE_MINIFLARE,'package.json'));
const {build}=esbuildRequire('esbuild');
const {Miniflare,convertV4MiniflareOptions}=miniflareRequire('miniflare');
const bundle=await build({entryPoints:[new URL('./coupled-workerd-worker.ts',import.meta.url).pathname],alias:{'fixture-event-runtime':process.env.FIXTURE_CLOUD_SOURCE},write:false,metafile:true,bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers','node:crypto'],logLevel:'warning'});
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const bundleEvidence={sha256:sha256(bundle.outputFiles[0].contents),inputs:sourceHashes(Object.keys(bundle.metafile.inputs),[join(process.env.FIXTURE_CLOUD_SOURCE,'../../..'),fileURLToPath(new URL('.',import.meta.url))])};
const secret=randomUUID();
const restoreLoopback=interceptLoopbackPort(ports.LOOPBACK);
let mf;
try {mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:bundle.outputFiles[0].text,compatibilityDate:'2026-10-05',cf:false,host:'127.0.0.1',port:ports.ENTRY,
  bindings:{FIXTURE_SECRET:secret,EVENT_ENABLED:'true',EVENT_NATIVE_BINDING_ENABLED:'true',EVENT_NATIVE_BINDING_CANARY:JSON.stringify({principal:'qualification@example.com',agent:'pilot'}),EVENT_MANUAL_ENABLED:'true',EVENT_HOST:'events.example.com',ACCESS_ISSUER:'https://access.test',ACCESS_EVENT_AUD:'event-aud',ACCESS_UI_AUD:'ui-aud'},
  durableObjects:{OWNER_REGISTRY:{className:'FixtureRegistry',useSQLite:true},AGENT_COORDINATOR:{className:'FixtureCoordinator',useSQLite:true}},
}));} catch(error) {restoreLoopback(false);throw error;}
const paths=new Set(['/fixture/challenge','/fixture/admission','/fixture/setup','/fixture/read','/fixture/alarm','/v1/nodes/complete','/v1/runtimes/challenge','/v1/runtimes/attach','/v1/dispatch/claim','/v1/dispatch/settle-no-start','/v1/ack']);
const server=createServer({requestTimeout:5000,headersTimeout:5000,maxHeaderSize:16384},async(req,res)=>{
  try {
    if(req.method!=='POST'||!paths.has(req.url)||req.headers['x-fixture-secret']!==secret) {res.writeHead(403).end();req.resume();return;}
    const chunks=[];let size=0;
    for await(const chunk of req) {size+=chunk.length;if(size>8192){res.writeHead(413).end();req.resume();return;}chunks.push(chunk);}
    const headers=new Headers();for(const [k,v] of Object.entries(req.headers))if(v!==undefined)headers.set(k,Array.isArray(v)?v.join(', '):v);
    headers.set('x-fixture-secret',secret);
    const response=await mf.dispatchFetch(`https://events.example.com${req.url}`,{method:'POST',headers,body:Buffer.concat(chunks)});
    res.writeHead(response.status,{'content-type':response.headers.get('content-type')??'application/octet-stream'});
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch(error) {console.error(error);if(!res.headersSent)res.writeHead(502);res.end();}
});
let stopping=false;
async function stop(){if(stopping)return;stopping=true;server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await mf.dispose();}
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>void stop().then(()=>process.exit(0)));
process.on('disconnect',()=>void stop().then(()=>process.exit(0)));
try {
  try {await mf.ready;} catch(error) {restoreLoopback(false);throw error;}
  restoreLoopback();
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(ports.BROKER,'127.0.0.1',resolve);});
  process.stdout.write(`${JSON.stringify({port:server.address().port,secret,bundle:bundleEvidence})}\n`);
} catch(error) {console.error(error);await stop();process.exitCode=1;}
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1])await main();
