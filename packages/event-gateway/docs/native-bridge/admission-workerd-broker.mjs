import {createServer} from 'node:http';
import {randomUUID,createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {sourceHashes} from './coupled-workerd-source-hashes.mjs';
console.log=(...args)=>console.error(...args); // stdout is solely the parent handshake.
// Explicit trusted CLI package directories anchor normal, constant-name resolution.
const esbuildRequire=createRequire(join(process.env.FIXTURE_ESBUILD,'package.json'));
const miniflareRequire=createRequire(join(process.env.FIXTURE_MINIFLARE,'package.json'));
const {build}=esbuildRequire('esbuild');
const {Miniflare,convertV4MiniflareOptions}=miniflareRequire('miniflare');
const bundle=await build({entryPoints:[new URL('./admission-workerd-worker.ts',import.meta.url).pathname],alias:{'fixture-event-runtime':process.env.FIXTURE_CLOUD_SOURCE},write:false,metafile:true,bundle:true,format:'esm',platform:'neutral',external:['cloudflare:workers'],logLevel:'warning'});
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const bundleEvidence={sha256:sha256(bundle.outputFiles[0].contents),inputs:sourceHashes(Object.keys(bundle.metafile.inputs),[join(process.env.FIXTURE_CLOUD_SOURCE,'../../..'),fileURLToPath(new URL('.',import.meta.url))])};
const secret=randomUUID();
const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:bundle.outputFiles[0].text,compatibilityDate:'2026-10-05',host:'127.0.0.1',port:0,
  bindings:{FIXTURE_SECRET:secret,EVENT_ENABLED:'true',EVENT_NATIVE_BINDING_ENABLED:'true',EVENT_NATIVE_BINDING_CANARY:JSON.stringify({principal:'qualification@example.com',agent:'pilot'}),EVENT_MANUAL_ENABLED:'true',EVENT_HOST:'events.example.com',ACCESS_ISSUER:'https://access.test',ACCESS_EVENT_AUD:'event-aud',ACCESS_UI_AUD:'ui-aud'},
  durableObjects:{OWNER_REGISTRY:{className:'OwnerRegistry',useSQLite:true},AGENT_COORDINATOR:{className:'AdmissionCoordinator',useSQLite:true}},
}));
const paths=new Set(['/fixture/challenge','/fixture/read','/v1/nodes/complete','/v1/runtimes/challenge','/v1/runtimes/attach','/v1/runtimes/renew','/v1/runtimes/transfer']);
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
  await mf.ready;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  process.stdout.write(`${JSON.stringify({port:server.address().port,secret,bundle:bundleEvidence})}\n`);
} catch(error) {console.error(error);await stop();process.exitCode=1;}
