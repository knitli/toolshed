const NOTE = "WORKSHOP_IDLE_20261113T0412Z_398bc619", PLACEHOLDER = "PLACEHOLDER_EXACT_CALLBACK_ID";
function check(r, id, digest) {
  const errors = []; let body;
  try { body = JSON.parse(r?.body); } catch { errors.push("body-json"); }
  if (r?.id !== id) errors.push("id");
  if (r?.taskType !== "workshop-qualification/v1") errors.push("taskType");
  if (body?.fields?.note !== NOTE) errors.push("note");
  if (r?.status !== "read") errors.push("status");
  if (r?.provenance?.verified?.authentic !== true) errors.push("authentic");
  if (!Array.isArray(r?.provenance?.verified?.reasons) || r.provenance.verified.reasons.length) errors.push("reasons");
  if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) errors.push("receiptDigest-hex");
  if (!Array.isArray(r?.provenance?.chain) || !r.provenance.chain.length) errors.push("chain");
  return { errors, body };
}
// Copy into Workshop executeCode; replace only PLACEHOLDER_EXACT_CALLBACK_ID.
async function executeCode(env, id = PLACEHOLDER, log = console.log) {
  let r, readError = false;
  try { r = await env.MESSAGING.read(id); } catch { readError = true; }
  const digest = r?.provenance?.receiptDigest, { errors, body } = check(r, id, digest);
  if (readError) errors.unshift("read-error");
  log(JSON.stringify({ id: typeof r?.id === "string" ? r.id.slice(0,128) : null, taskType: r?.taskType ?? null,
    note: typeof body?.fields?.note === "string" ? body.fields.note.slice(0,128) : null, status: r?.status ?? null,
    verified: r?.provenance?.verified?.authentic === true && Array.isArray(r?.provenance?.verified?.reasons) && !r.provenance.verified.reasons.length,
    receiptDigest: typeof digest === "string" ? digest.slice(0,128) : null, chainLength: Array.isArray(r?.provenance?.chain) ? r.provenance.chain.length : 0 }));
  if (errors.length) throw new Error(`CHECK_FAIL: ${errors.join(",")}`);
  log("WORKSHOP_IDLE_ACK");
}
async function selfCheck() {
  const a = (x,m) => { if (!x) throw new Error(`SELF_CHECK_FAIL: ${m}`); }, id = "test-id";
  const good = { id, taskType:"workshop-qualification/v1", body:JSON.stringify({fields:{note:NOTE}}), status:"read", provenance:{verified:{authentic:true,reasons:[]},receiptDigest:"a".repeat(64),chain:["receipt"]} };
  const run = async r => { let n=0; const out=[]; let err; try { await executeCode({MESSAGING:{read:async x=>{n++;a(x===id,"read id");return r;}}},id,x=>out.push(x)); } catch(e) { err=String(e); } return {n,out,err}; };
  const green=await run(good); a(green.n===1&&!green.err&&green.out.at(-1)==="WORKSHOP_IDLE_ACK","valid/read once");
  a(check(good,id,good.provenance.verified.receiptDigest).errors.includes("receiptDigest-hex"),"old nested-path mutant red");
  a(!check(good,id,good.provenance.receiptDigest).errors.length,"restored sibling path green");
  for (const [key,value] of [["id","wrong"],["note","wrong"],["authentic",false]]) {
    const bad=structuredClone(good); if(key==="id") bad.id=value; if(key==="note") bad.body=JSON.stringify({fields:{note:value}}); if(key==="authentic") bad.provenance.verified.authentic=value;
    const x=await run(bad); a(x.n===1&&!!x.err&&!x.out.includes("WORKSHOP_IDLE_ACK"),`${key} rejects/read once`);
  }
  console.log("SELF_CHECK_PASS: valid ACK/read=1; wrong digest path red, restored green; wrong id/note/authentic reject");
}
if (process.argv[2] === "--self-check") await selfCheck(); else console.log(executeCode.toString());
