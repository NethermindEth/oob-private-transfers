// JSON-lines chain worker for the OOB core (Anvil devnet). Field elements as decimal strings; bytes32 as 0x-hex.
import fs from 'node:fs';
import readline from 'node:readline';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {JsonRpcProvider,Contract,ContractFactory,HDNodeWallet} from 'ethers';
import {buildPoseidon,poseidonContract} from 'circomlibjs';
import {groth16} from 'snarkjs';
const dir=path.dirname(fileURLToPath(import.meta.url));
const DEPTH=32;
const MNEMONIC='test test test test test test test test test test test junk';
const poseidon=await buildPoseidon();
const hash=(xs)=>poseidon.F.toObject(poseidon(xs.map(BigInt))).toString();
const zeros=[];{let z='0';for(let i=0;i<=DEPTH;i++){zeros.push(z);z=hash([z,z]);}}
const provider=new JsonRpcProvider(process.env.OOB_RPC??'http://127.0.0.1:8545',undefined,{cacheTimeout:-1,staticNetwork:true,batchMaxCount:1});
provider.pollingInterval=50;
const artifacts=JSON.parse(fs.readFileSync(path.join(dir,'build/contracts.json')));
const art=(file,name)=>artifacts[file][name];
let pool,registry,anchor,addresses={};
const wallet=(i)=>HDNodeWallet.fromPhrase(MNEMONIC,undefined,`m/44'/60'/0'/0/${i}`);
const signer=async(i)=>provider.getSigner(wallet(i??0).address);
const attach=async(a)=>{addresses=a;
 pool=new Contract(a.pool,art('ShieldedPool.sol','ShieldedPool').abi,provider);
 registry=new Contract(a.registry,art('ServiceRegistry.sol','ServiceRegistry').abi,provider);
 anchor=new Contract(a.anchor,art('EpochAnchor.sol','EpochAnchor').abi,provider);};
const as=async(c,i)=>c.connect(await signer(i));
const tip=async()=>Number(await provider.send('eth_blockNumber',[]));
function summary(tx,receipt){return {hash:tx.hash,block:receipt.blockNumber,gas:receipt.gasUsed.toString(),calldata_bytes:(tx.data.length-2)/2,
 log_data_bytes:receipt.logs.reduce((n,l)=>n+(l.data.length-2)/2,0),status:receipt.status};}
async function send(txp){const tx=await txp;const receipt=await tx.wait();return summary(tx,receipt);}
async function run(r){
 switch(r.op){
 case 'hash': return hash(r.values);
 case 'account': {const w=wallet(r.index);return {address:w.address,pub:'0x'+w.signingKey.publicKey.slice(4)};}
 case 'deploy': {
  const s=await signer(0);const out={};
  const h=await new ContractFactory(poseidonContract.generateABI(2),poseidonContract.createCode(2),s).deploy();await h.waitForDeployment();
  const va=art('Verifier.sol','Groth16Verifier');
  const v=await new ContractFactory(va.abi,va.evm.bytecode.object,s).deploy();await v.waitForDeployment();
  const pa=art('ShieldedPool.sol','ShieldedPool');
  const p=await new ContractFactory(pa.abi,pa.evm.bytecode.object,s).deploy(await h.getAddress(),await v.getAddress());await p.waitForDeployment();
  const ra=art('ServiceRegistry.sol','ServiceRegistry');
  const g=await new ContractFactory(ra.abi,ra.evm.bytecode.object,s).deploy();await g.waitForDeployment();
  const aa=art('EpochAnchor.sol','EpochAnchor');
  const an=await new ContractFactory(aa.abi,aa.evm.bytecode.object,s).deploy(await g.getAddress());await an.waitForDeployment();
  const a={poseidon:await h.getAddress(),verifier:await v.getAddress(),pool:await p.getAddress(),registry:await g.getAddress(),anchor:await an.getAddress()};
  await attach(a);return a;
 }
 case 'attach': await attach(r.addresses);return true;
 case 'rpc': return await provider.send(r.method,r.params??[]);
 case 'tip': return await tip();
 case 'mine': await provider.send('evm_mine',[]);return await tip();
 case 'root': return (await pool.root({blockTag:r.height??'latest'})).toString();
 case 'known_root': return await pool.knownRoots(r.root,{blockTag:r.height});
 case 'member': return await pool.commitments(r.cm,{blockTag:r.height??'latest'});
 case 'next_index': return Number(await pool.nextIndex({blockTag:r.height??'latest'}));
 case 'path': {
  // Sparse depth-32 path from Note events up to r.height; empty subtrees use zeros[level].
  const logs=await pool.queryFilter(pool.filters.Note(),0,r.height??'latest');
  let layer=new Map();for(const log of logs)layer.set(Number(log.args.index),log.args.commitment.toString());
  let index=-1;for(const [i,v] of layer)if(v===r.cm)index=i;
  if(index<0)throw Error('note not in tree');
  const directions=[],siblings=[];
  for(let d=0;d<DEPTH;d++){
   directions.push(index%2);siblings.push(layer.get(index^1)??zeros[d]);
   const next=new Map();
   for(const i of layer.keys()){const p=Math.floor(i/2);if(next.has(p))continue;
    next.set(p,hash([layer.get(2*p)??zeros[d],layer.get(2*p+1)??zeros[d]]));}
   layer=next;index=Math.floor(index/2);
  }
  return {root:layer.get(0),siblings,directions,leaf_index:logs.findIndex(l=>l.args.commitment.toString()===r.cm)};
 }
 case 'prove': {
  const t=performance.now();
  const {proof,publicSignals}=await groth16.fullProve(r.input,path.join(dir,'build/Spend_js/Spend.wasm'),path.join(dir,'build/spend_final.zkey'),undefined,undefined,{singleThread:!!r.single_thread});
  const args=JSON.parse('['+await groth16.exportSolidityCallData(proof,publicSignals)+']');return {args,publicSignals,prove_seconds:(performance.now()-t)/1000};
 }
 case 'deposit': return await send((await as(pool,r.from)).deposit(r.cm,r.payload??'0x',{value:10000000000000000n}));
 case 'transact': return await send((await as(pool,r.from)).transact(...r.args,r.payload??'0x'));
 case 'register': {
  // P's own account registers P (sid = sha256(account pubkey)); optional continues = predecessor sid, start_epoch
  const w=wallet(r.from);const pub='0x'+w.signingKey.publicKey.slice(4);
  const res=await send((await as(registry,r.from)).register(pub,r.op_key,r.holder_keys,r.holder_urls,r.endpoint??'',
    {k:r.k,q:r.q,continuesSid:r.continues??('0x'+'00'.repeat(32)),startEpoch:r.start_epoch??0}));
  const {sha256}=await import('ethers');return {...res,sid:sha256(pub)};
 }
 case 'set_endpoint': return await send((await as(registry,r.from)).setEndpoint(r.sid,r.endpoint));
 case 'set_assignment': return await send((await as(registry,r.from)).setAssignment(r.sid,r.holder_keys,r.holder_urls,r.k,r.q));
 case 'set_holder_endpoint': return await send((await as(registry,r.from)).setHolderEndpoint(r.sid,r.holder_key,r.url));
 case 'service': {
  // Directory view at one block (r.height or latest): operator history, assignments (gamma -> keys,k,n,q,block) and
  // the endpoint record of every holder identity that appears in some assignment. Contract state only (no logs).
  const bt={blockTag:r.height??'latest'};const o=await registry.operator(r.sid,bt);const lin=await registry.lineage(r.sid,bt);
  const keys=BigInt(o[0])===0n?[]:[{key:o[0],from_block:Number(lin[2])}];  // one key per provider (no rotation)
  const na=Number(await registry.assignmentCount(r.sid,bt));const asg=[];const ids=[];
  for(let g=0;g<na;g++){const a=await registry.assignmentAt(r.sid,g,bt);
   asg.push({version:g,keys:[...a[0]],k:Number(a[1]),n:Number(a[2]),q:Number(a[3]),from_block:Number(a[4])});
   for(const x of a[0])if(!ids.includes(x))ids.push(x);}
  const urls=ids.length?[...await registry.holderEndpoints(r.sid,ids,bt)]:[];const epm={};ids.forEach((x,i)=>{epm[x]=urls[i];});
  for(const a of asg)a.urls=a.keys.map(x=>epm[x]);
  const cur=asg.length?asg[asg.length-1]:null;const ep=await registry.endpoint(r.sid,bt);
  return {op_key:o[0],op_eoa:o[1],version:0,governance:o[3],account:o[3],key_history:keys,endpoint:ep,assignments:asg,
          continues:lin[0],start_epoch:Number(lin[1]),registered_block:Number(lin[2]),
          holder_endpoints:epm,holder_version:na-1,holder_keys:cur?cur.keys:[],holder_urls:cur?cur.urls:[],
          k:cur?cur.k:null,n:cur?cur.n:null,q:cur?cur.q:null};
 }
 case 'anchor': return await send((await as(anchor,r.from)).anchor(r.sid,r.e,r.manifest,r.cert));
 case 'anchor_data': {
  if(process.env.OOB_NO_EVENT_LOGS==='1')throw Error('event logs unavailable (OOB_NO_EVENT_LOGS=1)');
  // manifest/cert bytes from the Anchored event (calldata) at or below r.height
  const logs=await anchor.queryFilter(anchor.filters.Anchored(r.sid,r.e),0,r.height??'latest');
  if(!logs.length)return null;
  const l=logs[0];return {h_manifest:l.args.hManifest,h_cert:l.args.hCert,manifest:l.args.manifest,cert:l.args.cert,block:l.blockNumber};
 }
 case 'get_anchor': {const a=await anchor.get(r.sid,r.e,{blockTag:r.height??'latest'});return {h_manifest:a[0],h_cert:a[1],block:Number(a[2])};}
 case 'list_anchors': return (await anchor.epochs(r.sid,{blockTag:r.height??'latest'})).map(Number);
 }
 throw Error('unknown chain operation '+r.op);
}
for await(const line of readline.createInterface({input:process.stdin})){
 try{console.log(JSON.stringify({result:await run(JSON.parse(line))},(_,v)=>typeof v==='bigint'?v.toString():v));}
 catch(e){console.log(JSON.stringify({error:e.shortMessage??e.reason??e.message}));}
}
process.exit(0);
