// Build depth-32 Spend circuit, LOCAL TEST Groth16 setup (NOT a ceremony), verifier and contracts.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {randomBytes,createHash} from 'node:crypto';
import solc from 'solc';
import * as snarkjs from 'snarkjs';
const dir=path.dirname(fileURLToPath(import.meta.url)); process.chdir(dir);
fs.mkdirSync('build',{recursive:true});
const run=(bin,args)=>execFileSync(path.join(dir,'node_modules/.bin',bin),args,{stdio:'inherit'});
const sha=(f)=>createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const info={note:'LOCAL TEST SETUP, NOT A CEREMONY. Single-contributor powers of tau + single phase-2 contribution with OS randomness.'};
const fingerprint=createHash('sha256').update(fs.readFileSync('zk/Spend.circom')).digest('hex');
const t0=Date.now();
// circom2 (WASI) cannot follow the node_modules symlink: copy circomlib circuits into build/.
fs.cpSync(fs.realpathSync('node_modules/circomlib/circuits'),'build/circomlib',{recursive:true,dereference:true});
if(!fs.existsSync('build/spend_final.zkey') || !fs.existsSync('build/fingerprint') || fs.readFileSync('build/fingerprint','utf8')!==fingerprint) {
 run('circom2',['zk/Spend.circom','--r1cs','--wasm','--sym','-o','build']);
 const r1cs=await snarkjs.r1cs.info('build/Spend.r1cs');
 const need=Math.ceil(Math.log2(r1cs.nConstraints+r1cs.nPubInputs+r1cs.nOutputs+1))+1;
 info.constraints=r1cs.nConstraints; info.power_needed=need;
 // Reuse the existing local test ptau (power 14) when sufficient; otherwise generate a new local one.
 const existing=path.join(dir,'../../integration/build/pot.ptau');
 let ptau='build/pot.ptau';
 const have=fs.existsSync('build/pot.power')?Number(fs.readFileSync('build/pot.power','utf8')):0;
 if(fs.existsSync(ptau) && have>=need){info.ptau=`reused local test powers of tau build/pot.ptau (power ${have})`;}
 else if(need<=14 && fs.existsSync(existing)){fs.copyFileSync(existing,ptau);info.ptau='reused integration/build/pot.ptau (power 14, local test setup)';}
 else {
  const p=Math.max(need,12);
  run('snarkjs',['powersoftau','new','bn128',String(p),'build/pot0.ptau']);
  run('snarkjs',['powersoftau','contribute','build/pot0.ptau','build/pot1.ptau','--name=LOCAL TEST SETUP NOT A CEREMONY',`-e=${randomBytes(32).toString('hex')}`]);
  run('snarkjs',['powersoftau','prepare','phase2','build/pot1.ptau',ptau]);
  info.ptau=`new local powers of tau, power ${p}`;fs.writeFileSync('build/pot.power',String(p));
 }
 run('snarkjs',['groth16','setup','build/Spend.r1cs',ptau,'build/spend0.zkey']);
 run('snarkjs',['zkey','contribute','build/spend0.zkey','build/spend_final.zkey','--name=LOCAL TEST SETUP NOT A CEREMONY',`-e=${randomBytes(32).toString('hex')}`]);
 fs.writeFileSync('build/fingerprint',fingerprint);
 info.setup_seconds=(Date.now()-t0)/1000;
 fs.writeFileSync('build/setup_info.json',JSON.stringify(info,null,1));
}
run('snarkjs',['zkey','export','solidityverifier','build/spend_final.zkey','build/Verifier.sol']);
run('snarkjs',['zkey','export','verificationkey','build/spend_final.zkey','build/verification_key.json']);
const sources={};
for(const f of ['sol/ShieldedPool.sol','sol/ServiceRegistry.sol','sol/EpochAnchor.sol','build/Verifier.sol']) sources[path.basename(f)]={content:fs.readFileSync(f,'utf8')};
const result=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources,settings:{optimizer:{enabled:true,runs:200},evmVersion:'cancun',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
for(const e of result.errors??[]) {console.error(e.formattedMessage);if(e.severity==='error')process.exit(1);}
fs.writeFileSync('build/contracts.json',JSON.stringify(result.contracts));
const meta=JSON.parse(fs.existsSync('build/setup_info.json')?fs.readFileSync('build/setup_info.json'):'{}');
meta.zkey_sha256=sha('build/spend_final.zkey');meta.wasm_sha256=sha('build/Spend_js/Spend.wasm');meta.solc=solc.version();
fs.writeFileSync('build/setup_info.json',JSON.stringify(meta,null,1));
console.log('Built depth-32 Spend Groth16 verifier and contracts. LOCAL TEST SETUP, NOT A CEREMONY.',JSON.stringify(meta));
process.exit(0);
