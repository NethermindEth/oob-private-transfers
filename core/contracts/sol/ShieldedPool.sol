// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
interface IPoseidon { function poseidon(uint256[2] calldata) external pure returns(uint256); }
interface IVerifier { function verifyProof(uint[2] calldata,uint[2][2] calldata,uint[2] calldata,uint[4] calldata) external view returns(bool); }
/// Research-only fixed-denomination shielded pool (depth-32 incremental Poseidon Merkle tree).
/// Never deploy with real funds. Groth16 verifier comes from a LOCAL TEST SETUP, not a ceremony.
contract ShieldedPool {
 uint256 constant FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617;
 uint256 public constant DEPTH=32;
 uint256 public constant denomination=0.01 ether;
 uint256 public constant RECORD_BYTES=736; // on-chain payload baseline only (OOB transfers post no payload)
 uint256 public root;
 uint256 public nextIndex;
 uint256[32] public zeros;
 uint256[32] public filled;
 mapping(uint256=>bool) public knownRoots;
 mapping(uint256=>bool) public spent;
 mapping(uint256=>bool) public commitments;
 IPoseidon immutable hasher;
 IVerifier immutable verifier;
 event Note(uint256 indexed commitment,uint256 index,uint256 root,bytes payload);
 event Withdrawal(uint256 indexed nullifier,address recipient);
 constructor(address h,address v) {
  hasher=IPoseidon(h); verifier=IVerifier(v);
  uint256 z=0;
  for(uint i=0;i<DEPTH;i++){zeros[i]=z;filled[i]=z;z=hasher.poseidon([z,z]);}
  root=z;knownRoots[z]=true;
 }
 function insert(uint256 cm,bytes calldata payload) internal {
  require(cm>0 && cm<FIELD && !commitments[cm],"commitment");
  require(nextIndex<(1<<DEPTH),"full"); require(payload.length==0 || payload.length==RECORD_BYTES,"payload length");
  commitments[cm]=true;
  uint256 index=nextIndex++;uint256 cursor=index;uint256 cur=cm;
  for(uint i=0;i<DEPTH;i++){
   if(cursor%2==0){filled[i]=cur;cur=hasher.poseidon([cur,zeros[i]]);}
   else {cur=hasher.poseidon([filled[i],cur]);} cursor/=2;
  }
  root=cur;knownRoots[cur]=true;emit Note(cm,index,cur,payload);
 }
 function deposit(uint256 cm,bytes calldata payload) external payable {
  require(msg.value==denomination,"denomination");insert(cm,payload);
 }
 function transact(uint[2] calldata a,uint[2][2] calldata b,uint[2] calldata c,uint[4] calldata signals,bytes calldata payload) external {
  require(knownRoots[signals[0]],"root"); require(!spent[signals[1]],"spent");
  require(signals[3] <= type(uint160).max,"address");
  require(verifier.verifyProof(a,b,c,signals),"proof");
  spent[signals[1]]=true;
  if(signals[3]==0){insert(signals[2],payload);}
  else {
   require(signals[2]==0 && payload.length==0,"withdrawal");
   (bool ok,)=address(uint160(signals[3])).call{value:denomination}("");require(ok,"payment");
   emit Withdrawal(signals[1],address(uint160(signals[3])));
  }
 }
}
