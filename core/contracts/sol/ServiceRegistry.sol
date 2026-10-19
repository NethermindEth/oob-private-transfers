// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
/// Recovery directory of OOB providers (protocol v2). A provider P is identified by its
/// own account key: sid = SHA-256(64-byte uncompressed secp256k1 public key of P's account, without 0x04). There is
/// no separate governance party and no key rotation: only P's account writes P's entry, and P has ONE Ed25519 signing
/// key (receipts, manifests), fixed at registration. The entry keeps, with history by block:
///  - P's Ed25519 key and account, and its current service endpoint (updatable by P);
///  - holder assignments gamma -> (holder identities of coordinates 1..n, thresholds k, n, q, activation block);
///  - an endpoint record per holder identity (latest wins), updatable without a new assignment;
///  - optionally "continues P_old after epoch startEpoch-1": a replacement P' of a failed provider declares whose
///    epochs it reconstructs and continues P_old's numbering (its first anchor must be startEpoch; EpochAnchor).
/// Readers use the assignment active at an anchor's block for that epoch.
contract ServiceRegistry {
 struct Service { address account; bytes32 opKey; bytes32 continuesSid; uint64 startEpoch; uint64 fromBlock; }
 struct Assignment { bytes32[] keys; uint16 k; uint16 q; uint64 fromBlock; }
 struct RegParams { uint16 k; uint16 q; bytes32 continuesSid; uint64 startEpoch; }
 uint256 public constant MAX_N = 255;
 mapping(bytes32=>Service) internal services;
 mapping(bytes32=>string) internal endpoints;          // current service endpoint (P may move it)
 mapping(bytes32=>Assignment[]) internal assignments;  // index = assignment version gamma
 mapping(bytes32=>mapping(bytes32=>string)) internal holderUrl;      // (sid, holder identity) -> endpoint
 mapping(bytes32=>mapping(bytes32=>uint64)) internal holderUrlBlock; // block of the last endpoint update
 mapping(bytes32=>mapping(bytes32=>bool)) internal knownHolder;      // identity appears in some assignment of sid
 event Registered(bytes32 indexed sid,address account,bytes32 opKey,string endpoint,bytes32 continuesSid,uint64 startEpoch);
 event EndpointSet(bytes32 indexed sid,string endpoint);
 event AssignmentSet(bytes32 indexed sid,uint64 gamma,bytes32[] holderKeys,uint16 k,uint16 n,uint16 q);
 event HolderEndpoint(bytes32 indexed sid,bytes32 indexed holderKey,string url);

 function _onlyP(bytes32 sid) internal view {
  Service storage s=services[sid];
  require(s.account!=address(0) && msg.sender==s.account,"only the provider's own account");
 }
 /// Invalid configurations are rejected: 1 <= k <= q <= n <= MAX_N, distinct nonzero identities.
 function _checkAssignment(bytes32[] calldata keys,string[] calldata urls,uint16 k,uint16 q) internal pure {
  uint256 n=keys.length;
  require(n>=1 && n<=MAX_N,"n out of range");
  require(k>=1,"k < 1");
  require(q>=k,"q < k");
  require(q<=n,"q > n");
  require(urls.length==n,"urls length != n");
  for(uint256 i=0;i<n;i++){require(keys[i]!=bytes32(0),"holder");for(uint256 j=0;j<i;j++)require(keys[i]!=keys[j],"distinct holders");}
 }
 function _setAssignment(bytes32 sid,bytes32[] calldata keys,string[] calldata urls,uint16 k,uint16 q) internal {
  _checkAssignment(keys,urls,k,q);
  Assignment storage a=assignments[sid].push();
  a.keys=keys;a.k=k;a.q=q;a.fromBlock=uint64(block.number);
  for(uint256 i=0;i<keys.length;i++){
   knownHolder[sid][keys[i]]=true;
   if(bytes(urls[i]).length>0){holderUrl[sid][keys[i]]=urls[i];holderUrlBlock[sid][keys[i]]=uint64(block.number);emit HolderEndpoint(sid,keys[i],urls[i]);}
   else require(bytes(holderUrl[sid][keys[i]]).length>0,"new holder needs an endpoint");
  }
  emit AssignmentSet(sid,uint64(assignments[sid].length-1),keys,k,uint16(keys.length),q);
 }
 function register(bytes calldata accountPub,bytes32 opKey,bytes32[] calldata holderKeys,string[] calldata urls,
                   string calldata ep,RegParams calldata rp) external returns(bytes32 sid){
  require(accountPub.length==64,"accountPub");
  require(address(uint160(uint256(keccak256(accountPub))))==msg.sender,"account key/sender mismatch");
  sid=sha256(accountPub);
  require(services[sid].account==address(0),"exists");
  require(opKey!=bytes32(0),"signing key");
  require(rp.continuesSid!=sid,"cannot continue itself");
  require(rp.continuesSid!=bytes32(0) || rp.startEpoch==0,"a fresh provider starts at epoch 0");
  require(rp.continuesSid==bytes32(0) || services[rp.continuesSid].account!=address(0),"continued provider not registered");
  services[sid]=Service(msg.sender,opKey,rp.continuesSid,rp.startEpoch,uint64(block.number));
  endpoints[sid]=ep;
  _setAssignment(sid,holderKeys,urls,rp.k,rp.q);
  emit Registered(sid,msg.sender,opKey,ep,rp.continuesSid,rp.startEpoch);
 }
 function setEndpoint(bytes32 sid,string calldata ep) external {
  _onlyP(sid);
  endpoints[sid]=ep;
  emit EndpointSet(sid,ep);
 }
 /// P installs a new holder assignment (replace failed holders, or change k, n, q). Applies to manifests sealed and
 /// anchors written from this block on; earlier anchors stay verifiable against the assignment active at their block.
 /// An empty url keeps the identity's current endpoint record.
 function setAssignment(bytes32 sid,bytes32[] calldata holderKeys,string[] calldata urls,uint16 k,uint16 q) external {
  _onlyP(sid);
  _setAssignment(sid,holderKeys,urls,k,q);
 }
 /// P moves a holder identity to a new endpoint without a new assignment (all epochs it holds, old and new).
 function setHolderEndpoint(bytes32 sid,bytes32 holderKey,string calldata url) external {
  _onlyP(sid);
  require(knownHolder[sid][holderKey],"unknown holder identity");
  require(bytes(url).length>0,"empty endpoint");
  holderUrl[sid][holderKey]=url;holderUrlBlock[sid][holderKey]=uint64(block.number);
  emit HolderEndpoint(sid,holderKey,url);
 }
 /// (signing key, account, 0, account): compatibility tuple; the key version is always 0.
 function operator(bytes32 sid) external view returns(bytes32 opKey,address opEOA,uint64 version,address account){
  Service storage s=services[sid];return (s.opKey,s.account,0,s.account);
 }
 function lineage(bytes32 sid) external view returns(bytes32 continuesSid,uint64 startEpoch,uint64 fromBlock){
  Service storage s=services[sid];return (s.continuesSid,s.startEpoch,s.fromBlock);
 }
 function startEpoch(bytes32 sid) external view returns(uint64){return services[sid].startEpoch;}
 function endpoint(bytes32 sid) external view returns(string memory){return endpoints[sid];}
 function assignmentCount(bytes32 sid) external view returns(uint256){return assignments[sid].length;}
 function assignmentAt(bytes32 sid,uint256 gamma) external view
  returns(bytes32[] memory keys,uint16 k,uint16 n,uint16 q,uint64 fromBlock){
  Assignment storage a=assignments[sid][gamma];return (a.keys,a.k,uint16(a.keys.length),a.q,a.fromBlock);
 }
 function holderEndpoint(bytes32 sid,bytes32 holderKey) external view returns(string memory url,uint64 fromBlock){
  return (holderUrl[sid][holderKey],holderUrlBlock[sid][holderKey]);
 }
 function holderEndpoints(bytes32 sid,bytes32[] calldata keys) external view returns(string[] memory urls){
  urls=new string[](keys.length);
  for(uint256 i=0;i<keys.length;i++)urls[i]=holderUrl[sid][keys[i]];
 }
}
