// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
interface IServiceRegistry {
 function operator(bytes32 sid) external view returns(bytes32,address,uint64,address);
 function startEpoch(bytes32 sid) external view returns(uint64);
}
/// Write-once anchors (sid,e) carrying the canonical manifest M_e and certificate rho_avail,e in calldata/event
/// on chain. Only the registered account of provider sid may write; anyone may read.
/// Epoch numbers per sid are consecutive: the first anchor is e = startEpoch(sid) (0 for a fresh provider; last_P + 1
/// for a replacement P' that declared "continues P" in the registry) and every later one is e == last_e(sid) + 1.
/// The contract does NOT verify Ed25519 signatures: Certified(sid,e) is decided off-chain by every reader
/// (final anchor AND manifest signed by P's registered key AND pinning the assignment gamma active at the anchor block AND q valid distinct acks); otherwise VOID.
contract EpochAnchor {
 struct Anchor { bytes32 hManifest; bytes32 hCert; uint64 blockNumber; }
 IServiceRegistry public immutable registry;
 mapping(bytes32=>mapping(uint64=>Anchor)) internal anchors;
 mapping(bytes32=>uint64[]) internal epochList;
 event Anchored(bytes32 indexed sid,uint64 indexed e,bytes32 hManifest,bytes32 hCert,bytes manifest,bytes cert);
 constructor(address r){registry=IServiceRegistry(r);}
 function anchor(bytes32 sid,uint64 e,bytes calldata manifest,bytes calldata cert) external {
  (,address op,,)=registry.operator(sid);
  require(op!=address(0) && msg.sender==op,"only operator");
  require(manifest.length>0 && cert.length>0,"empty");
  require(anchors[sid][e].blockNumber==0,"write-once");
  uint256 n=epochList[sid].length;
  require(n==0 ? e==registry.startEpoch(sid) : e==epochList[sid][n-1]+1,"epochs must be consecutive (first = startEpoch, then last+1)");
  bytes32 hm=sha256(bytes.concat("OOB-manifest-v2",manifest));
  bytes32 hc=sha256(bytes.concat("OOB-cert-v1",cert));
  anchors[sid][e]=Anchor(hm,hc,uint64(block.number));epochList[sid].push(e);
  emit Anchored(sid,e,hm,hc,manifest,cert);
 }
 function get(bytes32 sid,uint64 e) external view returns(bytes32,bytes32,uint64){Anchor storage a=anchors[sid][e];return (a.hManifest,a.hCert,a.blockNumber);}
 function epochs(bytes32 sid) external view returns(uint64[] memory){return epochList[sid];}
}
