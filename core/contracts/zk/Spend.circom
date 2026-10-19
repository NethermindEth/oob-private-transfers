pragma circom 2.1.6;
include "../build/circomlib/poseidon.circom";
include "../build/circomlib/comparators.circom";

template Spend(depth) {
 signal input root;
 signal input nullifier;
 signal input newCommitment;
 signal input withdrawTo;
 signal input secret;
 signal input pkHash;   // Poseidon2(pk_R.x, pk_R.y) of the spent note's address (A11)
 signal input seed;
 signal input payloadHash;
 signal input newOwner;
 signal input newSeed;
 signal input newPayloadHash;
 signal input siblings[depth];
 signal input directions[depth];
 // A11: address (ob, pk_R), ob = Poseidon1(secret); owner field = Poseidon2(ob, pkHash)
 component ob = Poseidon(1); ob.inputs[0] <== secret;
 component owner = Poseidon(2); owner.inputs[0] <== ob.out; owner.inputs[1] <== pkHash;
 component leaf = Poseidon(3);
 leaf.inputs[0] <== owner.out; leaf.inputs[1] <== seed; leaf.inputs[2] <== payloadHash;
 component nf = Poseidon(2); nf.inputs[0] <== secret; nf.inputs[1] <== seed;
 nullifier === nf.out;
 signal nodes[depth+1]; nodes[0] <== leaf.out;
 signal left[depth]; signal right[depth];
 component hashes[depth];
 for (var i=0; i<depth; i++) {
  directions[i]*(directions[i]-1) === 0;
  left[i] <== nodes[i] + directions[i]*(siblings[i]-nodes[i]);
  right[i] <== siblings[i] + directions[i]*(nodes[i]-siblings[i]);
  hashes[i] = Poseidon(2); hashes[i].inputs[0] <== left[i]; hashes[i].inputs[1] <== right[i];
  nodes[i+1] <== hashes[i].out;
 }
 root === nodes[depth];
 component outputNote = Poseidon(3);
 outputNote.inputs[0] <== newOwner; outputNote.inputs[1] <== newSeed; outputNote.inputs[2] <== newPayloadHash;
 component transfer = IsZero(); transfer.in <== withdrawTo;
 newCommitment === transfer.out * outputNote.out;
}
component main {public [root, nullifier, newCommitment, withdrawTo]} = Spend(32);
