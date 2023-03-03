pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";


// if s == 0 returns [in[0], in[1]]
// if s == 1 returns [in[1], in[0]]
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}

// Verifies that merkle proof is correct for given merkle root and a leaf
// pathIndices input is an array of 0/1 selectors telling whether given pathElement is on the left or right side of merkle path
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component selectors[levels];
    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i - 1].out;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];
    }

    root === hashers[levels - 1].out;
}

// Note, the above code is directly copied from https://github.com/ChihChengLiang/poseidon-tornado/blob/main/circuits/merkleTree.circom

template SearchByUserAndPostNumber(depth) {
    signal input query;
    signal input message[8]; // We have a 254 byte message, which fits in 8 2^254 bit field elements (note this includes a 64 byte ecdsa signature, leaving 190 bytes for actual text)
    signal input root;
    signal input pathElements[depth];

    // we hash the message together to get the leaf node in the merkle tree
    component hasher = Poseidon(8);
    for (var i = 0; i < 8; i++) {
        hasher.inputs[i] <== message[i];
    }

    // we decompose the query into the path of the merkle tree
    signal pathIndices;
    component bitifier = Num2Bits(depth);
    bitifier.in <== query;

    component mtc = MerkleTreeChecker(depth);
    for (var i = 0; i < depth; i++) {
        mtc.pathIndices[i] <== bitifier.out[i];
        mtc.pathElements[i] <== pathElements[i];
    }
    mtc.leaf <== hasher.out;
    mtc.root <== root;
}

// We are using a sparse merkle tree with key = username | postNumber
// We limit users to 2^40 ~= 1,000,000,000,000 posts, and usernames are ethereum adresses of 20 bytes.
// This gives our key a bit length of 40 + 20 * 8 = 200, which fits within a standard field element
component main { public [query, root, message ] } = SearchByUserAndPostNumber(200);