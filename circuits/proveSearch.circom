pragma circom 2.0.0;

include "./MerkleProofChecker.circom";
include "node_modules/circomlib/circuits/bitify.circom";

template SearchByUserAndPostNumber(depth) {
    signal input query;
    signal input message[8]; // We have a 254 byte message, which fits in 8 2^254 bit field elements (note this includes a 64 byte ecdsa signature, leaving 190 bytes for actual text)
    signal input root;
    signal input pathElements[depth];
    signal input previosPathElements[depth];

    // we hash the message together to get the leaf node in the merkle tree
    component hasher = Poseidon(8);
    for (var i = 0; i < 8; i++) {
        hasher.inputs[i] <== message[i];
    }

    // we decompose the query into the path of the merkle tree
    component bitifier = Num2Bits(depth);
    bitifier.in <== query;

    component mpc = MerkleProofChecker(depth);
    for (var i = 0; i < depth; i++) {
        mpc.pathIndices[i] <== bitifier.out[i];
        mpc.pathElements[i] <== pathElements[i];
    }
    mpc.leaf <== hasher.out;
    mpc.root <== root;
}

// We are using a sparse merkle tree with key = username | postNumber
// We limit users to 2^40 ~= 1,000,000,000,000 posts, and usernames are ethereum adresses of 20 bytes.
// This gives our key a bit length of 40 + 20 * 8 = 200, which fits within a standard field element
component main { public [query, root, message ] } = SearchByUserAndPostNumber(200);