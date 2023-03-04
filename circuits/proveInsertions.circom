pragma circom 2.0.0;

include "./MerkleProofChecker.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/gates.circom";

// Inserts posts into a sparse merkle tree
template ProveInsertion(name_length, message_length) {
    var levels = name_length + message_length;
    signal input key;
    signal input siblingValue;
    signal input siblingAuditPath[levels];

    signal input oldRoot;
    signal input newRoot;
    signal input auditPath[levels];
    signal input newValue;

    // Verify that the key either represents the first message for a user, or the previous message from that user is non-zero
    component keybits = Num2Bits(levels);
    keybits.in <== key;
    component messageIndex = Bits2Num(message_length);
    for (var i = 0; i < message_length; i++) {
        messageIndex.in[i] <== keybits.out[name_length + i];
    }
    component isFirstMessage = IsZero();
    isFirstMessage.in <== messageIndex.out;

    component siblingKeybits = Num2Bits(levels); // TODO: can constraints be reused between siblingKeybits and keybits
    siblingKeybits.in <== key-1; // Note, if this does not refer to the same user as keybits, the constraints pass due to isFirstMessage being true

    component siblingMpc = MerkleProofCalculator(levels);
    siblingMpc.leaf <== 0;
    for (var i = 0; i < levels; i++) {
        siblingMpc.pathElements[i] <== siblingAuditPath[i];
        siblingMpc.pathIndices[i] <== siblingKeybits.out[i];
    }
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component prevMsgIsZero = IsEqual();
    prevMsgIsZero.in[0] <== siblingMpc.root;
    prevMsgIsZero.in[1] <== oldRoot;

    component validPosition = OR();
    validPosition.a <== isFirstMessage.out;
    validPosition.b <== 1 - prevMsgIsZero.out;
    validPosition.out === 1;

    // Verify that 0 is at the key in the old tree
    component wasZero = MerkleProofChecker(levels);
    wasZero.leaf <== 0;
    wasZero.root <== oldRoot;
    for (var i = 0; i < levels; i++) {
        wasZero.pathElements[i] <== keybits.out[i];
        wasZero.pathIndices[i] <== auditPath[i];
    }

    // Verify that the new value is at the key in the new tree, while the rest of the tree is held constant
    component isInserted = MerkleProofChecker(levels);
    isInserted.leaf <== newValue;
    isInserted.root <== newRoot;
    for (var i = 0; i < levels; i++) {
        isInserted.pathElements[i] <== keybits.out[i];
        isInserted.pathIndices[i] <== auditPath[i];
    }
}

component main { public [oldRoot, newRoot ] } = ProveInsertion(40, 160);