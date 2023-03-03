include "./node_modules/circomlib/circuits/smt/smtprocessor.circom"

// Inserts posts into a sparse merkle tree
template proveInsertions(post_count, levels) {
    signal input oldRoot;
    signal input siblings[levels];
    signal input key;
    signal input newValue;

    signal output newRoot;

    component inserter = SMTProcessor(levels);
    // The SMT processors can implement different functions dependening on the values of `fnc`.
    // [1, 0] means insert, and by constraining the values to constants we are only allowing inserts
    inserter.fnc[0] <== 1;
    inserter.fnc[1] <== 0;

    // The old value is zero because we are always inserting into the tree, never deleting or editing - this is crucial for long term data integrity
    inserter.oldValue <== 0;
    // Specifies that the old value is 0 (TODO: shouldn't this just be determined by the value of old? We can output equality in 2 constraints)
    inserter.isOld0 <== 1;

    // There is only one relevant position for an insertion - TODO: pare down the underlying construction so we don't need to compare two keys?
    inserter.newKey <== key;
    inserter.oldKey <== key;

    inserter.newValue <== newValue;
    inserter.oldRoot <== oldRoot;
    for (var i = 0; i < levels; i++) {
        inserter.siblings[i] <== siblings[i];
    }

    newRoot <== inserter.newRoot;
}

// A sparse merkle tree has a depth equal to the bit length of its keys.
// In this case, our keys are an ethereum address (20 bytes) and a tweet style message (140 bytes).
component main { public [oldRoot] } = proveInsertions(100, 20 * 8 + 140 * 8)