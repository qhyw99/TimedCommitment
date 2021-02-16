use super::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::BigInt;
use curv::cryptographic_primitives::commitments::traits::Commitment;

fn hash_commit(m:&BigInt,r:&BigInt) ->BigInt{
    HashCommitment::create_commitment_with_user_defined_randomness(m,r)
}
pub fn commit_message(m:&BigInt,r:&BigInt) -> BigInt {
    hash_commit(m,r)
}
pub fn reveal_message(m:&BigInt,r:&BigInt,C:BigInt) ->bool{
    return hash_commit(m,r) == C;
}