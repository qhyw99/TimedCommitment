use crate::*;
use crate::timeline_calculator::*;

pub struct Statement {
    mtl: MirrorTlPublic,
    b_aux: PedersenGroup,
    b: PedersenGroup,
    B: PedersenGroup,
    C: PedersenGroup,
}

pub struct Secret {
    mtl: MirrorTlSecret,
    m: RSAGroup,
}

struct MirrorTLProof {}

struct UniquenessProof {}

struct CommitmentEqProof {}

pub struct Proofs {
    m: MirrorTLProof,
    u: UniquenessProof,
    c: CommitmentEqProof,
}

pub fn proof() -> Proofs {
    let m = MirrorTLProof{};
    let u = UniquenessProof{};
    let c = CommitmentEqProof{};
    let proofs = Proofs {m,u,c};
    return proofs;
}
pub fn verify(_p: Proofs) -> bool {
    let result = true;
    return result;
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn proof_verify(){
        // let p = proof();
        // assert!(verify(p));
    }
}