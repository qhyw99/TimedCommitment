use crate::*;
use crate::timeline_calculator::*;

pub struct Statement {
    mtl: MirrorTlPublic,
    C: PedersenGroup,
    B: PedersenGroup,
    b: PedersenGroup,
    b_aux: PedersenGroup,
}

impl Statement {
    pub fn new(mtl: MirrorTlPublic,
               four_element_tuple: (PedersenGroup,
                                    PedersenGroup,
                                    PedersenGroup,
                                    PedersenGroup)) -> Self {
        return Statement {
            mtl,
            C: four_element_tuple.0,
            B: four_element_tuple.1,
            b: four_element_tuple.2,
            b_aux: four_element_tuple.3,
        };
    }
}

pub struct Secret {
    mtl: MirrorTlSecret,
    m: RSAGroup,
}

impl Secret {
    pub fn new(mtl: MirrorTlSecret, m: RSAGroup) -> Self {
        return Secret { mtl, m, };
    }
}

struct MirrorTLProof {}

struct UniquenessProof {}

struct CommitmentEqProof {}

pub struct Proofs {
    m: MirrorTLProof,
    u: UniquenessProof,
    c: CommitmentEqProof,
}

pub fn proof(state: Statement, secret: Secret) -> Proofs {
    let m = MirrorTLProof {};
    let u = UniquenessProof {};
    let c = CommitmentEqProof {};
    let proofs = Proofs { m, u, c };
    return proofs;
}

pub fn verify(_p: Proofs) -> bool {
    let result = true;
    return result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_verify() {
        // let p = proof();
        // assert!(verify(p));
    }
}