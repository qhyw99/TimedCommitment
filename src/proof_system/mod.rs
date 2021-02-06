use crate::*;
use crate::timeline_calculator::*;
use curv::cryptographic_primitives::proofs::{sigma_dlog,
                                             sigma_correct_homomorphic_elgamal_enc,
                                             sigma_ec_ddh};
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::{ECDDHProof, ECDDHWitness, ECDDHStatement};
use bulletproof::proofs::range_proof::RangeProof;
use curv::elliptic::curves::traits::ECPoint;

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
        return Secret { mtl, m };
    }
}

struct MirrorTLProof(ECDDHProof<PedersenGroup>,
                     ECDDHProof<PedersenGroup>);

struct UniquenessProof {
    p_eq: (ECDDHProof<PedersenGroup>,
           ECDDHProof<PedersenGroup>),
    p_range: RangeProof,
}

struct CommitmentEqProof(ECDDHProof<PedersenGroup>);

pub struct Proofs {
    m: MirrorTLProof,
    u: UniquenessProof,
    c: CommitmentEqProof,
}

pub fn proof(state: Statement, secret: Secret) -> Proofs {
    let mp: ECDDHProof<PedersenGroup> = sigma_ec_ddh::ECDDHProof::prove(
        &ECDDHWitness {
            x: secret.mtl
        },
        &ECDDHStatement {
            g1: PedersenGroup::generator(),
            h1: state.b_aux,
            g2: state.b_aux,
            h2: state.b,
        });
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