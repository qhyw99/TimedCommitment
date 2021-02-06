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

struct MirrorTLProof(
    // ECDDHProof<PedersenGroup>,
    // ECDDHProof<PedersenGroup>
);

struct UniquenessProof {
    p_eq: (ECDDHProof<PedersenGroup>,
           ECDDHProof<PedersenGroup>),
    //p_range: (RangeProof,RangeProof)
}

struct CommitmentEqProof(
    // ECDDHProof<PedersenGroup>
);

pub struct Proofs {
    m: MirrorTLProof,
    u: UniquenessProof,
    c: CommitmentEqProof,
}

pub fn proof(state: Statement, secret: Secret) -> Proofs {
    let mtl = secret.mtl.as_ref();
    let r = mtl.1.as_ref();
    let r_aux = mtl.2.as_ref();
    let a = mtl.0.as_ref();
    let u_p_eq_0: ECDDHProof<PedersenGroup> = sigma_ec_ddh::ECDDHProof::prove(
        &ECDDHWitness {
            x: r_aux.into()
        },
        &ECDDHStatement {
            g1: PedersenGroup::generator(),
            h1: state.b_aux,
            g2: state.b_aux,
            h2: state.b,
        });
    let u_p_eq_1: ECDDHProof<PedersenGroup> = sigma_ec_ddh::ECDDHProof::prove(
        &ECDDHWitness {
            x: r.into()
        },
        &ECDDHStatement {
            g1: PedersenGroup::generator(),
            h1: state.b,
            g2: state.b,
            h2: state.B,
        });
    let m = MirrorTLProof();
    let u = UniquenessProof {
        p_eq:(u_p_eq_0,u_p_eq_1),
        //p_range: RangeProof::prove()
    };
    let c = CommitmentEqProof();
    let proofs = Proofs { m, u, c };
    return proofs;
}

pub fn verify(proofs: Proofs) -> bool {

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