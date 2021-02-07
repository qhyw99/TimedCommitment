use crate::*;
use crate::timeline_calculator::*;
use curv::cryptographic_primitives::proofs::{sigma_dlog,
                                             sigma_correct_homomorphic_elgamal_enc,
                                             sigma_ec_ddh};
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::{ECDDHProof, ECDDHWitness, ECDDHStatement};
use bulletproof::proofs::range_proof_wip::*;
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
    p_range: RangeProofWIP
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
    let mtl: (&ZPhi, &RSAGroup, &RSAGroup) = secret.mtl.as_ref();
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
    let usize_length = M.bit_length();
    let length = BigInt::from(usize_length as u32);
    //2 ^ length
    let u_l = BigInt::from(2).powm(&length, &M);
    //secret = r - M + 2 ^ length in [0,2^length]  AND r in [0,2^length]
    let mut v_secret = vec![];
    v_secret.push((r - &M + u_l).into());
    v_secret.push(r.into());
    let blinding = [BigInt::zero().into(); 2];
    let seed = BigInt::from("zhang_xi".as_bytes());

    let mut stmt = StatementRP::generate_bases(&seed, 1, usize_length);
    stmt.H = PedersenGroup::generator().scalar_mul(BigInt::from(0).into());
    //blinding ->one
    let p_range = RangeProofWIP::prove(stmt, v_secret, &blinding[..]);
    let m = MirrorTLProof();
    let u = UniquenessProof {
        p_eq: (u_p_eq_0, u_p_eq_1),
        p_range
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