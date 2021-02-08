use crate::*;
use crate::timeline_calculator::*;
use curv::cryptographic_primitives::proofs::{sigma_dlog,
                                             sigma_correct_homomorphic_elgamal_enc,
                                             sigma_ec_ddh};
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::{ECDDHProof, ECDDHWitness, ECDDHStatement};
use bulletproof::proofs::range_proof_wip::*;
use curv::elliptic::curves::traits::ECPoint;

#[derive(Clone)]
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
    p_range: (RangeProofWIP, StatementRP),
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
    let mut v_secret: Vec<PedersenScaler> = vec![];
    v_secret.push((r + &u_l - M.clone()).into()); //[g^(u_l)*b]/(g^M) commitment
    v_secret.push(r.into()); //b
    v_secret.push((r_aux + &u_l - M.clone()).into()); //[g^(u_l)*b_aux]/(g^M)
    v_secret.push(r_aux.into()); //b_aux
    let blinding = [BigInt::zero().into(); 4];
    let seed = BigInt::from("zhang_xi".as_bytes());

    //H直接变为单位元
    let stmt = StatementRP::generate_bases(&seed, 4, usize_length);
    let p_range = RangeProofWIP::prove(stmt.clone(), v_secret, &blinding[..]);

    let m = MirrorTLProof();
    let u = UniquenessProof {
        p_eq: (u_p_eq_0, u_p_eq_1),
        p_range: (p_range, stmt),
    };
    let c = CommitmentEqProof();
    let proofs = Proofs { m, u, c };
    return proofs;
}

pub fn verify(state: Statement, proofs: Proofs) -> bool {
    let usize_length = M.bit_length();
    let length = BigInt::from(usize_length as u32);
    //2 ^ length
    let u_l = BigInt::from(2).powm(&length, &M);
    let u_l_f: PedersenScaler = u_l.into();

    let m_f :PedersenScaler = M.clone().into();

    let generator = PedersenGroup::generator();
    let u_l_g = generator * u_l_f ;
    let m_g = generator * m_f;
    let common = &u_l_g - &m_g;


    let mut v_commit: Vec<PedersenGroup> = vec![];
    v_commit.push((&u_l_g - &m_g + &state.b)); //(u_l)g + b - Mg
    v_commit.push(state.b.clone()); //b
    v_commit.push((&u_l_g - &m_g + &state.b_aux)); //(u_l)g + b_aux - Mg
    v_commit.push(state.b_aux.clone()); //b_aux


    let result1=
        proofs.u.p_range.0.aggregated_verify(
            proofs.u.p_range.1, v_commit.as_slice());

    // let mtl: (&RSAGroup, &RSAGroup, &RSAGroup) = secret.mtl.as_ref();
    // let h = mtl.0.as_ref();
    // let r_k0 = mtl.1.as_ref();
    // let r_k1 = mtl.2.as_ref();
    // proofs.u.p_eq.0.verify(&ECDDHStatement {});
    // proofs.u.p_eq.1.verify();

    match result1 {
        Ok(()) => {
            return true
        },
        Err(..) => {
            return false
        }
    }
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