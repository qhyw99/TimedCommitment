use crate::*;
use crate::timeline_calculator::*;
use curv::cryptographic_primitives::proofs::{sigma_correct_homomorphic_elgamal_enc,
                                             sigma_ec_ddh};
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::{ECDDHProof, ECDDHWitness, ECDDHStatement};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::{HomoELGamalProof, HomoElGamalStatement, HomoElGamalWitness};
use bulletproof::proofs::range_proof_wip::*;
use curv::elliptic::curves::traits::ECPoint;
use std::borrow::Borrow;

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
    ECDDHProof<PedersenGroup>,
    ECDDHProof<PedersenGroup>,
);

struct UniquenessProof {
    p_eq: (ECDDHProof<PedersenGroup>,
           ECDDHProof<PedersenGroup>),
    p_range: (RangeProofWIP, StatementRP),
}

struct CommitmentEqProof(
    HomoELGamalProof<PedersenGroup>
);

pub struct Proofs {
    m: MirrorTLProof,
    u: UniquenessProof,
    c: CommitmentEqProof,
}

pub fn proof(master_tl: MasterTl, state: Statement, secret: Secret) -> Proofs {
    let mtl: (&ZPhi, &RSAGroup, &RSAGroup) = secret.mtl.as_ref();
    let r = mtl.1.as_ref();
    let r_aux = mtl.2.as_ref();
    let a = mtl.0.as_ref();

    let mtl: (&RSAGroup, &RSAGroup, &RSAGroup) = state.mtl.as_ref();
    let h = mtl.0.as_ref();
    let r_k0 = mtl.1.as_ref();
    let r_k1 = mtl.2.as_ref();

    let master_tl: (&RSAGroup, &RSAGroup, &RSAGroup, &RSAGroup, &RSAGroup) =
        master_tl.as_ref();
    let generator = master_tl.0.as_ref();
    let m_0 = master_tl.3.as_ref();
    let m_1 = master_tl.4.as_ref();
    //Well-formed-ness proof
    //witness: a  Statement:g h m_0 r_k0
    let mut vec_int = vec![generator, h, m_0, r_k0, m_1, r_k1];
    let vec_group: Vec<PedersenGroup> = vec_int.into_iter().map(|x| {
        PedersenGroup::generator() * (x.into() as PedersenScaler)
    }).collect();
    //let s = vec_group.into_raw_parts();
    let slice_group = vec_group.as_ptr();

    let m_eq_0: ECDDHProof<PedersenGroup> = sigma_ec_ddh::ECDDHProof::prove(
        &ECDDHWitness {
            x: a.into()
        },
        unsafe {
            &ECDDHStatement {
                g1: slice_group.add(0).read(),
                h1: slice_group.add(1).read(),
                g2: slice_group.add(2).read(),
                h2: slice_group.add(3).read(),
            }
        });
    //witness: a Statement:m_0 r_k0 m_1 r_k1
    let m_eq_1: ECDDHProof<IntegerGroup> = sigma_ec_ddh::ECDDHProof::prove(
        &ECDDHWitness {
            x: a.into()
        },
        unsafe {
            &ECDDHStatement {
                g1: slice_group.add(2).read(),
                h1: slice_group.add(3).read(),
                g2: slice_group.add(4).read(),
                h2: slice_group.add(5).read(),
            }
        });

    //Uniqueness proof:
    //b b_aux g
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
    //B b g
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

    let usize_length = M.bit_length() + 1;
    //2 ^ length
    let u_l = BigInt::from(2).pow(usize_length as u32);

    //secret = r - M + 2 ^ length in [0,2^length]  AND r in [0,2^length]
    let mut v_secret: Vec<PedersenScaler> = vec![];
    v_secret.push((r + &u_l - M.clone()).borrow().into()); //[g^(u_l)*b]/(g^M) commitment
    v_secret.push(r.borrow().into()); //b
    v_secret.push((r_aux + &u_l - M.clone()).borrow().into()); //[g^(u_l)*b_aux]/(g^M)
    v_secret.push(r_aux.borrow().into()); //b_aux
    let blinding = [BigInt::zero().borrow().into(); 4];
    let seed = BigInt::from("zhang_xi".as_bytes());

    //H直接变为单位元
    let stmt = StatementRP::generate_bases(&seed, 4, usize_length);
    let p_range = RangeProofWIP::prove(stmt.clone(), v_secret, &blinding[..]);

    //Commitment Proof
    // want to proof:
    // statement: C = g^m * h^r; b = g^r
    // witness: (m,r)
    // primitive:
    // statement: D = xH + rG; E = xG
    // witness: (x,r)
    let hes = HomoElGamalStatement {
        G: (),
        H: (),
        Y: (),
        D: (),
        E: (),
    };
    let hew = HomoElGamalWitness {
        r: (),
        x: (),
    };
    let p_c_eq = HomoELGamalProof::prove(hew.borrow(), hes.borrow());

    //Construct proof
    let m = MirrorTLProof(m_eq_0, m_eq_1);
    let u = UniquenessProof {
        p_eq: (u_p_eq_0, u_p_eq_1),
        p_range: (p_range, stmt),
    };
    let c = CommitmentEqProof(p_c_eq);

    let proofs = Proofs { m, u, c };
    return proofs;
}

pub fn verify(master_tl: MasterTl, state: Statement, proofs: Proofs) -> bool {
    let mtl: (&RSAGroup, &RSAGroup, &RSAGroup) = state.mtl.as_ref();
    let h = mtl.0.as_ref();
    let r_k0 = mtl.1.as_ref();
    let r_k1 = mtl.2.as_ref();
    //Well-formed-ness verify
    proofs.m.0.verify(&ECDDHStatement {
        g1: PedersenGroup::generator(),
        h1: h.into(),
        g2: master_tl.m_0,
        h2: r_k0.into(),
    });

    proofs.m.1.verify(&ECDDHStatement {
        g1: master_tl.m_0,
        h1: r_k0.into(),
        g2: master_tl.m_1,
        h2: r_k1.into(),
    });
    //Uniqueness verify
    proofs.u.p_eq.0.verify(&ECDDHStatement {
        g1: PedersenGroup::generator(),
        h1: state.b_aux,
        g2: state.b_aux,
        h2: state.b,
    });
    proofs.u.p_eq.1.verify(
        &ECDDHStatement {
            g1: PedersenGroup::generator(),
            h1: state.b,
            g2: state.b,
            h2: state.B,
        }
    );
    let usize_length = M.bit_length() + 1;
    //2 ^ length
    let u_l = BigInt::from(2).pow(usize_length as u32);
    let u_l_f: PedersenScaler = (&u_l).into();

    let m_f: PedersenScaler = (&M as &BigInt).into();

    let generator = PedersenGroup::generator();
    let u_l_g = generator * u_l_f;
    let m_g = generator * m_f;

    let mut v_commit: Vec<PedersenGroup> = vec![];
    v_commit.push((&u_l_g - &m_g + &state.b)); //(u_l)g + b - Mg
    v_commit.push(state.b.clone()); //b
    v_commit.push((&u_l_g - &m_g + &state.b_aux)); //(u_l)g + b_aux - Mg
    v_commit.push(state.b_aux.clone()); //b_aux

    let result2 =
        proofs.u.p_range.0.verify(
            proofs.u.p_range.1, v_commit.as_slice());


    match result2 {
        Ok(()) => {
            return true;
        }
        Err(e) => {
            println!("{:?}", e);
            return false;
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