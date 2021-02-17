#![allow(non_snake_case)]

use crate::*;
//use crate::timeline_calculator::*;
use curv::cryptographic_primitives::proofs::{ProofError};
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::{ECDDHProof, ECDDHWitness, ECDDHStatement};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::{HomoELGamalProof, HomoElGamalStatement, HomoElGamalWitness};
use bulletproof::proofs::range_proof_wip::*;
use curv::elliptic::curves::traits::{ECPoint};
use std::borrow::Borrow;
use std::ops::Div;

#[derive(Clone)]
pub struct Statement {
    mtl: timeline_calculator::MirrorTlPublic,
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
    pub fn as_ref(&self) -> (&timeline_calculator::MirrorTlPublic, &PedersenGroup, &PedersenGroup, &PedersenGroup, &PedersenGroup)
    {
        return (&self.mtl, &self.C, &self.B, &self.b, &self.b_aux);
    }
    pub fn get_message_commitment(&self) -> PedersenGroup {
        return self.C.clone();
    }
    pub fn get_blind_commitment(&self) -> PedersenGroup {
        return self.b.clone();
    }
    pub fn get_rk0(&self) -> RSAGroup {
        return self.mtl.r_k0.clone();
    }
}

#[derive(Clone)]
pub struct Secret {
    mtl: timeline_calculator::MirrorTlSecret,
    m: RSAGroup,
}

impl Secret {
    pub fn new(mtl: MirrorTlSecret, m: RSAGroup) -> Self {
        return Secret { mtl, m };
    }
    pub fn as_ref(&self) -> (&RSAGroup, &RSAGroup) {
        return (&self.m, &self.mtl.as_ref().1);
    }
}

struct MirrorTLProof(
    ECDDHProof<IntegerGroup>,
    ECDDHProof<IntegerGroup>,
);

struct UniquenessProof {
    p_eq: (HomoELGamalProof<PedersenGroup>,
           HomoELGamalProof<PedersenGroup>),
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

pub fn proof(master_tl: MasterTl, state: &Statement, secret: &Secret) -> Proofs {
    let mtl: (&ZPhi, &RSAGroup, &RSAGroup) = secret.mtl.as_ref();
    let r = mtl.1.as_ref();
    let r_aux = mtl.2.as_ref();
    let a = mtl.0.as_ref();
    let msg = secret.m.as_ref();

    let mtl: (&RSAGroup, &RSAGroup, &RSAGroup) = state.mtl.as_ref();
    let h = mtl.0.as_ref();
    let r_k0 = mtl.1.as_ref();
    let r_k1 = mtl.2.as_ref();

    let master_tl: (&RSAGroup, &RSAGroup, &RSAGroup, &RSAGroup, &RSAGroup) =
        master_tl.as_ref();
    let generator = master_tl.0.as_ref();
    let m_0 = master_tl.1.as_ref();
    let m_1 = master_tl.2.as_ref();

    //Well-formed-ness proof
    // witness: a  Statement:g h m_0 r_k0

    let vec_int_0 = vec![generator, h, m_0, r_k0];
    let vec_int_1 = vec![m_0, r_k0, m_1, r_k1];
    let mut group_iter_0 = generate_integer_group_from_rsa_group(vec_int_0).into_iter();
    let mut group_iter_1 = generate_integer_group_from_rsa_group(vec_int_1).into_iter();

    let m_eq_0: ECDDHProof<IntegerGroup> = ECDDHProof::prove(
        &ECDDHWitness {
            x: a.into()
        },
        &ECDDHStatement {
            g1: group_iter_0.next().unwrap(),
            h1: group_iter_0.next().unwrap(),
            g2: group_iter_0.next().unwrap(),
            h2: group_iter_0.next().unwrap(),
        },
    );
    //witness: a Statement:m_0 r_k0 m_1 r_k1
    let m_eq_1: ECDDHProof<IntegerGroup> = ECDDHProof::prove(
        &ECDDHWitness {
            x: a.into()
        },
        &ECDDHStatement {
            g1: group_iter_1.next().unwrap(),
            h1: group_iter_1.next().unwrap(),
            g2: group_iter_1.next().unwrap(),
            h2: group_iter_1.next().unwrap(),
        },
    );

    //Uniqueness proof:
    //get H (common)
    let M_sf: PedersenScaler = (&M as &BigInt).into();
    let M_gr = PedersenGroup::identity() - (PedersenGroup::generator() * M_sf).borrow();
    //b b_aux g
    //D = b E = b_aux
    //H = generator^M x = k
    //Y = b_aux r = r_aux
    //G = generator

    //get x
    let x_0: PedersenScaler = (r_aux.pow(2) - r).div(&M as &BigInt).borrow().into();
    //get r
    let r_aux_sf: PedersenScaler = r_aux.into();
    let u_hes_0 = HomoElGamalStatement {
        G: PedersenGroup::generator(),
        H: M_gr.clone(),
        Y: state.b_aux.clone(),
        D: state.b.clone(),
        E: state.b_aux.clone(),
    };
    let u_hew_0 = HomoElGamalWitness {
        r: r_aux_sf,
        x: x_0,
    };
    let u_p_eq_0 = HomoELGamalProof::prove(u_hew_0.borrow(), u_hes_0.borrow());

    //B b g
    //D = B E = b
    //H = generator^M x = k
    //Y = b r = r
    //G = generator

    //get x
    let x_1: PedersenScaler = (r.pow(2) - r_k1).div(&M as &BigInt).borrow().into();
    //get r
    let r_sf: PedersenScaler = r.into();
    let u_hes_1 = HomoElGamalStatement {
        G: PedersenGroup::generator(),
        H: M_gr.clone(),
        Y: state.b.clone(),
        D: state.B.clone(),
        E: state.b.clone(),
    };
    let u_hew_1 = HomoElGamalWitness {
        r: r_sf,
        x: x_1,
    };
    let u_p_eq_1 = HomoELGamalProof::prove(u_hew_1.borrow(), u_hes_1.borrow());

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
    // statement: D = xH + rY; E = rG
    // witness: (x,r)
    let c_hes = HomoElGamalStatement {
        G: PedersenGroup::generator(),
        H: PedersenGroup::generator(),
        Y: PedersenGroup::base_point2(),
        D: state.C,
        E: state.b,
    };
    let c_hew = HomoElGamalWitness {
        r: r.into(),
        x: msg.into(),
    };
    let p_c_eq = HomoELGamalProof::prove(c_hew.borrow(), c_hes.borrow());

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

pub fn verify(master_tl: MasterTl, state: &Statement, proofs: Proofs) -> bool {
    let mtl: (&RSAGroup, &RSAGroup, &RSAGroup) = state.mtl.as_ref();
    let h = mtl.0.as_ref();
    let r_k0 = mtl.1.as_ref();
    let r_k1 = mtl.2.as_ref();

    let master_tl: (&RSAGroup, &RSAGroup, &RSAGroup, &RSAGroup, &RSAGroup) =
        master_tl.as_ref();
    let generator = master_tl.0.as_ref();
    let m_0 = master_tl.1.as_ref();
    let m_1 = master_tl.2.as_ref();

    let vec_int_0 = vec![generator, h, m_0, r_k0];
    let vec_int_1 = vec![m_0, r_k0, m_1, r_k1];
    let mut group_iter_0 = generate_integer_group_from_rsa_group(vec_int_0).into_iter();
    let mut group_iter_1 = generate_integer_group_from_rsa_group(vec_int_1).into_iter();

    //Well-formed-ness verify
    let result1_0 = proofs.m.0.verify(
        &ECDDHStatement {
            g1: group_iter_0.next().unwrap(),
            h1: group_iter_0.next().unwrap(),
            g2: group_iter_0.next().unwrap(),
            h2: group_iter_0.next().unwrap(),
        }
    );
    let result1_1 = proofs.m.1.verify(
        &ECDDHStatement {
            g1: group_iter_1.next().unwrap(),
            h1: group_iter_1.next().unwrap(),
            g2: group_iter_1.next().unwrap(),
            h2: group_iter_1.next().unwrap(),
        }
    );

    let M_sf: PedersenScaler = (&M as &BigInt).into();
    let M_gr = PedersenGroup::identity() - (PedersenGroup::generator() * M_sf).borrow();

    //Uniqueness verify
    let result2_0_0 = proofs.u.p_eq.0.verify(
        &HomoElGamalStatement {
            G: PedersenGroup::generator(),
            H: M_gr.clone(),
            Y: state.b_aux.clone(),
            D: state.b.clone(),
            E: state.b_aux.clone(),

        });
    let result2_0_1 = proofs.u.p_eq.1.verify(
        &HomoElGamalStatement {
            G: PedersenGroup::generator(),
            H: M_gr.clone(),
            Y: state.b.clone(),
            D: state.B.clone(),
            E: state.b.clone(),
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
    v_commit.push(&u_l_g - &m_g + &state.b); //(u_l)g + b - Mg
    v_commit.push(state.b.clone()); //b
    v_commit.push(&u_l_g - &m_g + &state.b_aux); //(u_l)g + b_aux - Mg
    v_commit.push(state.b_aux.clone()); //b_aux

    let result2_1 =
        proofs.u.p_range.0.verify(
            proofs.u.p_range.1, v_commit.as_slice()).map_err(|_| {
            ProofError
        });

    let result3 = proofs.c.0.verify(&HomoElGamalStatement {
        G: PedersenGroup::generator(),
        H: PedersenGroup::generator(),
        Y: PedersenGroup::base_point2(),
        D: state.C,
        E: state.b,
    });

    let result_vec = vec![result1_0, result1_1, result2_0_0, result2_0_1, result2_1, result3];
    let final_status = result_vec.into_iter().fold(true, |acc, x| {
        //println!("{:?}", x);
        acc && x.is_ok()
    });

    return final_status;
}

pub fn generate_integer_group_from_rsa_group(vec_int: Vec<&BigInt>) -> Vec<IntegerGroup> {
    let vec_group: Vec<IntegerGroup> = vec_int.into_iter().map(|x| {
        let i: IntegerGroup = x.into();
        i
    }).collect();
    vec_group
}