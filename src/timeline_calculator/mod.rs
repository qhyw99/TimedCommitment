#![allow(non_snake_case)]
use super::*;
use curv::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use std::borrow::Borrow;
use curv::elliptic::curves::traits::ECPoint;

pub mod salt_hash;

static mut K: u32 = 30;

pub unsafe fn set_system_parameter(new_k: u32) {
    K = new_k;
}

#[derive(Clone)]
pub struct MasterTl {
    pub generator: RSAGroup,
    pub u_0: RSAGroup,
    pub u_1: RSAGroup,
    pub m_0: RSAGroup,
    pub m_1: RSAGroup,
}

impl MasterTl {
    pub fn as_ref(&self) ->
    (&RSAGroup, &RSAGroup, &RSAGroup, &RSAGroup, &RSAGroup) {
        return (self.generator.borrow(),
                self.u_0.borrow(),
                self.u_1.borrow(),
                self.m_0.borrow(),
                self.m_1.borrow()
        );
    }
}

#[derive(Clone)]
pub struct MirrorTlPublic {
    pub h: RSAGroup,
    pub r_k0: RSAGroup,
    pub r_k1: RSAGroup,
}

impl MirrorTlPublic {
    pub fn as_ref(&self) -> (&RSAGroup, &RSAGroup, &RSAGroup) {
        let ref_h = &self.h;
        let ref_r_k0 = &self.r_k0;
        let ref_r_k1 = &self.r_k1;
        let ref_tuple = (ref_h, ref_r_k0, ref_r_k1);
        return ref_tuple;
    }
}

#[derive(Clone)]
pub struct MirrorTlSecret {
    a: ZPhi,
    r: RSAGroup,
    r_aux: RSAGroup,
}

impl MirrorTlSecret {
    pub fn as_ref(&self) -> (&ZPhi, &RSAGroup, &RSAGroup) {
        let ref_a = &self.a;
        let ref_r = &self.r;
        let ref_r_aux = &self.r_aux;
        let ref_tuple = (ref_a, ref_r, ref_r_aux);
        return ref_tuple;
    }
}

impl MasterTl {
    pub fn generate_master_timeline_trusted() -> Self {
        let generator = Zqf::from(g.clone());

        let base = Zqf::from(&BigInt::from(2));
        let (exp_u_0, exp_u_1) = unsafe {
            (2_u64.pow(K - 1), 2_u64.pow(K))
        };

        let exp0 = BigInt::from(exp_u_0);
        let exp1 = BigInt::from(exp_u_1);
        let exp1_0 = BigInt::from(exp_u_1 - 2);
        let exp1_1 = BigInt::from(exp_u_1 - 1);

        let a_0 = base.pow_mod_phi(&exp0);
        let a_1 = base.pow_mod_phi(&exp1);
        let a_1_0 = base.pow_mod_phi(&exp1_0);
        let a_1_1 = base.pow_mod_phi(&exp1_1);

        let u_0 = generator.pow_mod_m(a_0.as_ref());
        let u_1 = generator.pow_mod_m(a_1.as_ref());

        let m_1 = generator.pow_mod_m(a_1_1.as_ref());
        let m_0 = generator.pow_mod_m(a_1_0.as_ref());

        return MasterTl { generator, u_0, u_1, m_0, m_1 };
    }
}

pub fn generate_mirror_timeline(mtl: MasterTl) -> (MirrorTlPublic, MirrorTlSecret) {
    let a_inner = alpha.clone();
    let h = mtl.generator.pow_mod_m(&a_inner);
    let r_k0 = mtl.u_0.pow_mod_m(&a_inner);
    let r_k1 = mtl.u_1.pow_mod_m(&a_inner);
    let r = mtl.m_1.pow_mod_m(&a_inner);
    let r_aux = mtl.m_0.pow_mod_m(&a_inner);
    let a = ZPhi::from(&a_inner);

    //assert_eq!(r_aux.square(),r);

    return (MirrorTlPublic {
        h,
        r_k0,
        r_k1,
    }, MirrorTlSecret {
        a,
        r,
        r_aux,
    });
}

pub fn pedersen_commit(g_exp: &BigInt, h_exp: &BigInt) -> PedersenGroup {
    return PedersenCommitment::create_commitment_with_user_defined_randomness(g_exp, h_exp);
}

pub fn commit_message(message: &BigInt, blind: &MirrorTlSecret, public: &MirrorTlPublic) -> (PedersenGroup, PedersenGroup, PedersenGroup, PedersenGroup) {
    let one = BigInt::zero();
    let four_element_tuple =
        (pedersen_commit(message, blind.r.as_ref()),
         pedersen_commit(public.r_k1.as_ref(), &one),
         pedersen_commit(blind.r.as_ref(), &one),
         pedersen_commit(blind.r_aux.as_ref(), &one));
    return four_element_tuple;
}

//m r
//Verify
//C = g^m * g_1^r
//&&
//b = g^r
pub fn open_message(statement: &Statement, message: &BigInt, blind: &BigInt) -> bool {
    let state_tuple = statement.as_ref();
    let C = pedersen_commit(message, blind);
    let b = pedersen_commit(blind, &BigInt::zero());
    let status = &C == state_tuple.1 && b.borrow() == state_tuple.3;
    return status;
}

//r_k0 -> r
//r -> blind = g_1^r
//C/blind = g^m
//穷举得到m 暂时考虑两种情况
pub fn force_open_message(msg_0: &BigInt, msg_1: &BigInt, C: PedersenGroup, mut r_k0: RSAGroup, r_origin: RSAGroup) -> u8 {
    let msg_scalar_0: PedersenScaler = msg_0.into();
    let msg_scalar_1: PedersenScaler = msg_1.into();
    let msg_point_0 = PedersenGroup::generator() * msg_scalar_0;
    let msg_point_1 = PedersenGroup::generator() * msg_scalar_1;
    let mut steps = unsafe {
        2_u64.pow(K - 1) - 1
    };
    while steps > 0 {
        r_k0 = r_k0.square();
        steps -= 1;
    }
    assert_eq!(r_k0, r_origin);
    let r = r_k0.as_ref();
    let r_scalar: PedersenScaler = r.into();
    let blind_point = PedersenGroup::base_point2() * r_scalar;
    let message_point = C.sub_point(blind_point.get_element().borrow());

    return match message_point {
        x if x == msg_point_0 => 0,
        x if x == msg_point_1 => 1,
        _ => 2
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_master_timeline_trusted() {
        let mtl = MasterTl::generate_master_timeline_trusted();
        generate_mirror_timeline(mtl);
    }
}
