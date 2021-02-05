use super::*;
use curv::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;

const k: u32 = 50;

pub struct MasterTl {
    generator: RSAGroup,
    u_0: RSAGroup,
    u_1: RSAGroup,
    m_0: RSAGroup,
    m_1: RSAGroup,
}

pub struct MirrorTlPublic {
    h: RSAGroup,
    r_k0: RSAGroup,
    r_k1: RSAGroup,
}

pub struct MirrorTlSecret {
    a: ZPhi,
    r_aux: RSAGroup,
    r: RSAGroup,
}

impl MasterTl {
    pub fn generate_master_timeline_trusted() -> Self {
        let base = RSAGroup::from(&BigInt::from(2));
        let exp0 = BigInt::from(2_i64.pow(k - 1));
        let exp1 = BigInt::from(2_i64.pow(k));
        let u_0 = base.pow_mod_m(&exp0);
        let u_1 = base.pow_mod_m(&exp1);

        let m_1 = u_1.sqrt();

        let m_0 = m_1.sqrt();

        let generator = RSAGroup::from(&g);
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
    return (MirrorTlPublic {
        h,
        r_k0,
        r_k1,
    }, MirrorTlSecret {
        a,
        r_aux,
        r,
    });
}
fn commit(message:BigInt,blind:BigInt) -> (PedersenGroup,BigInt){
    return PedersenCommitment::create_commitment_with_user_defined_randomness(&message,&blind)
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
