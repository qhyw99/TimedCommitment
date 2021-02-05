use super::*;

const k: u32 = 50;

pub struct MasterTl {
    generator: RSAGroup,
    u_0: RSAGroup,
    u_1: RSAGroup,
    m_0: RSAGroup,
    m_1: RSAGroup,
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

#[cfg(test)]
mod test{
    use super::*;
    #[test]
    fn test_generate_master_timeline_trusted(){
        let mtl = MasterTl::generate_master_timeline_trusted();
    }
}