use curv::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use super::*;
use std::marker::PhantomData;

pub struct MirrorTlPublic{
    h: RSAGroup,
    R_k0: RSAGroup,
    R_k1: RSAGroup,
}
pub struct MirrorTlSecret{
    alpha: ZPhi,
    r_aux: RSAGroup,
    r: RSAGroup,
}

// fn generate_mirror_timeline() -> (MirrorTlPublic,MirrorTlSecret){
//
//     return (MirrorTlPublic{
//         h: (),
//         R_k0: (),
//         R_k1: ()
//     }, MirrorTlSecret{
//         alpha: (),
//         r_aux: (),
//         r: ()
//     });
// }
fn commit() -> PedersenCommitment<PedersenGroup>{
    return PedersenCommitment(PhantomData);
}