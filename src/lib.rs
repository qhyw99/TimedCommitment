#![allow(non_snake_case)]
extern crate curv;
extern crate bulletproof;

pub use curv::*;
use curv::elliptic::curves::rsa_group::*;
use curv::elliptic::curves::curve_ristretto::*;
use crate::timeline_calculator::*;
use crate::proof_system::{Statement, proof, verify, Secret};

pub mod proof_system;
pub mod timeline_calculator;

pub type RSAGroup = Zqf;
type ZPhi = Zqf;
//群的阶数较小
type PedersenGroup = RistrettoCurvPoint;
type PedersenScaler = RistrettoScalar;
// //群阶数较大
type IntegerGroup = curv::elliptic::curves::integer_group::Zqg;
//type IntegerScaler = curv::elliptic::curves::integer_group::Zqf;

fn main() {
    //Init
    let msg_0 = BigInt::from("My choice is false!".as_ref());
    let msg_1 = BigInt::from("My choice is true!".as_ref());

    let mtl = MasterTl::generate_master_timeline_trusted();
    //let mtl_to_ref = mtl.clone();

    //Commit
    let (mtl_p, mtl_s) = generate_mirror_timeline(mtl.clone());
    let commit = commit_message(&msg_1, &mtl_s, &mtl_p);

    //Proof
    let statement = Statement::new(mtl_p, commit);
    let secret = Secret::new(mtl_s, RSAGroup::from(&msg_1));
    let proofs = proof(mtl.clone(), &statement, &secret);

    //Verify
    let status = verify(mtl.clone(), &statement, proofs);

    let message_commitment = statement.get_message_commitment();
    let rk_0 = statement.get_rk0();
    let s = secret.as_ref(); //m r
    //Force open
    if status {
        let b = force_open_message(&msg_0, &msg_1, message_commitment, rk_0, s.1.clone());
        assert_eq!(b, 1);
    }
    //Open
    let open_status = open_message(&statement, s.0.as_ref(), s.1.as_ref());
    println!("{:?}", open_status);
}
