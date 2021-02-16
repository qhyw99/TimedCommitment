use curv::*;

pub mod proof_system;
pub mod timeline_calculator;

extern crate curv;
extern crate bulletproof;

use curv::elliptic::curves::rsa_group::*;
use curv::elliptic::curves::curve_ristretto::*;
use crate::timeline_calculator::*;
use crate::proof_system::{Statement, proof, verify, Secret};

type RSAGroup = Zqf;
type ZPhi = Zqf;
//群的阶数较小
type PedersenGroup = RistrettoCurvPoint;
type PedersenScaler = RistrettoScalar;
// //群阶数较大
type IntegerGroup = curv::elliptic::curves::integer_group::Zqg;
type IntegerScaler = curv::elliptic::curves::integer_group::Zqf;

fn main() {
    //Init
    let msg = BigInt::from("My choice is true!".as_ref());
    let mtl = MasterTl::generate_master_timeline_trusted();
    //let mtl_to_ref = mtl.clone();

    //Commit
    let (mtl_p, mtl_s) = generate_mirror_timeline(mtl.clone());
    let commit = commit_message(&msg, &mtl_s, &mtl_p);

    //Proof
    let statement = Statement::new(mtl_p, commit);
    let statement_to_transfer = statement.clone();
    let secret = Secret::new(mtl_s, RSAGroup::from(msg));
    let proofs = proof(mtl.clone(), &statement, secret);

    //Verify
    let status = verify(mtl.clone(), &statement_to_transfer, proofs);

    //Force open
    if status {

    }
    //Open
}
