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
type PedersenGroup = RistrettoCurvPoint; //TODO 改成其他
type PedersenScaler = RistrettoScalar;

fn main() {
    //Init
    let msg = BigInt::from("My choice is true!".as_ref());
    let mtl = MasterTl::generate_master_timeline_trusted();

    //Commit
    let (mtl_p, mtl_s) = generate_mirror_timeline(mtl);
    let commit = commit_message(&msg, &mtl_s, &mtl_p);

    //Proof
    let statement = Statement::new(mtl_p, commit);
    let statement_to_transfer = statement.clone();
    let secret = Secret::new(mtl_s, RSAGroup::from(msg));
    let proofs = proof(statement, secret);

    //Verify
    let status = verify(statement_to_transfer,proofs);

    println!("{:?}",status);
}
