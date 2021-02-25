#[macro_use]
extern crate criterion;
extern crate TimedCommitment;

use TimedCommitment::*;
use TimedCommitment::timeline_calculator::*;
use TimedCommitment::proof_system::*;
lazy_static::lazy_static! {
   pub static ref msg_0:BigInt = {
   BigInt::from("My choice is false!".as_ref())
   };
   pub static ref msg_1:BigInt = {
   BigInt::from("My choice is true!".as_ref())
   };
   pub static ref SYSTEM_PARAMETER: [usize; 8] = [10, 20, 30, 35, 37, 38, 39, 40];
   //, 30, 35, 37, 40
}

mod proof_verify {
    use criterion::Criterion;
    use super::*;

    pub fn bench_proof_verify(c: &mut Criterion) {
        let label = format!("Proof & Verify");
        c.bench_function_over_inputs(
            &label,
            |b, &&m| {
                unsafe {
                    set_system_parameter(m as u32);
                }
                let mtl = MasterTl::generate_master_timeline_trusted();
                let (mtl_p, mtl_s) = generate_mirror_timeline(mtl.clone());
                let commit = commit_message(&msg_1, &mtl_s, &mtl_p);

                //Proof
                let statement = Statement::new(mtl_p, commit);
                let secret = Secret::new(mtl_s, RSAGroup::from(msg_1.clone()));

                b.iter(|| {
                    let proofs = proof(mtl.clone(), &statement, &secret);
                    //Verify
                    let status = verify(mtl.clone(), &statement, proofs);
                    assert!(status);
                })
            },
            &*SYSTEM_PARAMETER,
        );
    }

    pub fn bench_proof_create(c: &mut Criterion) {
        let label = format!("Information node: Proof");
        c.bench_function_over_inputs(
            &label,
            |b, &&m| {
                unsafe {
                    set_system_parameter(m as u32);
                }
                let mtl = MasterTl::generate_master_timeline_trusted();
                let (mtl_p, mtl_s) = generate_mirror_timeline(mtl.clone());
                let commit = commit_message(&msg_1, &mtl_s, &mtl_p);

                //Proof
                let statement = Statement::new(mtl_p, commit);
                let secret = Secret::new(mtl_s, RSAGroup::from(msg_1.clone()));

                b.iter(|| {
                    let proofs = proof(mtl.clone(), &statement, &secret);
                })
            },
            &*SYSTEM_PARAMETER,
        );
    }

    // pub fn bench_verify(c: &mut Criterion) {
    //     let label = format!("Computation node: Verify");
    //     c.bench_function_over_inputs(
    //         &label,
    //         |b, &&m| {
    //             unsafe {
    //                 set_system_parameter(m as u32);
    //             }
    //             let mtl = MasterTl::generate_master_timeline_trusted();
    //             let (mtl_p, mtl_s) = generate_mirror_timeline(mtl.clone());
    //             let commit = commit_message(&msg_1, &mtl_s, &mtl_p);
    //
    //             //Proof
    //             let statement = Statement::new(mtl_p, commit);
    //             let secret = Secret::new(mtl_s, RSAGroup::from(msg_1.clone()));
    //
    //             let proofs = proof(mtl.clone(), &statement, &secret);
    //             b.iter(|| {
    //                 //Verify
    //                 let status = verify(mtl.clone(), &statement, proofs.clone());
    //                 assert!(status);
    //             })
    //         },
    //         &*SYSTEM_PARAMETER,
    //     );
    // }

    criterion_group!(
    name = proof_verify;
    config = Criterion::default().sample_size(10);
    targets =
    bench_proof_verify,
    bench_proof_create,
    //bench_verify
    );
}

mod force_open {
    use criterion::Criterion;
    use super::*;

    pub fn bench_force_open(c: &mut Criterion) {
        let label = format!("Computation node: Force open");
        c.bench_function_over_inputs(
            &label,
            |b, &&m| {
                unsafe {
                    set_system_parameter(m as u32);
                }
                let mtl = MasterTl::generate_master_timeline_trusted();
                let (mtl_p, mtl_s) = generate_mirror_timeline(mtl.clone());
                let commit = commit_message(&msg_1, &mtl_s, &mtl_p);

                //Proof
                let statement = Statement::new(mtl_p, commit);
                let secret = Secret::new(mtl_s, RSAGroup::from(msg_1.clone()));

                let message_commitment = statement.get_message_commitment();
                let rk_0 = statement.get_rk0();
                let s = secret.as_ref(); //m r
                b.iter(|| {
                    let b = force_open_message(&msg_0, &msg_1, message_commitment, rk_0.clone(), s.1.clone());
                    assert_eq!(b, 1);
                })
            },
            &*SYSTEM_PARAMETER,
        );
    }
    criterion_group!(
    name = force_open;
    config = Criterion::default().sample_size(10);
    targets = bench_force_open,
    );
}

mod commit_reveal {
    use criterion::Criterion;
    use super::*;
    use timeline_calculator::salt_hash;
    use timeline_calculator::pedersen_commit;
    use TimedCommitment::arithmetic::traits::Samplable;

    pub fn bench_commit_in_pedersen_group(c: &mut Criterion) {
        let label = format!("Information node: commit-group");
        c.bench_function_over_inputs(
            &label,
            |b, &&m| {
                unsafe {
                    set_system_parameter(m as u32);
                }
                let mtl = MasterTl::generate_master_timeline_trusted();
                let (mtl_p, mtl_s) = generate_mirror_timeline(mtl.clone());
                b.iter(|| {
                    let commit = commit_message(&msg_1, &mtl_s, &mtl_p);
                })
            },
            &*SYSTEM_PARAMETER,
        );
    }

    pub fn bench_reveal_in_pedersen_group(c: &mut Criterion) {
        let label = format!("Information node: reveal-group");
        c.bench_function_over_inputs(
            &label,
            |b, &&m| {
                unsafe {
                    set_system_parameter(m as u32);
                }
                let mtl = MasterTl::generate_master_timeline_trusted();
                let (mtl_p, mtl_s) = generate_mirror_timeline(mtl.clone());
                let commit = commit_message(&msg_1, &mtl_s, &mtl_p);

                //Proof
                let statement = Statement::new(mtl_p, commit);
                let secret = Secret::new(mtl_s, RSAGroup::from(msg_1.clone()));

                let s = secret.as_ref(); //m r
                let C = statement.as_ref().1;
                b.iter(|| {
                    assert_eq!(C, &pedersen_commit(s.0.as_ref(), s.1.as_ref()));
                })
            },
            &*SYSTEM_PARAMETER,
        );
    }

    pub fn bench_commit_in_salt_hash(c: &mut Criterion) {
        let label = format!("Information node: commit-hash");
        c.bench_function(&label, |b| {
            b.iter(|| {
                let r = BigInt::sample(512);
                let commit_hash = salt_hash::commit_message(&msg_1, &r);
            });
        });
    }

    pub fn bench_reveal_in_salt_hash(c: &mut Criterion) {
        let label = format!("Information node: reveal-hash");
        c.bench_function(&label, |b| {
            let r = BigInt::sample(512);
            let commit_hash = salt_hash::commit_message(&msg_1, &r);
            b.iter(|| {
                let status = salt_hash::reveal_message(&msg_1, &r, commit_hash.clone());
                assert!(status);
            });
        });
    }

    criterion_group!(
    name = commit_reveal;
    config = Criterion::default().sample_size(10);
    targets =
    bench_commit_in_pedersen_group,
    bench_reveal_in_pedersen_group,
    bench_commit_in_salt_hash,
    bench_reveal_in_salt_hash,
    );
}
criterion_main!(
    //proof_verify::proof_verify,
    //force_open::force_open,
    commit_reveal::commit_reveal
);