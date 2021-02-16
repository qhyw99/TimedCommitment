#[macro_use]
extern crate criterion;

mod proof_verify {
    use criterion::Criterion;

    pub fn bench_range_proof_17_2(c: &mut Criterion) {
        c.bench_function("haha",|b|{
            b.iter(||{
                assert_eq!(true);
            })
        });
    }

    criterion_group!(
    name = proof_verify;
    config = Criterion::default().sample_size(10);
    targets = bench_range_proof_17_2
    );
}

mod force_open {
    use criterion::Criterion;

    pub fn bench_range_proof_17_2(c: &mut Criterion) {}
    criterion_group!(
    name = force_open;
    config = Criterion::default().sample_size(10);
    targets = bench_range_proof_17_2
    );
}

criterion_main!(
    proof_verify::proof_verify,
    force_open::force_open,
);