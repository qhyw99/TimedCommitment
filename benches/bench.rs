#[macro_use]
extern crate criterion;

mod proof_verify {
    use criterion::Criterion;

    pub fn bench_proof_verify(c: &mut Criterion) {
        c.bench_function("p-v", |b| {
            b.iter(|| {
                assert_eq!(true);
            })
        });
    }

    pub fn bench_proof_create(c: &mut Criterion) {
        c.bench_function("p", |b| {
            b.iter(|| {
                assert_eq!(true);
            })
        });
    }

    pub fn bench_verify(c: &mut Criterion) {
        c.bench_function("v", |b| {
            b.iter(|| {
                assert_eq!(true);
            })
        });
    }

    criterion_group!(
    name = proof_verify;
    config = Criterion::default().sample_size(10);
    targets =
    bench_proof_verify,
    bench_proof_create,
    bench_verify
    );
}

mod force_open {
    use criterion::Criterion;

    static AGGREGATION_SIZES: [usize; 6] = [10, 20, 30, 35, 37, 40];
    pub fn bench_force_open(c: &mut Criterion) {
        let label = format!("Aggregated {}-bit rangeproofs verification", n);

        c.bench_function_over_inputs(
            &label,
            move |b, &&m| {
                let nm = n * m;
                let kzen: &[u8] = &[75, 90, 101, 110];
                let kzen_label = BigInt::from(kzen);

                let g: GE = ECPoint::generator();
                let label = BigInt::from(1);
                let hash = HSha512::create_hash(&[&label]);
                let h = generate_random_point(&Converter::to_vec(&hash));

                let g_vec = (0..nm)
                    .map(|i| {
                        let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                        let hash_i = HSha512::create_hash(&[&kzen_label_i]);
                        generate_random_point(&Converter::to_vec(&hash_i))
                    })
                    .collect::<Vec<GE>>();

                // can run in parallel to g_vec:
                let h_vec = (0..nm)
                    .map(|i| {
                        let kzen_label_j =
                            BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                        let hash_j = HSha512::create_hash(&[&kzen_label_j]);
                        generate_random_point(&Converter::to_vec(&hash_j))
                    })
                    .collect::<Vec<GE>>();

                let range = BigInt::from(2).pow(n as u32);
                let v_vec = (0..m)
                    .map(|_i| {
                        let v = BigInt::sample_below(&range);
                        let v_fe: FE = ECScalar::from(&v);
                        v_fe
                    })
                    .collect::<Vec<FE>>();

                let r_vec = (0..m).map(|_i| ECScalar::new_random()).collect::<Vec<FE>>();

                let ped_com_vec = (0..m)
                    .map(|i| {
                        let ped_com = g.scalar_mul(&v_vec[i].get_element())
                            + h.scalar_mul(&r_vec[i].get_element());
                        ped_com
                    })
                    .collect::<Vec<GE>>();

                let range_proof = RangeProof::prove(&g_vec, &h_vec, &g, &h, v_vec.clone(), &r_vec, n);

                b.iter(|| {
                    let result =
                        RangeProof::aggregated_verify(&range_proof, &g_vec, &h_vec, &g, &h, &ped_com_vec, n);
                    assert!(result.is_ok());
                })
            },
            &AGGREGATION_SIZES,
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

    pub fn bench_commit_reveal_in_pedersen_group(c: &mut Criterion) {}

    pub fn bench_commit_reveal_in_salt_hash(c: &mut Criterion) {}

    criterion_group!(
    name = commit_reveal;
    config = Criterion::default().sample_size(10);
    targets =
    bench_commit_reveal_in_pedersen_group,
    bench_commit_reveal_in_salt_hash
    );
}
criterion_main!(
    proof_verify::proof_verify,
    force_open::force_open,
    commit_reveal::commit_reveal
);