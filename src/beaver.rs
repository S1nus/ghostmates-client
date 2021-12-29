#![feature(iter_zip)]
use rand::{distributions::Uniform, Rng, rngs::ThreadRng};
use paillier::*;
use paillier::{
    EncryptionKey as PaillierEncryptionKey,
    DecryptionKey as PaillierDecryptionKey,
    encoding::EncodedCiphertext as PaillierEncodedCiphertext
};
use std::{
    sync::{Arc, Mutex},
    net::SocketAddr,
    iter::zip,
    convert::TryFrom,
};

fn main() {

    let (courier_pk, courier_sk) = Paillier::keypair().keys();
    let (recipient_pk, recipient_sk) = Paillier::keypair().keys();

    let mut rng = rand::thread_rng();
    let range = Uniform::new(0, 50);

    let sender_a_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
    let sender_b_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();

    let courier_a_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
    let courier_b_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
    let courier_encrypted_pairs: Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)> = zip(&courier_a_vals, &courier_b_vals)
        .map(|(a, b)| {
            (Paillier::encrypt(&courier_pk, *a), Paillier::encrypt(&courier_pk, *b))
        }).collect();

    let recipient_a_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
    let recipient_b_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
    let recipient_encrypted_pairs: Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)> = zip(&recipient_a_vals, &recipient_b_vals)
        .map(|(a, b)| {
            (Paillier::encrypt(&recipient_pk, *a), Paillier::encrypt(&recipient_pk, *b))
        }).collect();

    let sender_to_courier_rs: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
    let sender_to_recipient_rs: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
    let courier_to_recipient_rs: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();

    let sender_to_courier_ts: Vec<PaillierEncodedCiphertext<u64>> = zip(sender_a_vals.clone(), zip(sender_b_vals.clone(), zip(courier_encrypted_pairs,sender_to_courier_rs.clone())))
        .map(|(a, (b, ((ea, eb), r)))| {
            Paillier::add(&courier_pk,
                Paillier::add(&courier_pk,
                    Paillier::mul(&courier_pk, ea, b),
                    Paillier::mul(&courier_pk, a, eb)
                ),
                r
            )
        }).collect();

    let sender_to_recipient_ts: Vec<PaillierEncodedCiphertext<u64>> = zip(sender_a_vals.clone(), zip(sender_b_vals.clone(), zip(recipient_encrypted_pairs.clone(),sender_to_recipient_rs.clone())))
        .map(|(a, (b, ((ea, eb), r)))| {
            Paillier::add(&recipient_pk,
                Paillier::add(&recipient_pk,
                    Paillier::mul(&recipient_pk, ea, b),
                    Paillier::mul(&recipient_pk, a, eb)
                ),
                r
            )
        }).collect();

    let courier_to_recipient_ts: Vec<PaillierEncodedCiphertext<u64>> = zip(courier_a_vals.clone(), zip(courier_b_vals.clone(), zip(recipient_encrypted_pairs.clone(),courier_to_recipient_rs.clone())))
        .map(|(a, (b, ((ea, eb), r)))| {
            Paillier::add(&recipient_pk,
                Paillier::add(&recipient_pk,
                    Paillier::mul(&recipient_pk, ea, b),
                    Paillier::mul(&recipient_pk, a, eb)
                ),
                r
            )
        }).collect();

    let sender_ws : Vec<u64> = zip(sender_to_recipient_rs.clone(), zip(sender_to_courier_rs.clone(), zip(sender_a_vals.clone(), sender_b_vals.clone())))
        .map(|(rs, (rc, (a,b)))| {
            u64::try_from(7757*3+(
                i64::try_from(((a*b)%7757)).unwrap() -
                i64::try_from(rs).unwrap() -
                i64::try_from(rc).unwrap()
            )%7757).unwrap()
        }).collect();

    let courier_ws : Vec<u64> = zip(sender_to_courier_ts.clone(), zip(courier_to_recipient_rs.clone(), zip(courier_a_vals.clone(), courier_b_vals.clone())))
        .map(|(ts, (rw, (a,b)))| {
            u64::try_from((
                i64::try_from(((a*b)%7757)).unwrap() - i64::try_from(rw).unwrap() + i64::try_from(Paillier::decrypt(&courier_sk, ts)).unwrap()
            )%7757).unwrap()
        }).collect();

    let recipient_ws : Vec<u64> = zip(sender_to_recipient_ts.clone(), zip(courier_to_recipient_ts.clone(), zip(recipient_a_vals.clone(), recipient_b_vals.clone())))
        .map(|(ts, (tc, (a, b)))| {
            (((a*b)%7757) + Paillier::decrypt(&recipient_sk, ts) + Paillier::decrypt(&recipient_sk, tc))%7757
        }).collect();

    let a_sums = zip(sender_a_vals.clone(), zip(courier_a_vals.clone(), recipient_a_vals.clone()))
        .map(|(sa, (ca, ra))| {
            (sa+ca+ra)%7757
        });
    let b_sums = zip(sender_b_vals.clone(), zip(courier_b_vals.clone(), recipient_b_vals.clone()))
        .map(|(sb, (cb, rb))| {
            (sb+cb+rb)%7757
        });
    let w_sums = zip(sender_ws.clone(), zip(courier_ws.clone(), recipient_ws.clone()))
        .map(|(sw, (cw, rw))| {
            (sw+cw+rw)%7757
        });

    println!("{} * {} = {}", sender_a_vals[0], sender_b_vals[0], sender_ws[0]);
    println!("{} * {} = {}", courier_a_vals[0], courier_b_vals[0], courier_ws[0]);
    println!("{} * {} = {}", recipient_a_vals[0], recipient_b_vals[0], recipient_ws[0]);
    /*zip(a_sums, zip(b_sums, w_sums))
        .for_each(|(a, (b, w))| {
            println!("{} * {} = {}", a, b, w);
            println!("{}", (a*b)%7757==w);
        });*/
}
