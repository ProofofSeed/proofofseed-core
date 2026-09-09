// SPDX-License-Identifier: LGPL-3.0-or-later

//! What it costs to supply the BIP-39 PBKDF2 salt as witness rather than as public
//! circuit constants, isolated to the one HMAC whose message it is.
//!
//! Run: `cargo run --release -p proofofseed-host --example salt_secrecy_cost`

use zkboo::backend::{Backend, Frontend};
use proofofseed_circuits::assert_nothing;
use zkboo::circuit::Circuit;
use zkboo_hmac::hmac;
use zkboo_profiling::profile;
use zkboo_sha2::{SHA512_BLOCKSIZE, sha512bytes};

const MNEMONIC: &[u8] =
    b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// One HMAC-SHA512 under a secret key, over a message of `salt_len` bytes plus the
/// PBKDF2 block counter. `secret_salt` chooses whether those salt bytes are witness or
/// public constants — the whole of the proposed change.
struct FirstHmac {
    salt_len: usize,
    secret_salt: bool,
}

impl Circuit for FirstHmac {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let key = MNEMONIC.iter().map(|&b| frontend.input(b)).collect::<Vec<_>>();
        let mut msg: Vec<_> = (0..self.salt_len)
            .map(|_| if self.secret_salt { frontend.input(0x61u8) } else { frontend.alloc(0x61u8) })
            .collect();
        // The block counter INT_32_BE(1) is public either way.
        for byte in 1u32.to_be_bytes() {
            msg.push(frontend.alloc(byte));
        }
        let out = hmac(frontend.allocator(), key, msg, sha512bytes, SHA512_BLOCKSIZE);
        out.into_iter().for_each(|w| frontend.output(w));
        assert_nothing(frontend);
    }
}

fn main() {
    println!(
        "Cost of making the BIP-39 PBKDF2 salt secret, isolated to the one HMAC it appears in.\n\
         Salt = \"mnemonic\" + passphrase, so 8 bytes plus the passphrase's length.\n"
    );
    println!("{:<22} {:>14} {:>14} {:>12}", "salt (passphrase)", "public", "secret", "extra/resp");
    for pass_len in [0usize, 8, 12, 24, 64] {
        let salt_len = 8 + pass_len;
        let a = profile(&FirstHmac { salt_len, secret_salt: false })
            .response_size::<[u8; 32], [u8; 32]>();
        let b = profile(&FirstHmac { salt_len, secret_salt: true })
            .response_size::<[u8; 32], [u8; 32]>();
        println!(
            "{:<22} {a:>12} B {b:>12} B {:>10} B",
            format!("{salt_len} B ({pass_len} char)"),
            b as i64 - a as i64
        );
    }

    // The same difference against the statement it is a part of.
    use proofofseed_circuits::{SeedCircuit, bip39_salt_for};
    let whole = profile(&SeedCircuit {
        mnemonic: MNEMONIC.to_vec(),
        salt: bip39_salt_for(b""),
        rounds: 2048,
    })
    .response_size::<[u8; 32], [u8; 32]>();
    let a =
        profile(&FirstHmac { salt_len: 20, secret_salt: false }).response_size::<[u8; 32], [u8; 32]>();
    let b =
        profile(&FirstHmac { salt_len: 20, secret_salt: true }).response_size::<[u8; 32], [u8; 32]>();
    let delta = b as f64 - a as f64;
    println!(
        "\nThe full statement at 2048 rounds is {whole} B per response, so a 12-character\n\
         passphrase made secret costs {:.0} B more per response: {:.4}% .",
        delta,
        delta / whole as f64 * 100.0
    );
    println!(
        "\n⚠️ The salt's *length* stays public either way — it is the number of input words —\n\
         so this hides the passphrase's value, not its length nor the fact that one exists."
    );
}
