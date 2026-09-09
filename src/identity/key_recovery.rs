use pqc_crypto_module::legacy::sha256::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum RecoveryError {
    ThresholdTooLow,
    ThresholdExceedsShares,
    TooFewShares,
    DuplicateIndex,
    ShareLengthMismatch,
    ChecksumMismatch,
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ThresholdTooLow => write!(f, "threshold must be >= 2"),
            Self::ThresholdExceedsShares => write!(f, "threshold exceeds total shares"),
            Self::TooFewShares => write!(f, "not enough shares to reconstruct"),
            Self::DuplicateIndex => write!(f, "duplicate share index"),
            Self::ShareLengthMismatch => write!(f, "shares have different lengths"),
            Self::ChecksumMismatch => write!(f, "reconstructed secret checksum mismatch"),
        }
    }
}

const CHECKSUM_LEN: usize = 4;

fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut r: u16 = 0;
    let mut aa = a as u16;
    let mut bb = b as u16;
    for _ in 0..8 {
        if bb & 1 != 0 {
            r ^= aa;
        }
        let carry = aa & 0x80;
        aa <<= 1;
        if carry != 0 {
            aa ^= 0x11b;
        }
        bb >>= 1;
    }
    r as u8
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut r = a;
    for _ in 0..6 {
        r = gf256_mul(r, r);
        r = gf256_mul(r, a);
    }
    r = gf256_mul(r, r);
    r
}

fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf256_add(gf256_mul(result, x), c);
    }
    result
}

fn checksum(data: &[u8]) -> [u8; CHECKSUM_LEN] {
    let hash = Sha256::digest(data);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&hash[..CHECKSUM_LEN]);
    out
}

pub fn split(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Share>, RecoveryError> {
    if threshold < 2 {
        return Err(RecoveryError::ThresholdTooLow);
    }
    if threshold > total || total < 2 {
        return Err(RecoveryError::ThresholdExceedsShares);
    }

    let checksum_bytes = checksum(secret);
    let payload: Vec<u8> = secret
        .iter()
        .copied()
        .chain(checksum_bytes.iter().copied())
        .collect();

    let mut shares: Vec<Share> = (1..=total)
        .map(|i| Share {
            index: i,
            data: Vec::with_capacity(payload.len()),
        })
        .collect();

    let mut rng_state = Sha256::digest(secret);

    for (byte_idx, &secret_byte) in payload.iter().enumerate() {
        let mut coeffs = vec![secret_byte];
        for coeff_idx in 1..threshold as usize {
            let mut seed_input = rng_state.to_vec();
            seed_input.extend_from_slice(&(byte_idx as u32).to_le_bytes());
            seed_input.extend_from_slice(&(coeff_idx as u32).to_le_bytes());
            rng_state = Sha256::digest(&seed_input);
            coeffs.push(rng_state[0]);
        }

        for share in &mut shares {
            share.data.push(eval_poly(&coeffs, share.index));
        }
    }

    Ok(shares)
}

pub fn reconstruct(shares: &[Share], threshold: u8) -> Result<Vec<u8>, RecoveryError> {
    if (shares.len() as u8) < threshold {
        return Err(RecoveryError::TooFewShares);
    }

    let shares = &shares[..threshold as usize];
    let len = shares[0].data.len();
    if shares.iter().any(|s| s.data.len() != len) {
        return Err(RecoveryError::ShareLengthMismatch);
    }

    let mut seen = [false; 256];
    for s in shares {
        if seen[s.index as usize] {
            return Err(RecoveryError::DuplicateIndex);
        }
        seen[s.index as usize] = true;
    }

    let mut payload = vec![0u8; len];

    for (byte_idx, slot) in payload.iter_mut().enumerate() {
        let mut value = 0u8;
        for (i, si) in shares.iter().enumerate() {
            let xi = si.index;
            let yi = si.data[byte_idx];
            let mut basis = 1u8;
            for (j, sj) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = sj.index;
                let num = gf256_add(0, xj);
                let den = gf256_add(xi, xj);
                basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
            }
            value = gf256_add(value, gf256_mul(yi, basis));
        }
        *slot = value;
    }

    if len < CHECKSUM_LEN {
        return Err(RecoveryError::ChecksumMismatch);
    }

    let secret_len = len - CHECKSUM_LEN;
    let secret = &payload[..secret_len];
    let stored_checksum = &payload[secret_len..];
    let expected = checksum(secret);

    if stored_checksum != expected {
        return Err(RecoveryError::ChecksumMismatch);
    }

    Ok(secret.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_reconstruct_ed25519() {
        let secret = vec![42u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = reconstruct(&shares[0..3], 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn reconstruct_with_different_share_subsets() {
        let secret = b"goya-ledger-master-key-material!".to_vec();
        let shares = split(&secret, 3, 5).unwrap();

        let r1 = reconstruct(
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
            3,
        )
        .unwrap();
        let r2 = reconstruct(
            &[shares[1].clone(), shares[3].clone(), shares[4].clone()],
            3,
        )
        .unwrap();
        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
    }

    #[test]
    fn reconstruct_fails_with_too_few() {
        let secret = vec![1u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        assert!(reconstruct(&shares[0..2], 3).is_err());
    }

    #[test]
    fn reconstruct_detects_corruption() {
        let secret = vec![7u8; 32];
        let mut shares = split(&secret, 2, 3).unwrap();
        shares[0].data[0] ^= 0xff;
        assert!(matches!(
            reconstruct(&shares[0..2], 2),
            Err(RecoveryError::ChecksumMismatch)
        ));
    }

    #[test]
    fn threshold_2_of_2() {
        let secret = vec![99u8; 64];
        let shares = split(&secret, 2, 2).unwrap();
        let recovered = reconstruct(&shares, 2).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn rejects_threshold_one() {
        assert!(matches!(
            split(&[1, 2, 3], 1, 3),
            Err(RecoveryError::ThresholdTooLow)
        ));
    }

    #[test]
    fn rejects_threshold_exceeds_total() {
        assert!(matches!(
            split(&[1, 2, 3], 5, 3),
            Err(RecoveryError::ThresholdExceedsShares)
        ));
    }

    #[test]
    fn rejects_duplicate_index() {
        let secret = vec![1u8; 16];
        let shares = split(&secret, 2, 3).unwrap();
        let duped = vec![shares[0].clone(), shares[0].clone()];
        assert!(matches!(
            reconstruct(&duped, 2),
            Err(RecoveryError::DuplicateIndex)
        ));
    }

    #[test]
    fn large_secret_mldsa65() {
        let secret = vec![0xAB; 4032];
        let shares = split(&secret, 3, 5).unwrap();
        let recovered = reconstruct(&shares[1..4], 3).unwrap();
        assert_eq!(recovered, secret);
    }
}
