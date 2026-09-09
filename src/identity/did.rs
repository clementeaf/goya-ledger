pub fn did_from_pubkey_hex(pubkey_hex: &str) -> String {
    format!("did:goya:{}", &pubkey_hex[..16])
}

pub fn did_matches_pubkey(did: &str, pubkey_hex: &str) -> bool {
    pubkey_hex.len() >= 16 && did == did_from_pubkey_hex(pubkey_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_did_from_pubkey_hex() {
        let pubkey_hex = "aabbccdd11223344ffffffffffffffff";
        assert_eq!(did_from_pubkey_hex(pubkey_hex), "did:goya:aabbccdd11223344");
    }

    #[test]
    fn canonical_did_matches_pubkey() {
        let pubkey_hex = "aabbccdd11223344ffffffffffffffff";
        let did = did_from_pubkey_hex(pubkey_hex);
        assert!(did_matches_pubkey(&did, pubkey_hex));
    }

    #[test]
    fn canonical_did_rejects_wrong_pubkey() {
        let did = "did:goya:aabbccdd11223344";
        let wrong_key = "1111111111111111ffffffffffffffff";
        assert!(!did_matches_pubkey(did, wrong_key));
    }

    #[test]
    fn canonical_did_rejects_short_pubkey() {
        let did = "did:goya:aabbccdd11223344";
        assert!(!did_matches_pubkey(did, "aabb"));
    }

    #[test]
    fn canonical_did_deterministic() {
        let key = "606024501eda68c20bd7b65841d0c580aaaaaa";
        assert_eq!(did_from_pubkey_hex(key), did_from_pubkey_hex(key));
    }
}
