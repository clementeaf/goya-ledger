//! Canonical document fingerprint and dimensional verification.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use serde::{Deserialize, Serialize};

/// Canonical fingerprint of a document, decomposed by dimension.
///
/// Each hash is 64 hex chars (SHA-256 or SHA3-256, 32 bytes).
/// `canonical_hash` is the merkle root of all present dimension hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentFingerprint {
    /// Hash of the normalized text content (whitespace-collapsed, lowercased).
    pub content_hash: String,
    /// Hash of the structural skeleton (headings, paragraphs, sections order).
    pub structure_hash: String,
    /// Hash of serialized table data, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tables_hash: Option<String>,
    /// Hash of embedded images (perceptual or raw), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub images_hash: Option<String>,
    /// Hash of document metadata (author, title, creation date).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<String>,
    /// Merkle root of all dimension hashes above.
    pub canonical_hash: String,
}

impl DocumentFingerprint {
    /// Compute the merkle root from the dimension hashes.
    pub fn compute_canonical_hash(
        content_hash: &str,
        structure_hash: &str,
        tables_hash: Option<&str>,
        images_hash: Option<&str>,
        metadata_hash: Option<&str>,
        algorithm: HashAlgorithm,
    ) -> String {
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for h in [
            Some(content_hash),
            Some(structure_hash),
            tables_hash,
            images_hash,
            metadata_hash,
        ]
        .into_iter()
        .flatten()
        {
            let bytes = hex::decode(h).unwrap_or_else(|_| vec![0u8; 32]);
            let mut arr = [0u8; 32];
            let len = bytes.len().min(32);
            arr[..len].copy_from_slice(&bytes[..len]);
            leaves.push(arr);
        }
        let root = merkle_root(&leaves, algorithm);
        hex::encode(root)
    }

    /// Verify that `canonical_hash` matches the merkle root of dimensions.
    pub fn verify_integrity(&self, algorithm: HashAlgorithm) -> bool {
        let expected = Self::compute_canonical_hash(
            &self.content_hash,
            &self.structure_hash,
            self.tables_hash.as_deref(),
            self.images_hash.as_deref(),
            self.metadata_hash.as_deref(),
            algorithm,
        );
        self.canonical_hash == expected
    }

    /// Compare this fingerprint against a reference, producing a dimensional report.
    pub fn verify_against(&self, reference: &DocumentFingerprint) -> VerificationReport {
        let content =
            DimensionMatch::compare("content", &self.content_hash, &reference.content_hash);
        let structure =
            DimensionMatch::compare("structure", &self.structure_hash, &reference.structure_hash);
        let tables =
            DimensionMatch::compare_optional("tables", &self.tables_hash, &reference.tables_hash);
        let images =
            DimensionMatch::compare_optional("images", &self.images_hash, &reference.images_hash);
        let metadata = DimensionMatch::compare_optional(
            "metadata",
            &self.metadata_hash,
            &reference.metadata_hash,
        );

        let file_identical = self.canonical_hash == reference.canonical_hash;

        let mut dimensions = vec![content, structure];
        dimensions.extend(tables);
        dimensions.extend(images);
        dimensions.extend(metadata);

        let all_match = dimensions.iter().all(|d| d.matches);
        let match_count = dimensions.iter().filter(|d| d.matches).count();
        let total = dimensions.len();

        let verdict = if file_identical {
            VerificationVerdict::Identical
        } else if all_match {
            VerificationVerdict::ContentMatch
        } else if match_count > 0 {
            VerificationVerdict::PartialMatch
        } else {
            VerificationVerdict::NoMatch
        };

        VerificationReport {
            verdict,
            file_identical,
            dimensions,
            match_ratio: match_count as f64 / total as f64,
        }
    }
}

/// Result of comparing one dimension between two fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionMatch {
    pub dimension: String,
    pub matches: bool,
    pub status: String,
}

impl DimensionMatch {
    fn compare(name: &str, a: &str, b: &str) -> Self {
        let matches = a == b;
        Self {
            dimension: name.to_string(),
            matches,
            status: if matches {
                "identical".into()
            } else {
                "modified".into()
            },
        }
    }

    fn compare_optional(name: &str, a: &Option<String>, b: &Option<String>) -> Option<Self> {
        match (a, b) {
            (Some(av), Some(bv)) => Some(Self::compare(name, av, bv)),
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => Some(Self {
                dimension: name.to_string(),
                matches: false,
                status: "dimension_mismatch".into(),
            }),
        }
    }
}

/// Overall verdict of a document verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    /// Canonical hashes are byte-identical.
    Identical,
    /// File differs but all content dimensions match.
    ContentMatch,
    /// Some dimensions match, some don't.
    PartialMatch,
    /// Nothing matches.
    NoMatch,
}

impl std::fmt::Display for VerificationVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identical => write!(f, "identical"),
            Self::ContentMatch => write!(f, "content_match"),
            Self::PartialMatch => write!(f, "partial_match"),
            Self::NoMatch => write!(f, "no_match"),
        }
    }
}

/// Full verification report comparing a candidate against a registered fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub verdict: VerificationVerdict,
    pub file_identical: bool,
    pub dimensions: Vec<DimensionMatch>,
    pub match_ratio: f64,
}

/// Compute a simple merkle root from leaf hashes.
/// For odd leaf counts, the last leaf is duplicated.
fn merkle_root(leaves: &[[u8; 32]], algorithm: HashAlgorithm) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current: Vec<[u8; 32]> = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for chunk in current.chunks(2) {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&chunk[0]);
            if chunk.len() == 2 {
                combined.extend_from_slice(&chunk[1]);
            } else {
                combined.extend_from_slice(&chunk[0]);
            }
            next.push(hash_with(algorithm, &combined));
        }
        current = next;
    }
    current[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash(seed: u8) -> String {
        hex::encode(hash_with(HashAlgorithm::Sha256, &[seed]))
    }

    fn make_fingerprint(content_seed: u8, structure_seed: u8) -> DocumentFingerprint {
        let content_hash = sample_hash(content_seed);
        let structure_hash = sample_hash(structure_seed);
        let canonical_hash = DocumentFingerprint::compute_canonical_hash(
            &content_hash,
            &structure_hash,
            None,
            None,
            None,
            HashAlgorithm::Sha256,
        );
        DocumentFingerprint {
            content_hash,
            structure_hash,
            tables_hash: None,
            images_hash: None,
            metadata_hash: None,
            canonical_hash,
        }
    }

    #[test]
    fn canonical_hash_is_deterministic() {
        let fp1 = make_fingerprint(1, 2);
        let fp2 = make_fingerprint(1, 2);
        assert_eq!(fp1.canonical_hash, fp2.canonical_hash);
    }

    #[test]
    fn canonical_hash_changes_with_content() {
        let fp1 = make_fingerprint(1, 2);
        let fp2 = make_fingerprint(3, 2);
        assert_ne!(fp1.canonical_hash, fp2.canonical_hash);
    }

    #[test]
    fn verify_integrity_passes_for_valid_fingerprint() {
        let fp = make_fingerprint(1, 2);
        assert!(fp.verify_integrity(HashAlgorithm::Sha256));
    }

    #[test]
    fn verify_integrity_fails_for_tampered_canonical() {
        let mut fp = make_fingerprint(1, 2);
        fp.canonical_hash = sample_hash(99);
        assert!(!fp.verify_integrity(HashAlgorithm::Sha256));
    }

    #[test]
    fn identical_fingerprints_produce_identical_verdict() {
        let fp = make_fingerprint(1, 2);
        let report = fp.verify_against(&fp);
        assert_eq!(report.verdict, VerificationVerdict::Identical);
        assert!(report.file_identical);
        assert_eq!(report.match_ratio, 1.0);
    }

    #[test]
    fn same_content_different_canonical_produces_content_match() {
        let fp1 = make_fingerprint(1, 2);
        let mut fp2 = make_fingerprint(1, 2);
        // Same dimensions but different canonical (simulates re-hashed file)
        fp2.canonical_hash = "ff".repeat(32);
        let report = fp1.verify_against(&fp2);
        assert_eq!(report.verdict, VerificationVerdict::ContentMatch);
        assert!(!report.file_identical);
    }

    #[test]
    fn different_structure_produces_partial_match() {
        let fp1 = make_fingerprint(1, 2);
        let fp2 = make_fingerprint(1, 3);
        let report = fp1.verify_against(&fp2);
        assert_eq!(report.verdict, VerificationVerdict::PartialMatch);
        assert_eq!(report.match_ratio, 0.5);
    }

    #[test]
    fn completely_different_produces_no_match() {
        let fp1 = make_fingerprint(1, 2);
        let fp2 = make_fingerprint(3, 4);
        let report = fp1.verify_against(&fp2);
        assert_eq!(report.verdict, VerificationVerdict::NoMatch);
        assert_eq!(report.match_ratio, 0.0);
    }

    #[test]
    fn optional_dimensions_included_when_present() {
        let content_hash = sample_hash(1);
        let structure_hash = sample_hash(2);
        let tables_hash = Some(sample_hash(3));
        let canonical_hash = DocumentFingerprint::compute_canonical_hash(
            &content_hash,
            &structure_hash,
            tables_hash.as_deref(),
            None,
            None,
            HashAlgorithm::Sha256,
        );
        let fp = DocumentFingerprint {
            content_hash,
            structure_hash,
            tables_hash,
            images_hash: None,
            metadata_hash: None,
            canonical_hash,
        };
        assert!(fp.verify_integrity(HashAlgorithm::Sha256));
    }

    #[test]
    fn all_dimensions_present() {
        let ch = sample_hash(1);
        let sh = sample_hash(2);
        let th = Some(sample_hash(3));
        let ih = Some(sample_hash(4));
        let mh = Some(sample_hash(5));
        let canonical = DocumentFingerprint::compute_canonical_hash(
            &ch,
            &sh,
            th.as_deref(),
            ih.as_deref(),
            mh.as_deref(),
            HashAlgorithm::Sha256,
        );
        let fp = DocumentFingerprint {
            content_hash: ch,
            structure_hash: sh,
            tables_hash: th,
            images_hash: ih,
            metadata_hash: mh,
            canonical_hash: canonical,
        };
        assert!(fp.verify_integrity(HashAlgorithm::Sha256));

        let report = fp.verify_against(&fp);
        assert_eq!(report.verdict, VerificationVerdict::Identical);
        assert_eq!(report.dimensions.len(), 5);
    }

    #[test]
    fn merkle_root_single_leaf() {
        let leaf = hash_with(HashAlgorithm::Sha256, b"single");
        let root = merkle_root(&[leaf], HashAlgorithm::Sha256);
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_root_empty_returns_zeros() {
        let root = merkle_root(&[], HashAlgorithm::Sha256);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn merkle_root_order_matters() {
        let a = hash_with(HashAlgorithm::Sha256, b"a");
        let b = hash_with(HashAlgorithm::Sha256, b"b");
        let root_ab = merkle_root(&[a, b], HashAlgorithm::Sha256);
        let root_ba = merkle_root(&[b, a], HashAlgorithm::Sha256);
        assert_ne!(root_ab, root_ba);
    }

    #[test]
    fn sha3_produces_different_canonical() {
        let fp_sha2 = DocumentFingerprint::compute_canonical_hash(
            &sample_hash(1),
            &sample_hash(2),
            None,
            None,
            None,
            HashAlgorithm::Sha256,
        );
        let fp_sha3 = DocumentFingerprint::compute_canonical_hash(
            &sample_hash(1),
            &sample_hash(2),
            None,
            None,
            None,
            HashAlgorithm::Sha3_256,
        );
        assert_ne!(fp_sha2, fp_sha3);
    }

    #[test]
    fn serialization_roundtrip() {
        let fp = make_fingerprint(1, 2);
        let json = serde_json::to_string(&fp).unwrap();
        let fp2: DocumentFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, fp2);
    }

    #[test]
    fn dimension_mismatch_when_one_side_missing() {
        let mut fp1 = make_fingerprint(1, 2);
        fp1.tables_hash = Some(sample_hash(3));
        let fp2 = make_fingerprint(1, 2);
        let report = fp1.verify_against(&fp2);
        let tables_dim = report
            .dimensions
            .iter()
            .find(|d| d.dimension == "tables")
            .unwrap();
        assert!(!tables_dim.matches);
        assert_eq!(tables_dim.status, "dimension_mismatch");
    }
}
