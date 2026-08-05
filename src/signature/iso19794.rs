//! ISO/IEC 19794-2:2005 fingerprint minutiae template parser.
//!
//! Validates that a byte buffer is a structurally valid fingerprint minutiae
//! record before it gets hashed into a biometric commitment. This prevents
//! garbage data from being accepted as biometric evidence.
//!
//! Only parses the fixed header + minutiae records. Does NOT interpret
//! the minutiae geometrically (matching is out of scope).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Iso19794Error {
    #[error("template too short: need >= {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("invalid magic: expected 'FMR\\0' (0x464D5200), got 0x{got:08X}")]
    BadMagic { got: u32 },
    #[error("unsupported version: expected '020\\0' (0x20323000), got 0x{got:08X}")]
    BadVersion { got: u32 },
    #[error("record length {declared} exceeds buffer size {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("no minutiae in record (count = 0)")]
    NoMinutiae,
    #[error("minutiae data truncated: need {expected} bytes, got {got}")]
    MinutiaeTruncated { expected: usize, got: usize },
    #[error("minutia type {0} is invalid (must be 0, 1, or 2)")]
    InvalidMinutiaType(u8),
}

/// A single minutia point extracted from the template.
#[derive(Debug, Clone)]
pub struct Minutia {
    pub minutia_type: MinutiaType,
    pub x: u16,
    pub y: u16,
    pub angle: u8,
    pub quality: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinutiaType {
    Other,
    RidgeEnding,
    RidgeBifurcation,
}

/// Parsed fingerprint minutiae record header.
#[derive(Debug, Clone)]
pub struct FingerprintRecord {
    pub width: u16,
    pub height: u16,
    pub resolution_x: u16,
    pub resolution_y: u16,
    pub minutiae: Vec<Minutia>,
}

// ISO 19794-2:2005 constants
const MAGIC: u32 = 0x464D_5200; // "FMR\0"
const VERSION: u32 = 0x2032_3000; // " 20\0"
const GENERAL_HEADER_LEN: usize = 24;
const FINGER_VIEW_HEADER_LEN: usize = 4;
const MINUTIA_LEN: usize = 6;

/// Parse and validate an ISO 19794-2:2005 fingerprint minutiae template.
///
/// Returns the parsed record if valid, or an error describing what's wrong.
pub fn parse_fingerprint_template(data: &[u8]) -> Result<FingerprintRecord, Iso19794Error> {
    if data.len() < GENERAL_HEADER_LEN {
        return Err(Iso19794Error::TooShort {
            expected: GENERAL_HEADER_LEN,
            got: data.len(),
        });
    }

    // Magic: "FMR\0"
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != MAGIC {
        return Err(Iso19794Error::BadMagic { got: magic });
    }

    // Version: " 20\0"
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != VERSION {
        return Err(Iso19794Error::BadVersion { got: version });
    }

    // Total record length (bytes 8-11, big-endian u32)
    let record_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if record_len > data.len() {
        return Err(Iso19794Error::LengthMismatch {
            declared: record_len,
            actual: data.len(),
        });
    }

    // Image size (bytes 14-17)
    let width = u16::from_be_bytes([data[14], data[15]]);
    let height = u16::from_be_bytes([data[16], data[17]]);

    // Resolution (bytes 18-21)
    let resolution_x = u16::from_be_bytes([data[18], data[19]]);
    let resolution_y = u16::from_be_bytes([data[20], data[21]]);

    // Finger view header starts at byte 26
    let fv_offset = GENERAL_HEADER_LEN;
    if data.len() < fv_offset + FINGER_VIEW_HEADER_LEN {
        return Err(Iso19794Error::TooShort {
            expected: fv_offset + FINGER_VIEW_HEADER_LEN,
            got: data.len(),
        });
    }

    // Number of minutiae (byte 27 in the finger view, which is offset 29 overall)
    // Finger view: [finger_position, view_number_impression_type, finger_quality, minutiae_count]
    let minutiae_count = data[fv_offset + 3] as usize;
    if minutiae_count == 0 {
        return Err(Iso19794Error::NoMinutiae);
    }

    // Minutiae data starts after finger view header
    let minutiae_offset = fv_offset + FINGER_VIEW_HEADER_LEN;
    let minutiae_end = minutiae_offset + minutiae_count * MINUTIA_LEN;
    if minutiae_end > data.len() {
        return Err(Iso19794Error::MinutiaeTruncated {
            expected: minutiae_count * MINUTIA_LEN,
            got: data.len() - minutiae_offset,
        });
    }

    let mut minutiae = Vec::with_capacity(minutiae_count);
    for i in 0..minutiae_count {
        let base = minutiae_offset + i * MINUTIA_LEN;
        // Bytes 0-1: type (2 bits) + x (14 bits)
        let type_x = u16::from_be_bytes([data[base], data[base + 1]]);
        let mt = (type_x >> 14) & 0x03;
        let x = type_x & 0x3FFF;
        // Bytes 2-3: reserved (2 bits) + y (14 bits)
        let res_y = u16::from_be_bytes([data[base + 2], data[base + 3]]);
        let y = res_y & 0x3FFF;
        // Byte 4: angle (0-255, maps to 0-<360°)
        let angle = data[base + 4];
        // Byte 5: quality (0-100, or 0 = not reported)
        let quality = data[base + 5];

        let minutia_type = match mt {
            0 => MinutiaType::Other,
            1 => MinutiaType::RidgeEnding,
            2 => MinutiaType::RidgeBifurcation,
            _ => return Err(Iso19794Error::InvalidMinutiaType(mt as u8)),
        };

        minutiae.push(Minutia {
            minutia_type,
            x,
            y,
            angle,
            quality,
        });
    }

    Ok(FingerprintRecord {
        width,
        height,
        resolution_x,
        resolution_y,
        minutiae,
    })
}

/// Validate that raw bytes are a structurally valid ISO 19794-2 template.
pub fn validate_fingerprint_template(data: &[u8]) -> Result<(), Iso19794Error> {
    parse_fingerprint_template(data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_template(minutiae_count: u8) -> Vec<u8> {
        let minutiae_bytes = minutiae_count as usize * MINUTIA_LEN;
        let total_len = (GENERAL_HEADER_LEN + FINGER_VIEW_HEADER_LEN + minutiae_bytes) as u32;
        let mut buf = Vec::new();

        // General header (26 bytes)
        buf.extend(b"FMR\0"); // magic
        buf.extend(&[0x20, 0x32, 0x30, 0x00]); // version " 20\0"
        buf.extend(total_len.to_be_bytes()); // record length
        buf.extend(&[0x00, 0x01]); // capture equipment (placeholder)
        buf.extend(&[0x01, 0x40]); // width = 320
        buf.extend(&[0x01, 0x90]); // height = 400
        buf.extend(&[0x01, 0xF4]); // resolution_x = 500 ppi
        buf.extend(&[0x01, 0xF4]); // resolution_y = 500 ppi
        buf.extend(&[0x01]); // number of finger views
        buf.push(0x00); // reserved

        // Finger view header (4 bytes)
        buf.push(0x01); // finger position (right index)
        buf.push(0x00); // view number + impression type
        buf.push(80); // finger quality
        buf.push(minutiae_count);

        // Minutiae data
        for i in 0..minutiae_count as u16 {
            // type=ridge_ending(01) + x=100+i
            let type_x: u16 = (1 << 14) | (100 + i);
            buf.extend(type_x.to_be_bytes());
            // reserved(00) + y=200+i
            let y: u16 = 200 + i;
            buf.extend(y.to_be_bytes());
            buf.push(45 + i as u8); // angle
            buf.push(80); // quality
        }

        buf
    }

    #[test]
    fn valid_template_parses() {
        let tmpl = make_valid_template(5);
        let record = parse_fingerprint_template(&tmpl).unwrap();
        assert_eq!(record.width, 320);
        assert_eq!(record.height, 400);
        assert_eq!(record.resolution_x, 500);
        assert_eq!(record.minutiae.len(), 5);
    }

    #[test]
    fn minutiae_fields_correct() {
        let tmpl = make_valid_template(1);
        let record = parse_fingerprint_template(&tmpl).unwrap();
        let m = &record.minutiae[0];
        assert_eq!(m.minutia_type, MinutiaType::RidgeEnding);
        assert_eq!(m.x, 100);
        assert_eq!(m.y, 200);
        assert_eq!(m.angle, 45);
        assert_eq!(m.quality, 80);
    }

    #[test]
    fn too_short_rejected() {
        let err = parse_fingerprint_template(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, Iso19794Error::TooShort { .. }));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut tmpl = make_valid_template(1);
        tmpl[0] = 0x00; // corrupt magic
        let err = parse_fingerprint_template(&tmpl).unwrap_err();
        assert!(matches!(err, Iso19794Error::BadMagic { .. }));
    }

    #[test]
    fn bad_version_rejected() {
        let mut tmpl = make_valid_template(1);
        tmpl[4] = 0xFF;
        let err = parse_fingerprint_template(&tmpl).unwrap_err();
        assert!(matches!(err, Iso19794Error::BadVersion { .. }));
    }

    #[test]
    fn length_mismatch_rejected() {
        let mut tmpl = make_valid_template(1);
        // Set record length way larger than buffer
        tmpl[8..12].copy_from_slice(&999u32.to_be_bytes());
        let err = parse_fingerprint_template(&tmpl).unwrap_err();
        assert!(matches!(err, Iso19794Error::LengthMismatch { .. }));
    }

    #[test]
    fn zero_minutiae_rejected() {
        let mut tmpl = make_valid_template(1);
        tmpl[GENERAL_HEADER_LEN + 3] = 0; // set count to 0
        let err = parse_fingerprint_template(&tmpl).unwrap_err();
        assert!(matches!(err, Iso19794Error::NoMinutiae));
    }

    #[test]
    fn truncated_minutiae_rejected() {
        let mut tmpl = make_valid_template(1);
        let trunc_len = GENERAL_HEADER_LEN + FINGER_VIEW_HEADER_LEN + 3;
        // Fix declared record length to match truncated buffer
        let len_bytes = (trunc_len as u32).to_be_bytes();
        tmpl[8..12].copy_from_slice(&len_bytes);
        tmpl.truncate(trunc_len);
        let err = parse_fingerprint_template(&tmpl).unwrap_err();
        assert!(matches!(err, Iso19794Error::MinutiaeTruncated { .. }));
    }

    #[test]
    fn multiple_minutiae() {
        let tmpl = make_valid_template(10);
        let record = parse_fingerprint_template(&tmpl).unwrap();
        assert_eq!(record.minutiae.len(), 10);
        for (i, m) in record.minutiae.iter().enumerate() {
            assert_eq!(m.x, 100 + i as u16);
            assert_eq!(m.y, 200 + i as u16);
        }
    }

    #[test]
    fn validate_returns_ok_for_valid() {
        let tmpl = make_valid_template(3);
        assert!(validate_fingerprint_template(&tmpl).is_ok());
    }

    #[test]
    fn validate_returns_err_for_garbage() {
        assert!(validate_fingerprint_template(&[0xFF; 50]).is_err());
    }

    #[test]
    fn bifurcation_type_parsed() {
        let mut tmpl = make_valid_template(1);
        // Set type bits to 10 (bifurcation)
        let base = GENERAL_HEADER_LEN + FINGER_VIEW_HEADER_LEN;
        let type_x: u16 = (2 << 14) | 100;
        tmpl[base..base + 2].copy_from_slice(&type_x.to_be_bytes());
        let record = parse_fingerprint_template(&tmpl).unwrap();
        assert_eq!(
            record.minutiae[0].minutia_type,
            MinutiaType::RidgeBifurcation
        );
    }

    #[test]
    fn other_type_parsed() {
        let mut tmpl = make_valid_template(1);
        let base = GENERAL_HEADER_LEN + FINGER_VIEW_HEADER_LEN;
        let type_x: u16 = (0 << 14) | 100; // type=other
        tmpl[base..base + 2].copy_from_slice(&type_x.to_be_bytes());
        let record = parse_fingerprint_template(&tmpl).unwrap();
        assert_eq!(record.minutiae[0].minutia_type, MinutiaType::Other);
    }

    #[test]
    fn empty_buffer_rejected() {
        assert!(parse_fingerprint_template(&[]).is_err());
    }
}
