//! DER-encoded CMS for PAdES-BES (ETSI TS 102 778).
//!
//! PAdES embeds a CMS SignedData (CAdES-BES) in the PDF `/Contents` field.
//! The `content` parameter should be the PDF byte range (everything except
//! the `/Contents` hex placeholder). PDF embedding is out of scope here;
//! this produces the raw CMS blob that would go into `/Contents`.

// ponytail: PAdES DER = CAdES DER; the only difference is WHAT is signed
// (PDF byte range vs arbitrary content). Same CMS structure, same code.
#[allow(unused_imports)]
pub use crate::signature::cades_der::build_cades_bes_der as build_pades_bes_der;
#[allow(unused_imports)]
pub use crate::signature::cades_der::verify_cades_bes_der as verify_pades_bes_der;
#[allow(unused_imports)]
pub use crate::signature::cades_der::CadesDerError as PadesDerError;
#[allow(unused_imports)]
pub use crate::signature::cades_der::CadesDerFields as PadesDerFields;
