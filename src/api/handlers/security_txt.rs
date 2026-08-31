use actix_web::{get, HttpResponse};

const SECURITY_TXT: &str = "\
Contact: mailto:security@goya.cl\n\
Contact: https://github.com/clementeaf/goya-ledger/security/advisories/new\n\
Expires: 2027-08-31T23:59:59.000Z\n\
Preferred-Languages: en, es\n\
Canonical: https://goya.cl/.well-known/security.txt\n\
Policy: https://github.com/clementeaf/goya-ledger/blob/main/SECURITY.md\n\
";

#[get("/.well-known/security.txt")]
pub async fn security_txt() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(SECURITY_TXT)
}
