#[derive(Debug, Clone)]
pub struct CertifiedKeyDer {
    pub cert_der: Vec<u8>,
    /// Pkcs8
    pub key_der: Vec<u8>,
}

pub fn generate_crl(
    issuer: &rcgen::Issuer<rcgen::KeyPair>,
) -> Result<Vec<u8>, rcgen::Error> {
    let now = rcgen::date_time_ymd(2026, 1, 1);
    let next = rcgen::date_time_ymd(2036, 1, 1);
    let crl_params = rcgen::CertificateRevocationListParams {
        this_update: now,
        next_update: next,
        crl_number: rcgen::SerialNumber::from(1),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl = crl_params.signed_by(issuer)?;
    Ok(crl.der().to_vec())
}

static CRL_URL: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

pub fn set_crl_distribution_point(url: String) {
    if let Ok(mut lock) = CRL_URL.write() {
        *lock = Some(url);
    }
}

pub fn get_crl_distribution_point() -> Option<String> {
    CRL_URL.read().ok().and_then(|lock| lock.clone())
}

pub fn generate_cert(
    host: String,
    issuer: &rcgen::Issuer<rcgen::KeyPair>,
) -> Result<CertifiedKeyDer, rcgen::Error> {
    let mut cert_params = rcgen::CertificateParams::new(vec![host.clone()])?;
    let crl_uri = get_crl_distribution_point()
        .unwrap_or_else(|| "http://127.0.0.1:8877/ca.crl".to_string());
    cert_params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    cert_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    cert_params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, host);
        dn
    };

    let key_pair = rcgen::KeyPair::generate()?;

    let cert = cert_params.signed_by(&key_pair, issuer)?;

    Ok(CertifiedKeyDer {
        cert_der: cert.der().to_vec(),
        key_der: key_pair.serialize_der(),
    })
}
