use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use native_tls::{TlsConnector, TlsStream};
use sha2::{Sha256, Digest};
use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_proto::rr::rdata::TLSA;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::tlsa::Selector;
use hex;
use x509_parser::prelude::*;

fn main() {
    // Read URL from command line
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <gemini-url>", args[0]);
        std::process::exit(1);
    }

    let gemini_url = &args[1];

    match fetch_gemini_page(gemini_url) {
        Ok(_) => println!("Done."),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn fetch_gemini_page(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (hostname, path) = parse_gemini_url(url)?;
    let stream = TcpStream::connect((hostname.as_str(), 1965))?;
    
    // Create TLS connector (DISABLE CERTIFICATE VALIDATION)
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true) // 🔥 Allow self-signed certs (so we can manually verify them)
        .danger_accept_invalid_hostnames(true) // Optional: Ignore hostname mismatches
        .build()?;
    
    let mut stream = connector.connect(&hostname, stream)?;

    // Check TLSA record for DANE verification
    if let Some(tlsa_record) = get_tlsa_record(&hostname) {
        if !verify_tlsa(&mut stream, &tlsa_record) {
            return Err("TLS certificate does not match TLSA record".into());
        }
    } else {
        println!("No TLSA record found. Falling back to TOFU.");
        verify_tofu(&hostname, &mut stream)?;
    }

    // Send the Gemini request
    let request = format!("gemini://{}{}\r\n", hostname, path);
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    // Read and process response
    process_gemini_response(stream)?;

    Ok(())
}

/// Parses a Gemini URL into hostname and path, adding "gemini://" if missing.
fn parse_gemini_url(url: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let url = if url.starts_with("gemini://") {
        url.to_string()
    } else {
        format!("gemini://{}", url)
    };

    let stripped = url.strip_prefix("gemini://").ok_or("Invalid URL scheme")?;
    let parts: Vec<&str> = stripped.splitn(2, '/').collect();
    let hostname = parts[0].to_string();
    let path = if parts.len() > 1 { format!("/{}", parts[1]) } else { String::from("/") };
    Ok((hostname, path))
}

/// Fetches the TLSA record for the given hostname and port 1965.
fn get_tlsa_record(hostname: &str) -> Option<TLSA> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).ok()?;
    let lookup = resolver.lookup(format!("_1965._tcp.{}", hostname), hickory_proto::rr::RecordType::TLSA).ok()?;
    
    for record in lookup.iter() {
        if let RData::TLSA(tlsa) = record {
            return Some(tlsa.clone());
        }
    }
    None
}

/// Verifies the TLS certificate against a TLSA record.
fn verify_tlsa(stream: &mut TlsStream<TcpStream>, tlsa_record: &TLSA) -> bool {
    if let Ok(Some(cert)) = stream.peer_certificate() {
        if let Ok(cert_der) = cert.to_der() {
            let data_to_check = match tlsa_record.selector() {
                Selector::Full => {
                    cert_der.clone()
                }
                Selector::Spki => {
                    extract_spki_from_cert(&cert_der)
                }
                _ => {
                    println!("⚠️ Unsupported TLSA selector type.");
                    return false;
                }
            };

            let fingerprint = match tlsa_record.matching() {
                hickory_proto::rr::rdata::tlsa::Matching::Sha256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(&data_to_check);
                    hasher.finalize().to_vec()
                }
                hickory_proto::rr::rdata::tlsa::Matching::Sha512 => {
                    use sha2::Sha512;
                    let mut hasher = Sha512::new();
                    hasher.update(&data_to_check);
                    hasher.finalize().to_vec()
                }
                hickory_proto::rr::rdata::tlsa::Matching::Raw => {
                    data_to_check.clone()
                }
                _ => {
                    println!("⚠️ Unsupported TLSA matching type.");
                    return false;
                }
            };

            if fingerprint == tlsa_record.cert_data() {
                println!("✅ TLS certificate matches TLSA record.");
                return true;
            } else {
                println!("❌ TLS certificate does NOT match TLSA record!");
                return false;
            }
        }
    }
    false
}

/// Extracts the Subject Public Key Info (SPKI) from a DER-encoded certificate.
fn extract_spki_from_cert(cert_der: &[u8]) -> Vec<u8> {
    if let Ok((_, cert)) = X509Certificate::from_der(cert_der) {
        return cert.public_key().raw.to_vec();
    }
    vec![]
}

/// Implements TOFU (Trust On First Use) for certificate verification.
fn verify_tofu(hostname: &str, stream: &mut TlsStream<TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
    let cert_file = format!("{}.cert", hostname);

    if let Ok(Some(cert)) = stream.peer_certificate() {
        if let Ok(cert_der) = cert.to_der() {
            let mut hasher = Sha256::new();
            hasher.update(&cert_der);
            let fingerprint = hex::encode(hasher.finalize());

            if Path::new(&cert_file).exists() {
                let stored_fingerprint = fs::read_to_string(&cert_file)?.trim().to_string();
                if stored_fingerprint != fingerprint {
                    return Err("Certificate fingerprint mismatch! Possible MITM attack.".into());
                }
            } else {
                println!("First time connecting to {}. Trusting certificate.", hostname);
                fs::write(cert_file, &fingerprint)?;
            }
        }
    }
    Ok(())
}

/// Reads and processes the Gemini response in a streaming manner.
fn process_gemini_response(mut stream: TlsStream<TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(&mut stream);
    let mut response_line = String::new();

    reader.read_line(&mut response_line)?;
    println!("Server Response: {}", response_line.trim());

    if response_line.starts_with("20 ") {
        println!("--- Gemini Page Content ---");
        for line in reader.lines() {
            match line {
                Ok(text) => println!("{}", text),
                Err(e) => return Err(Box::new(e)),
            }
        }
    } else {
        println!("Non-success status code received.");
    }

    Ok(())
}
