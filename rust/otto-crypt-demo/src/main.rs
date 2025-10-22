use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use otto_crypt::{Otto, DEFAULT_CHUNK_SIZE};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name="otto-crypt-demo", version, about="Demo app for OTTO encryption (text + any files incl. photo/audio/video)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt+decrypt a text message
    Text {
        /// Base64 32-byte raw key
        #[arg(long, env="OTTO_RAWKEY_B64")]
        key_b64: String,
        /// Message to encrypt
        #[arg(long)]
        message: String,
    },
    /// Encrypt+decrypt a file (any type: photo/audio/video/docs)
    File {
        #[arg(long, env="OTTO_RAWKEY_B64")]
        key_b64: String,
        /// Input file path
        #[arg(long)]
        input: PathBuf,
        /// Output encrypted file path (default: <input>.otto)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Decrypted file output (default: <input>.dec)
        #[arg(long)]
        output_dec: Option<PathBuf>,
        /// Chunk size (bytes)
        #[arg(long, default_value_t=DEFAULT_CHUNK_SIZE)]
        chunk: usize,
    },
    /// Encrypt+decrypt all files in a directory (recursively)
    Batch {
        #[arg(long, env="OTTO_RAWKEY_B64")]
        key_b64: String,
        /// Directory with sample files (images/audio/video/anything)
        #[arg(long, default_value = "./samples")]
        dir: PathBuf,
        /// Output directory for encrypted files
        #[arg(long, default_value = "./out")]
        out: PathBuf,
        /// Chunk size (bytes)
        #[arg(long, default_value_t=DEFAULT_CHUNK_SIZE)]
        chunk: usize,
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Text { key_b64, message } => cmd_text(&key_b64, &message),
        Commands::File { key_b64, input, output, output_dec, chunk } =>
            cmd_file(&key_b64, &input, output.as_ref(), output_dec.as_ref(), chunk),
        Commands::Batch { key_b64, dir, out, chunk } =>
            cmd_batch(&key_b64, &dir, &out, chunk),
    }
}

fn decode_key32(b64: &str) -> Result<[u8;32]> {
    let v = general_purpose::STANDARD.decode(b64).context("invalid base64")?;
    if v.len()!=32 { anyhow::bail!("expected 32-byte key"); }
    let mut out = [0u8;32]; out.copy_from_slice(&v); Ok(out)
}

fn cmd_text(key_b64: &str, message: &str) -> Result<()> {
    let key = decode_key32(key_b64)?;
    let enc = Otto::encrypt_string(message.as_bytes(), &key)?;
    println!("HEADER_B64={}", general_purpose::STANDARD.encode(&enc.header));
    println!("CIPHER_B64={}", general_purpose::STANDARD.encode(&enc.cipher_and_tag));
    let dec = Otto::decrypt_string(&enc.cipher_and_tag, &enc.header, &key)?;
    println!("DECRYPTED={}", String::from_utf8_lossy(&dec));
    Ok(())
}

fn cmd_file(key_b64: &str, input: &Path, output: Option<&PathBuf>, output_dec: Option<&PathBuf>, chunk: usize) -> Result<()> {
    let key = decode_key32(key_b64)?;
    let out_enc = output.cloned().unwrap_or_else(|| PathBuf::from(format!("{}.otto", input.display())));
    let out_dec = output_dec.cloned().unwrap_or_else(|| PathBuf::from(format!("{}.dec", input.display())));

    println!("Encrypting {} -> {}", input.display(), out_enc.display());
    Otto::encrypt_file(input, &out_enc, &key, chunk)?;
    println!("Decrypting {} -> {}", out_enc.display(), out_dec.display());
    Otto::decrypt_file(&out_enc, &out_dec, &key)?;
    println!("Done.");
    Ok(())
}

fn cmd_batch(key_b64: &str, dir: &Path, out: &Path, chunk: usize) -> Result<()> {
    let key = decode_key32(key_b64)?;
    fs::create_dir_all(out).ok();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.metadata().map(|m| m.is_file()).unwrap_or(false) { continue; }
        let p = entry.path();
        // Skip already encrypted
        if p.extension().and_then(|s| s.to_str()) == Some("otto") { continue; }
        let rel = p.strip_prefix(dir).unwrap_or(p);
        let enc_out = out.join(rel).with_extension(format!("{}{}", rel.extension().and_then(|s| s.to_str()).unwrap_or(""), ".otto"));
        let dec_out = out.join(rel).with_extension(format!("{}{}", rel.extension().and_then(|s| s.to_str()).unwrap_or(""), ".dec"));
        if let Some(parent) = enc_out.parent() { fs::create_dir_all(parent).ok(); }
        println!("Encrypting {} -> {}", p.display(), enc_out.display());
        Otto::encrypt_file(p, &enc_out, &key, chunk)?;
        println!("Decrypting {} -> {}", enc_out.display(), dec_out.display());
        Otto::decrypt_file(&enc_out, &dec_out, &key)?;
    }
    println!("Batch complete. Output dir: {}", out.display());
    Ok(())
}
