//! Interactive Wizard mode for double-click and guided operation.

use crate::error::OpkeError;
use std::io::{self, IsTerminal, Write};

use super::args::{BenchmarkArgs, DecryptArgs, EncryptArgs, InspectArgs};
use super::{cmd_benchmark, cmd_decrypt, cmd_encrypt, cmd_inspect};

/// Waits for the user to press Enter before exiting, preventing console window from closing on double-click.
pub fn pause_for_exit() {
    if !io::stdin().is_terminal() {
        return;
    }
    println!();
    print!("[*] Press Enter to exit...");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

/// Prompts user for a line of text, automatically trimming surrounding quotes (Windows drag-and-drop).
/// Returns OpkeError::Validation on EOF to prevent infinite busy loops.
pub fn prompt_line(prompt: &str) -> Result<String, OpkeError> {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line)?;
    if n == 0 {
        return Err(OpkeError::Validation("End of input (EOF) reached.".into()));
    }
    let mut s = line.trim();
    while s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s = s[1..s.len() - 1].trim();
    }
    Ok(s.to_string())
}

/// Prompts for an output file path, prompting to confirm overwrite if file exists.
/// Supports default fallback and skipping/optional input.
fn prompt_destination_file(
    prompt: &str,
    default: Option<&str>,
) -> Result<Option<String>, OpkeError> {
    loop {
        let input = prompt_line(prompt)?;
        let path_str = if input.is_empty() {
            match default {
                Some(d) => d.to_string(),
                None => return Ok(None),
            }
        } else {
            input
        };

        if path_str.eq_ignore_ascii_case("skip") {
            return Ok(None);
        }

        let p = std::path::Path::new(&path_str);
        if p.exists() {
            eprintln!(
                "[!] Warning: Destination file '{}' already exists.",
                p.display()
            );
            let ans = prompt_line("Overwrite? (y/N): ")?;
            if ans.eq_ignore_ascii_case("y") {
                return Ok(Some(path_str));
            } else {
                println!("[*] Please specify a different output file path.");
                continue;
            }
        } else {
            return Ok(Some(path_str));
        }
    }
}

pub fn run_interactive_wizard() -> Result<(), OpkeError> {
    loop {
        println!();
        println!("============================================================");
        println!("       OPKE v3.1 (Offline Paper-Key Encryptor)             ");
        println!("       Offline Paper-Key Encryption Utility                 ");
        println!("============================================================");
        println!(" [1] Encrypt Secret (Encrypt -> Paper Key / QR)");
        println!(" [2] Decrypt Paper Key (Decrypt -> Secret)");
        println!(" [3] Inspect Envelope Metadata (Inspect Envelope)");
        println!(" [4] Benchmark Hardware (Benchmark)");
        println!(" [5] Exit");
        println!("============================================================");

        let choice = match prompt_line("Select operation [1-5]: ") {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] {}", e);
                break;
            }
        };

        match choice.as_str() {
            "1" => {
                println!();
                println!("--- [1] Encrypt Secret Wizard ---");

                println!("Select KDF profile:");
                println!("  [1] production (Recommended: 8 GiB, 64 iters - Maximum Strength)");
                println!("  [2] moderate   (1 GiB, 16 iters - Standard)");
                println!("  [3] fast       (64 MiB, 2 iters - Fast Testing)");
                let prof_choice = prompt_line("Profile [1-3, default: 1]: ")?;
                let profile = match prof_choice.as_str() {
                    "2" => "moderate",
                    "3" => "fast",
                    _ => "production",
                };

                let in_file =
                    prompt_line("Read secret from file? (Leave empty for direct entry): ")?;
                let input_file = if in_file.is_empty() {
                    None
                } else {
                    Some(in_file)
                };

                let output = prompt_destination_file(
                    "Paper key output file [default: paper_key.txt, 'skip' for console only]: ",
                    Some("paper_key.txt"),
                )?;

                let qr = prompt_destination_file(
                    "QR code image output file [default: paper_key.png, 'skip' to skip]: ",
                    Some("paper_key.png"),
                )?;

                let qr_term_ans = prompt_line("Display QR code in terminal? (Y/n): ")?;
                let qr_term = !qr_term_ans.eq_ignore_ascii_case("n");
                let overwrite = output
                    .as_ref()
                    .is_some_and(|p| std::path::Path::new(p).exists())
                    || qr
                        .as_ref()
                        .is_some_and(|p| std::path::Path::new(p).exists());

                let args = EncryptArgs {
                    secret: None,
                    input_file,
                    passphrase: None,
                    output,
                    profile: profile.to_string(),
                    mem: None,
                    time: None,
                    threads: None,
                    qr,
                    qr_term,
                    raw: false,
                    multiline: false,
                    v2: false,
                    overwrite,
                    force: false,
                };

                if let Err(e) = cmd_encrypt::execute(args) {
                    eprintln!("[-] Encryption failed: {}", e);
                } else {
                    println!("[+] Encryption completed successfully!");
                }
            }
            "2" => {
                println!();
                println!("--- [2] Decrypt Paper Key Wizard ---");

                let in_file = prompt_line("Paper key file path [default: paper_key.txt]: ")?;
                let input_file = if in_file.is_empty() {
                    Some("paper_key.txt".to_string())
                } else {
                    Some(in_file)
                };

                let output = prompt_destination_file(
                    "Save decrypted plaintext to file (leave empty for console display): ",
                    None,
                )?;

                // Warn user about shoulder surfing before direct screen output
                if output.is_none() {
                    println!(
                        "[!] Warning: Without an output file, plaintext will be printed directly to the console."
                    );
                    println!("    Please ensure no one is shoulder-surfing your screen.");
                    let confirm = prompt_line("Proceed with console display? (y/N): ")?;
                    if !confirm.trim().eq_ignore_ascii_case("y") {
                        println!("[-] Decryption canceled.");
                        continue;
                    }
                }

                let overwrite = output
                    .as_ref()
                    .is_some_and(|p| std::path::Path::new(p).exists());

                let args = DecryptArgs {
                    input: None,
                    input_file,
                    passphrase: None,
                    output,
                    max_mem: None,
                    max_time: None,
                    max_threads: None,
                    allow_v2: false,
                    overwrite,
                    force: false,
                };

                if let Err(e) = cmd_decrypt::execute(args) {
                    eprintln!("[-] Decryption failed: {}", e);
                } else {
                    println!("\n[+] Decryption completed successfully!");
                }
            }
            "3" => {
                println!();
                println!("--- [3] Inspect Envelope Metadata ---");
                let in_file = prompt_line("Paper key file to inspect [default: paper_key.txt]: ")?;
                let input_file = if in_file.is_empty() {
                    Some("paper_key.txt".to_string())
                } else {
                    Some(in_file)
                };

                let args = InspectArgs {
                    input: None,
                    input_file,
                };

                if let Err(e) = cmd_inspect::execute(args) {
                    eprintln!("[-] Inspection error: {}", e);
                }
            }
            "4" => {
                println!();
                println!("--- [4] Hardware Benchmark ---");
                println!("Select profile to benchmark:");
                println!("  [1] production (8 GiB, 64 iters)");
                println!("  [2] moderate   (1 GiB, 16 iters)");
                println!("  [3] fast       (64 MiB, 2 iters)");
                let prof_choice = prompt_line("Profile [1-3, default: 3 (fast test)]: ")?;
                let profile = match prof_choice.as_str() {
                    "1" => "production",
                    "2" => "moderate",
                    _ => "fast",
                };

                let args = BenchmarkArgs {
                    profile: profile.to_string(),
                    mem: None,
                    time: None,
                    threads: None,
                    force: false,
                };

                if let Err(e) = cmd_benchmark::execute(args) {
                    eprintln!("[-] Benchmark error: {}", e);
                }
            }
            "5" | "q" | "exit" => {
                println!("Exiting.");
                break;
            }
            _ => {
                println!("[-] Invalid choice. Please enter a number between 1 and 5.");
            }
        }
    }

    pause_for_exit();
    Ok(())
}
