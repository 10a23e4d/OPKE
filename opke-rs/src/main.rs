//! Main executable entrypoint for OPKE v3.0.

use clap::Parser;
use std::process;

use opke::cli::args::{Cli, Commands};
use opke::cli::{cmd_benchmark, cmd_decrypt, cmd_encrypt, cmd_inspect, wizard};

fn main() {
    // Disable core dumps and crash report dialogs (WER) to prevent memory dumps to disk (VULN-44)
    #[cfg(windows)]
    unsafe {
        extern "system" {
            fn SetErrorMode(uMode: u32) -> u32;
        }
        SetErrorMode(0x0001 | 0x0002);
    }
    #[cfg(unix)]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    // Register clean SIGINT/Ctrl+C handler to prevent dangling secrets (VULN-56)
    let _ = ctrlc::set_handler(move || {
        eprintln!("\n[!] 中断シグナル (Ctrl+C) を受信しました。終了します。");
        process::exit(130);
    });

    // If launched without any command-line arguments (e.g. double-clicked from Explorer),
    // launch the interactive wizard mode.
    if std::env::args().len() <= 1 {
        if let Err(e) = wizard::run_interactive_wizard() {
            eprintln!("[-] Error: {}", e);
            wizard::pause_for_exit();
            process::exit(1);
        }
        return;
    }

    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Encrypt(args)) => cmd_encrypt::execute(args),
        Some(Commands::Decrypt(args)) => cmd_decrypt::execute(args),
        Some(Commands::Inspect(args)) => cmd_inspect::execute(args),
        Some(Commands::Benchmark(args)) => cmd_benchmark::execute(args),
        None => wizard::run_interactive_wizard(),
    };

    if let Err(e) = result {
        if let opke::error::OpkeError::Io(ref io_err) = e {
            if io_err.kind() == std::io::ErrorKind::BrokenPipe {
                process::exit(0);
            }
        }
        eprintln!("[-] Error: {}", e);
        process::exit(1);
    }
}
