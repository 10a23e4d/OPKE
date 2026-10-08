//! Main executable entrypoint for OPKE v3.0.

use clap::Parser;
use std::process;

use opke::cli::args::{Cli, Commands};
use opke::cli::{cmd_benchmark, cmd_decrypt, cmd_encrypt, cmd_inspect, wizard};

fn main() {
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
        eprintln!("[-] Error: {}", e);
        process::exit(1);
    }
}
