//! Interactive Wizard mode for double-click and guided operation.

use std::io::{self, Write};
use crate::error::OpkeError;

use super::args::{BenchmarkArgs, DecryptArgs, EncryptArgs, InspectArgs};
use super::{cmd_benchmark, cmd_decrypt, cmd_encrypt, cmd_inspect};

/// Waits for the user to press Enter before exiting, preventing console window from closing on double-click.
pub fn pause_for_exit() {
    println!();
    print!("[*] Enterキーを押すと終了します...");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

/// Prompts user for a line of text, automatically trimming surrounding quotes (Windows drag-and-drop).
pub fn prompt_line(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    let mut s = line.trim();
    if s.len() >= 2 && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))) {
        s = &s[1..s.len() - 1];
    }
    s.trim().to_string()
}

/// Prompts for an output file path, prompting to confirm overwrite if file exists (VULN-22).
/// If overwrite is rejected, re-prompts for a different file path.
fn prompt_output_file(prompt: &str, default: &str) -> Option<String> {
    loop {
        let input = prompt_line(prompt);
        let path_str = if input.is_empty() {
            default.to_string()
        } else {
            input
        };
        if path_str.eq_ignore_ascii_case("skip") {
            return None;
        }
        let p = std::path::Path::new(&path_str);
        if p.exists() {
            eprintln!("[!] 警告: 出力先ファイル '{}' は既に存在します。", p.display());
            let ans = prompt_line("上書きしますか？ (y/N): ");
            if ans.eq_ignore_ascii_case("y") {
                return Some(path_str);
            } else {
                println!("[*] 別の出力ファイル名を指定してください。");
                continue;
            }
        } else {
            return Some(path_str);
        }
    }
}

/// Prompts for an optional output file path, confirming overwrite if existing.
fn prompt_optional_output_file(prompt: &str) -> Option<String> {
    loop {
        let input = prompt_line(prompt);
        if input.is_empty() {
            return None;
        }
        let p = std::path::Path::new(&input);
        if p.exists() {
            eprintln!("[!] 警告: 出力先ファイル '{}' は既に存在します。", p.display());
            let ans = prompt_line("上書きしますか？ (y/N): ");
            if ans.eq_ignore_ascii_case("y") {
                return Some(input);
            } else {
                println!("[*] 別の出力ファイル名を指定してください。");
                continue;
            }
        } else {
            return Some(input);
        }
    }
}

pub fn run_interactive_wizard() -> Result<(), OpkeError> {
    loop {
        println!();
        println!("============================================================");
        println!("       OPKE v3.0 (Offline Paper-Key Encryptor)             ");
        println!("       オフライン・ペーパーキー暗号化ツール                 ");
        println!("============================================================");
        println!(" [1] 秘密情報を暗号化 (Encrypt -> Paper Key / QR)");
        println!(" [2] ペーパーキーを復号 (Decrypt -> Secret)");
        println!(" [3] エンベロープ情報の確認 (Inspect Envelope)");
        println!(" [4] 暗号化ベンチマーク (Benchmark)");
        println!(" [5] 終了 (Exit)");
        println!("============================================================");

        let choice = prompt_line("操作番号を選択してください [1-5]: ");

        match choice.as_str() {
            "1" => {
                println!();
                println!("--- [1] 秘密情報の暗号化ウィザード ---");

                println!("プロファイルを選択してください:");
                println!("  [1] production (推奨: 8 GiB, 64 iters - 最高強度)");
                println!("  [2] moderate   (1 GiB, 16 iters - 標準)");
                println!("  [3] fast       (64 MiB, 2 iters - テスト用)");
                let prof_choice = prompt_line("プロファイル [1-3, デフォルト: 1]: ");
                let profile = match prof_choice.as_str() {
                    "2" => "moderate",
                    "3" => "fast",
                    _ => "production",
                };

                let in_file = prompt_line("秘密情報ファイルから読み込みますか？ (空欄で直接入力): ");
                let input_file = if in_file.is_empty() { None } else { Some(in_file) };

                let output = prompt_output_file(
                    "ペーパーキー出力ファイル名 [デフォルト: paper_key.txt]: ",
                    "paper_key.txt",
                );

                let qr = prompt_output_file(
                    "QRコード画像保存ファイル名 [デフォルト: paper_key.png, 'skip'でスキップ]: ",
                    "paper_key.png",
                );

                let qr_term_ans = prompt_line("ターミナル画面上にもQRコードを表示しますか？ (Y/n): ");
                let qr_term = !qr_term_ans.eq_ignore_ascii_case("n");

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
                    force: false,
                };

                if let Err(e) = cmd_encrypt::execute(args) {
                    eprintln!("[-] エラーが発生しました: {}", e);
                } else {
                    println!("[+] 暗号化が完了しました！");
                }
            }
            "2" => {
                println!();
                println!("--- [2] ペーパーキーの復号ウィザード ---");

                let in_file = prompt_line("ペーパーキーファイル名 [デフォルト: paper_key.txt]: ");
                let input_file = if in_file.is_empty() {
                    Some("paper_key.txt".to_string())
                } else {
                    Some(in_file)
                };

                let output = prompt_optional_output_file(
                    "復号平文の保存先ファイル名 (空欄で画面に直接表示): ",
                );

                let args = DecryptArgs {
                    input: None,
                    input_file,
                    passphrase: None,
                    output,
                    max_mem: None,
                    max_time: None,
                    max_threads: None,
                    force: false,
                };

                if let Err(e) = cmd_decrypt::execute(args) {
                    eprintln!("[-] 復号に失敗しました: {}", e);
                } else {
                    println!("\n[+] 復号処理が完了しました！");
                }
            }
            "3" => {
                println!();
                println!("--- [3] エンベロープ情報の確認 ---");
                let in_file = prompt_line("確認するペーパーキーファイル名 [デフォルト: paper_key.txt]: ");
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
                    eprintln!("[-] 読み込みエラー: {}", e);
                }
            }
            "4" => {
                println!();
                println!("--- [4] 暗号化ベンチマーク ---");
                println!("測定するプロファイルを選択してください:");
                println!("  [1] production (8 GiB, 64 iters)");
                println!("  [2] moderate   (1 GiB, 16 iters)");
                println!("  [3] fast       (64 MiB, 2 iters)");
                let prof_choice = prompt_line("プロファイル [1-3, デフォルト: 3 (テスト用)]: ");
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
                    eprintln!("[-] ベンチマークエラー: {}", e);
                }
            }
            "5" | "q" | "exit" => {
                println!("終了します。");
                break;
            }
            _ => {
                println!("[-] 無効な選択肢です。1から5の番号を入力してください。");
            }
        }
    }

    pause_for_exit();
    Ok(())
}
