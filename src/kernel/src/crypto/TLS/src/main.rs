use anyhow::Result;
use std::env;
use std::time::Duration;
use std::ffi::OsString;
use std::thread;
use redmi_tls;

fn main() -> Result<()> {
    redmi_tls::run::start()?;

    #[cfg(feature = "real_tls")]
    {
        if let (Ok(addr), Ok(cert), Ok(key)) = (
            env::var("TLS_SERVE_REAL_ADDR"),
            env::var("TLS_CERT_PATH"),
            env::var("TLS_KEY_PATH"),
        ) {
            std::thread::spawn(move || {
                let _ = redmi_tls::api::server::real_tls::serve_real(&addr, &cert, &key);
            });
        }
    }

    let mut run_seconds = env::var("RUN_SECONDS").ok().and_then(|s| s.parse::<u64>().ok());

    let mut args: std::vec::IntoIter<OsString> = std::env::args_os().skip(1).collect::<Vec<OsString>>().into_iter();
    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--timeout" | "-t" => {
                if let Some(val) = args.next() {
                    if let Ok(n) = val.to_string_lossy().parse::<u64>() {
                        run_seconds = Some(n);
                    } else {
                        eprintln!("invalid timeout value: {:?}", val);
                    }
                } else {
                    eprintln!("missing value for --timeout");
                }
            }
            "--help" | "-h" => {
                println!("Usage: run [--timeout <seconds>]\nEnvironment: RUN_SECONDS=<seconds>");
                return Ok(());
            }
            _ => {
            }
        }
    }

    println!("tls: en cours d'exécution — appuyez sur Ctrl-C pour quitter");
    if let Some(sec) = run_seconds {
        println!("tls: mode timeout activé — arrêt automatique après {} secondes", sec);
        thread::sleep(Duration::from_secs(sec));
        println!("tls: timeout atteint, arrêt automatique");
    } else {
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }

    Ok(())
}

