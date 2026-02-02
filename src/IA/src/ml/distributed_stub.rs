use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, BufReader, BufRead};
use std::thread;

/// Very small TCP-based parameter exchange stub for distributed training experiments.
/// Server listens for `expected_clients` connections, receives newline-separated floats per client,
/// averages them and returns averaged weights as newline-separated floats to each client.

pub fn start_parameter_server(addr: &str, expected_clients: usize) {
    let listener = TcpListener::bind(addr).expect("Failed to bind parameter server");
    println!("Parameter server listening on {} (expecting {} clients)", addr, expected_clients);

    let mut clients = Vec::new();
    for stream in listener.incoming().take(expected_clients) {
        match stream {
            Ok(s) => {
                s.set_nonblocking(false).ok();
                clients.push(s);
            }
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }

    // Read all clients
    let mut all_weights: Vec<Vec<f64>> = Vec::new();
    for mut s in clients.iter() {
        let mut reader = BufReader::new(s);
        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() {
            let weights: Vec<f64> = line.trim().split_whitespace()
                .filter_map(|t| t.parse::<f64>().ok())
                .collect();
            all_weights.push(weights);
        }
    }

    if all_weights.is_empty() {
        return;
    }

    let num_params = all_weights[0].len();
    let mut global = vec![0.0f64; num_params];
    for w in &all_weights {
        for (i, &v) in w.iter().enumerate() {
            global[i] += v / all_weights.len() as f64;
        }
    }

    // Send global back to clients (best-effort)
    for mut s in clients {
        let mut out = String::new();
        for (i, v) in global.iter().enumerate() {
            if i > 0 { out.push(' '); }
            out.push_str(&format!("{}", v));
        }
        let _ = s.write_all(out.as_bytes());
    }
}

pub fn client_send_weights(server_addr: &str, weights: &[f64]) -> Option<Vec<f64>> {
    match TcpStream::connect(server_addr) {
        Ok(mut s) => {
            let mut out = String::new();
            for (i, v) in weights.iter().enumerate() {
                if i > 0 { out.push(' '); }
                out.push_str(&format!("{}", v));
            }
            if s.write_all(out.as_bytes()).is_err() {
                return None;
            }

            // Read response
            let mut reader = BufReader::new(s);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                let resp: Vec<f64> = line.trim().split_whitespace().filter_map(|t| t.parse().ok()).collect();
                return Some(resp);
            }
            None
        }
        Err(_) => None,
    }
}
