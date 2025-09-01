use std::env;
use std::fs;
use std::path::PathBuf;

fn escape_rust_string(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"'  => vec!['\\', '"'],   // escape quotes
            '\\' => vec!['\\', '\\'],  // escape backslashes
            _    => vec![c],
        })
        .collect()
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Load the CSV
    let csv = fs::read_to_string("data/mac-vendors-export.csv")
        .expect("Failed to read vendor CSV");

    let mut out = String::new();
    out.push_str("pub static OUI_TABLE: &[(u32, &str)] = &[\n");

    for line in csv.lines().skip(1) { // skip header
        let parts: Vec<&str> = line.splitn(3, ',').collect();
        if parts.len() >= 2 {
            let prefix = parts[0].replace(':', "");
            let vendor = parts[1].trim().trim_matches('"');
            let vendor_escaped = escape_rust_string(vendor);

            if let Ok(oui) = u32::from_str_radix(&prefix, 16) {
                out.push_str(&format!("    (0x{:06X}, \"{}\"),\n", oui, vendor_escaped));
            }
        }
    }

    out.push_str("];\n");

    // Write generated Rust file
    fs::write(out_dir.join("oui_table.rs"), out).unwrap();
}
