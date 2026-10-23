//! Test helper: prints argv (including argv[0]) as a JSON array.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    println!("{}", serde_json::to_string(&args).unwrap());
}
