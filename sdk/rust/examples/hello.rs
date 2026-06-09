// Example naitron-c controller in Rust.
use naitron::Request;

fn main() {
    naitron::run(
        |req: Request| {
            let name = req.params.get("name").cloned().unwrap_or_default();
            let body = format!(
                r#"{{"controller":"rust-hello","lang":"rust","pid":{},"method":"{}","path":"{}","name":"{}","sub":"{}"}}"#,
                std::process::id(),
                req.method,
                req.path,
                name,
                req.sub
            );
            (200u16, "application/json".to_string(), body.into_bytes())
        },
        "rust-hello",
    );
}
