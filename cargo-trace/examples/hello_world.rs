// used by tests, do not delete.

fn main() {
    println!("hello world!");
    for i in 0usize..100_000 {
        blake3::hash(&i.to_ne_bytes());
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
}
