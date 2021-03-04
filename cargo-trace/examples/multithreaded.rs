fn main() {
    std::thread::spawn(spawn_main);
}

fn spawn_main() {
    let mut i = 0;
    for _ in 0..100000 {
        i += 1;
    }
    println!("{}", i);
}
