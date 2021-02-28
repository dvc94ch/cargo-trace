fn main() {
    allocate_once();
    allocate_three_times();
}

fn allocate_three_times() {
    for _ in 0..3 {
        allocate();
    }
}

fn allocate_once() {
    allocate();
}

fn allocate() {
    "a string".to_string();
}
