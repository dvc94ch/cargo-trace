use std::time::Duration;

fn main() {
    sleep_once();
    sleep_three_times();
}

fn sleep_three_times() {
    for _ in 0..3 {
        sleep();
    }
}

fn sleep_once() {
    sleep();
}

fn sleep() {
    std::thread::sleep(Duration::from_millis(100));
}
