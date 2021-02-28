fn main() {
    //println!("main");
    env_logger::init();
    fill_my_stack1(10);
}

fn fill_my_stack1(depth: u8) {
    if depth == 0 {
        stack_filled();
    } else {
        fill_my_stack2(depth - 1);
    }
}

fn fill_my_stack2(depth: u8) {
    if depth == 0 {
        stack_filled();
    } else {
        fill_my_stack1(depth - 1);
    }
}

fn stack_filled() {
    /*bpf_backtrace::walk_stack(|ctx| {
        backtrace::resolve(ctx.rip() as *const std::ffi::c_void as *mut _, |symbol| {
            println!(
                "rip 0x{:x} rsp 0x{:x}  {:#}",
                ctx.rip(),
                ctx.rsp(),
                symbol.name().unwrap()
            );
        });
    });*/
    for _ in 0..1000000 {}
}
