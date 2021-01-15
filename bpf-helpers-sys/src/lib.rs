#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

mod helpers {
    include!(concat!(env!("OUT_DIR"), "/helpers.rs"));
}

pub use helpers::*;
