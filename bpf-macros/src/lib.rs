use bpf_utils::event::FieldFormat;
use heck::CamelCase;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
};

struct Args(Punctuated<syn::Lit, syn::token::Comma>);

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Args> {
        Ok(Args(Punctuated::parse_terminated(input)?))
    }
}

/// Generates program metadata.
///
/// Takes two arguments, the `LINUX_VERSION_CODE` the program is compatible with,
/// and the license. The special version code `0xFFFFFFFE` can be used to signify
/// any kernel version.
///
/// # Example
///
/// ```compile_fail
/// #![no_std]
/// #![no_main]
/// # use bpf_macros::program;
/// program!(0xFFFFFFFE, b"GPL");
/// ```
#[proc_macro]
pub fn program(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Args);
    let mut args = input.0.iter();
    let version = args.next().expect("no version");
    let license = args.next().expect("no license");
    let len = quote!(lincense).to_string().len() - 5;
    let tokens = quote! {
        #[no_mangle]
        #[link_section = "license"]
        pub static _license: [u8; #len] = *#license;

        #[no_mangle]
        #[link_section = "version"]
        pub static _version: u32 = #version;

        #[panic_handler]
        #[no_mangle]
        pub extern "C" fn rust_begin_panic(info: &::core::panic::PanicInfo) -> ! {
            bpf_helpers::bpf_trace_printk(b"panic\0");
            unsafe { core::hint::unreachable_unchecked() }
        }
    };
    tokens.into()
}

#[proc_macro_attribute]
pub fn map(_: TokenStream, item: TokenStream) -> TokenStream {
    let map = parse_macro_input!(item as syn::ItemStatic);
    let tokens = quote! {
        #[no_mangle]
        #[link_section = "maps"]
        #map
    };
    tokens.into()
}

#[proc_macro_attribute]
pub fn entry(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let prog = parse_macro_input!(item as syn::ItemFn);
    let mut prog_type = match parse_macro_input!(attrs as syn::Lit) {
        syn::Lit::Str(s) => s.value(),
        _ => panic!("expected string literal"),
    };
    let mut event = quote!();
    let arg = match prog_type.as_str() {
        "kprobe" => quote!(bpf_helpers::kprobe::pt_regs),
        "perf_event" => quote!(bpf_helpers::perf_event::bpf_perf_event_data),
        "tracing" => quote!(core::ffi::c_void),
        //"raw_tracepoint" => quote!(u64),
        //"raw_tracepoint_writable" => quote!(u64),
        tracepoint => {
            let mut iter = tracepoint.split(':');
            let category = iter.next().expect("category");
            let name = iter.next().expect("name");
            let struct_ident = format_ident!("{}", name.to_camel_case());
            let format = bpf_utils::event::event_format(&category, &name).unwrap();
            let fields = format.fields().map(|field| {
                let name = format_ident!("{}", &field.0);
                let ty = field_type(&field.1);
                quote!(#name: #ty,)
            });
            prog_type = "tracepoint".to_string();
            event = quote! {
                #[repr(C)]
                struct #struct_ident {
                    #(#fields)*
                }
            };
            quote!(#struct_ident)
        }
    };
    let ident = &prog.sig.ident;
    let section_name = format!("{}/{}", prog_type, ident.to_string());
    let prog_type = format_ident!("{}", prog_type);
    let tokens = quote! {
        #event

        #[no_mangle]
        #[link_section = #section_name]
        fn #ident(arg: *const core::ffi::c_void) -> i32 {
            use bpf_helpers::#prog_type::*;
            #[inline(always)]
            #prog
            let arg = unsafe { &*(arg as *const #arg) };
            #ident(arg);
            0
        }
    };
    tokens.into()
}

fn field_type(format: &FieldFormat) -> TokenStream2 {
    match format {
        FieldFormat::Simple { signed: true, size } => {
            let ty = format_ident!("i{}", (size * 8).to_string());
            quote!(#ty)
        }
        FieldFormat::Simple {
            signed: false,
            size,
        } => {
            let ty = format_ident!("u{}", (size * 8).to_string());
            quote!(#ty)
        }
        FieldFormat::Array { signed, size, len } => {
            let ty = field_type(&FieldFormat::Simple {
                signed: *signed,
                size: *size,
            });
            quote!([#ty; #len])
        }
    }
}
