use proc_macro2::Ident;
use quote::quote;
use std::env;
use std::path::PathBuf;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::visit::Visit;

fn main() {
    println!("cargo:rerun-if-changed=bpf_helper_defs.h");

    let bindings = bindgen::Builder::default()
        .header("bpf_helper_defs.h")
        .use_core()
        .ctypes_prefix("cty")
        .generate()
        .expect("Unable to generate bindings.")
        .to_string();

    let helpers = gen_helpers(&bindings);

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    std::fs::write(out_path.join("bindings.rs"), bindings).expect("Couldn't write bindings!");

    std::fs::write(out_path.join("helpers.rs"), helpers).expect("Couldn't write helpers!");
}

struct RewriteBpfHelpers {
    helpers: Vec<String>,
}

impl Visit<'_> for RewriteBpfHelpers {
    fn visit_foreign_item_static(&mut self, item: &syn::ForeignItemStatic) {
        if let syn::Type::Path(path) = &*item.ty {
            let ident = &item.ident;
            let ident_str = ident.to_string();
            let last = path.path.segments.last().unwrap();
            let ty_ident = last.ident.to_string();
            if ident_str.starts_with("bpf_") && ty_ident == "Option" {
                let fn_ty = match &last.arguments {
                    syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
                        args,
                        ..
                    }) => args.first().unwrap(),
                    _ => panic!(),
                };
                let mut ty_s = quote! {
                    #[inline(always)]
                    pub #fn_ty
                }
                .to_string();
                ty_s = ty_s.replace("fn (", &format!("fn {} (", ident_str));
                let call_idx = self.helpers.len() + 1;
                let args: Punctuated<Ident, Comma> = match fn_ty {
                    syn::GenericArgument::Type(syn::Type::BareFn(f)) => f
                        .inputs
                        .iter()
                        .map(|arg| arg.name.clone().unwrap().0)
                        .collect(),
                    _ => unreachable!(),
                };
                let body = quote! {
                    {
                        let f: #fn_ty = ::core::mem::transmute(#call_idx);
                        f(#args)
                    }
                }
                .to_string();
                ty_s.push_str(&body);
                let mut helper = ty_s;
                if helper.contains("printk") {
                    helper = format!("/* {} */", helper);
                }
                self.helpers.push(helper);
            }
        }
    }
}

fn gen_helpers(helpers: &str) -> String {
    let tree: syn::File = syn::parse_str(&helpers).unwrap();
    let mut tx = RewriteBpfHelpers {
        helpers: Vec::new(),
    };
    tx.visit_file(&tree);
    let mut out = String::new();
    out.push_str("pub use crate::bindings::*;\n");
    for helper in &tx.helpers {
        out.push_str(helper);
    }
    out
}
