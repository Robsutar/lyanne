use proc_macro::TokenStream;
use syn::DeriveInput;

fn impl_packet_trait(ast: DeriveInput) -> TokenStream {
    let ident = ast.ident;

    quote::quote! {
        impl Packet for #ident {

        }
    }
    .into()
}

#[proc_macro_derive(Packet)]
pub fn packet_derive_macro(item: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(item).unwrap();

    impl_packet_trait(ast)
}
