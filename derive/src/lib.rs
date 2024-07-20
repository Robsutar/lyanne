use proc_macro::TokenStream;
use syn::DeriveInput;

fn impl_packet_trait(ast: &DeriveInput) -> TokenStream {
    let ident = &ast.ident;

    let mut functions = Vec::new();
    let mut external = Vec::new();

    // To avoid explicit use of proc_macro2
    functions.push(quote::quote! {});
    external.push(quote::quote! {});

    #[cfg(all(feature = "bevy-packet-schedules", feature = "client"))]
    {
        let client_schedule_ident =
            syn::Ident::new(&format!("{}ClientSchedule", ident), ident.span());
        functions.push(quote::quote! {
            type ClientSchedule = #client_schedule_ident;
            fn client_schedule() -> Self::ClientSchedule {
                #client_schedule_ident
            }
        });
        external.push(quote::quote! {
            #[derive(lyanne::bevy::bevy_ecs::schedule::ScheduleLabel, Debug, Clone, PartialEq, Eq, Hash)]
            pub struct #client_schedule_ident;
        });
    }

    #[cfg(all(feature = "bevy-packet-schedules", feature = "server"))]
    {
        let server_schedule_ident =
            syn::Ident::new(&format!("{}ServerSchedule", ident), ident.span());
        functions.push(quote::quote! {
            type ServerSchedule = #server_schedule_ident;
            fn server_schedule() -> Self::ServerSchedule {
                #server_schedule_ident
            }
        });
        external.push(quote::quote! {
            #[derive(lyanne::bevy::bevy_ecs::schedule::ScheduleLabel, Debug, Clone, PartialEq, Eq, Hash)]
            pub struct #server_schedule_ident;
        });
    }

    quote::quote! {
        impl Packet for #ident {
            #( #functions )*
        }

        #( #external )*
    }
    .into()
}

#[proc_macro_derive(Packet)]
pub fn packet_derive_macro(item: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(item).unwrap();

    impl_packet_trait(&ast)
}
