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
            fn run_client_schedule(world: &mut lyanne::bevy::bevy_ecs::world::World) -> Result<(), lyanne::bevy::lyanne::bevy::bevy_ecs::world::error::TryRunScheduleError>{
                world.try_run_schedule(#client_schedule_ident)
            }
        });
        external.push(quote::quote! {
            #[derive(lyanne::bevy::bevy_ecs::schedule::ScheduleLabel,Debug, Clone, PartialEq, Eq, Hash)]
            pub struct #client_schedule_ident;
        });
    }

    #[cfg(all(feature = "bevy-packet-schedules", feature = "server"))]
    {
        let server_schedule_ident =
            syn::Ident::new(&format!("{}ServerSchedule", ident), ident.span());
        functions.push(quote::quote! {
            fn run_server_schedule(world: &mut lyanne::bevy::bevy_ecs::world::World) -> Result<(), lyanne::bevy::lyanne::bevy::bevy_ecs::world::error::TryRunScheduleError>{
                world.try_run_schedule(#server_schedule_ident)
            }
        });
        external.push(quote::quote! {
            #[derive(lyanne::bevy::bevy_ecs::schedule::ScheduleLabel,Debug, Clone, PartialEq, Eq, Hash)]
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
