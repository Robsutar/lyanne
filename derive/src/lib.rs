use proc_macro::TokenStream;
use syn::DeriveInput;

fn impl_packet_trait(ast: DeriveInput) -> TokenStream {
    let ident = ast.ident;

    let client_schedule_ident = syn::Ident::new(&format!("{}ClientSchedule", ident), ident.span());
    let server_schedule_ident = syn::Ident::new(&format!("{}ServerSchedule", ident), ident.span());

    quote::quote! {
        impl Packet for #ident {
            #[cfg(all(feature = "use_bevy", feature = "client"))]
            fn run_client_schedule(world: &mut World) -> Result<(), bevy::ecs::world::error::TryRunScheduleError>{
                world.try_run_schedule(#client_schedule_ident)
            }

            #[cfg(all(feature = "use_bevy", feature = "server"))]
            fn run_server_schedule(world: &mut World) -> Result<(), bevy::ecs::world::error::TryRunScheduleError>{
                world.try_run_schedule(#server_schedule_ident)
            }
        }

        #[cfg(all(feature = "use_bevy", feature = "client"))]
        #[derive(bevy::ecs::schedule::ScheduleLabel,Debug, Clone, PartialEq, Eq, Hash)]
        pub struct #client_schedule_ident;

        #[cfg(all(feature = "use_bevy", feature = "server"))]
        #[derive(bevy::ecs::schedule::ScheduleLabel,Debug, Clone, PartialEq, Eq, Hash)]
        pub struct #server_schedule_ident;
    }
    .into()
}

#[proc_macro_derive(Packet)]
pub fn packet_derive_macro(item: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(item).unwrap();

    impl_packet_trait(ast)
}
