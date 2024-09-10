#[cfg(all(
    feature = "rt_tokio",
    any(
        feature = "rt_async_std",
        feature = "rt_smol",
        feature = "rt_async_executor",
        feature = "rt_bevy"
    )
))]
compile_error!("feature \"rt_tokio\" can not be enabled with another rt");

#[cfg(all(
    feature = "rt_async_std",
    any(
        feature = "rt_tokio",
        feature = "rt_smol",
        feature = "rt_async_executor",
        feature = "rt_bevy"
    )
))]
compile_error!("feature \"rt_async_std\" can not be enabled with another rt");

#[cfg(all(
    feature = "rt_smol",
    any(
        feature = "rt_tokio",
        feature = "rt_async_std",
        feature = "rt_async_executor",
        feature = "rt_bevy"
    )
))]
compile_error!("feature \"rt_smol\" can not be enabled with another rt");

#[cfg(all(
    feature = "rt_async_executor",
    any(
        feature = "rt_tokio",
        feature = "rt_async_std",
        feature = "rt_smol",
        feature = "rt_bevy"
    )
))]
compile_error!("feature \"rt_async_executor\" can not be enabled with another rt");

#[cfg(all(
    feature = "rt_bevy",
    any(
        feature = "rt_tokio",
        feature = "rt_async_std",
        feature = "rt_smol",
        feature = "rt_async_executor",
    )
))]
compile_error!("feature \"rt_bevy\" can not be enabled with another rt");

#[cfg(feature = "rt_tokio")]
mod tokio;
#[cfg(feature = "rt_tokio")]
pub use tokio::*;

#[cfg(feature = "rt_async_std")]
mod async_std;
#[cfg(feature = "rt_async_std")]
pub use async_std::*;

#[cfg(feature = "rt_smol")]
mod smol;
#[cfg(feature = "rt_smol")]
pub use smol::*;

#[cfg(feature = "rt_async_executor")]
mod async_executor;
#[cfg(feature = "rt_async_executor")]
pub use async_executor::*;

#[cfg(feature = "rt_bevy")]
mod bevy;
#[cfg(feature = "rt_bevy")]
pub use bevy::*;
