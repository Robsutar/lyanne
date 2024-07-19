macro_rules! cfg_sd_bincode {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "sd-bincode")]
            $item
        )*
    }
}

macro_rules! cfg_sd_none {
    ($($item:item)*) => {
        $(
            #[cfg(all(not(feature = "sd-bincode")))]
            $item
        )*
    }
}

pub(crate) use cfg_sd_bincode;
pub(crate) use cfg_sd_none;
