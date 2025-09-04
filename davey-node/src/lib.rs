#![deny(clippy::all)]
#![allow(clippy::upper_case_acronyms)]

#[macro_use]
extern crate napi_derive;

#[cfg(debug_assertions)]
use napi::bindgen_prelude::Object;

macro_rules! napi_error {
  ($($arg:tt)*) => {
      napi::Error::new(napi::Status::GenericFailure, format!($($arg)*))
  };
}

macro_rules! napi_invalid_arg_error {
  ($($arg:tt)*) => {
      napi::Error::new(napi::Status::InvalidArg, format!($($arg)*))
  };
}

mod displayable_code;
mod fingerprint;
mod session;
mod signing_key_pair;

pub use displayable_code::*;
pub use fingerprint::*;
pub use session::*;
pub use signing_key_pair::*;

/// The version of the davey package being used.
#[napi]
pub const VERSION: &str = match option_env!("npm_package_version") {
  Some(version) => version,
  None => env!("CARGO_PKG_VERSION"),
};

/// Whether davey is using a debug build.
#[napi]
pub const DEBUG_BUILD: bool = cfg!(debug_assertions);

pub type DAVEProtocolVersion = u16;

// This enables debug statements on debug builds.
#[cfg(debug_assertions)]
#[napi(module_exports)]
pub fn exports(mut _exports: Object) -> napi::Result<()> {
  tracing_log::LogTracer::init().expect("Failed to set logger");

  let subscriber = tracing_subscriber::FmtSubscriber::builder()
    .with_max_level(tracing::Level::DEBUG)
    .with_target(true)
    .with_level(true)
    .finish();

  tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

  Ok(())
}
