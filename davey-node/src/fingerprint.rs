use napi::{
  bindgen_prelude::{AsyncTask, Buffer},
  Env, Error, Task,
};

/// Generate a key fingerprint.
/// @see https://daveprotocol.com/#verification-fingerprint
#[napi]
pub fn generate_key_fingerprint(
  version: u16,
  key: Buffer,
  user_id: String,
) -> napi::Result<Buffer> {
  let user_id = user_id
    .parse::<u64>()
    .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;
  let result = davey::generate_key_fingerprint(version, &key, user_id)
    .map_err(|e| napi_invalid_arg_error!("failed to generate key fingerprint: {:?}", e))?;
  Ok(Buffer::from(result))
}

/// Generate a pairwise fingerprint.
/// @see https://daveprotocol.com/#verification-fingerprint
#[allow(dead_code)]
#[napi(ts_return_type = "Promise<Buffer>")]
pub fn generate_pairwise_fingerprint(
  version: u16,
  key_a: Buffer,
  user_id_a: String,
  key_b: Buffer,
  user_id_b: String,
) -> AsyncTask<AsyncPairwiseFingerprint> {
  AsyncTask::new(AsyncPairwiseFingerprint {
    version,
    key_a,
    user_id_a,
    key_b,
    user_id_b,
  })
}

pub struct AsyncPairwiseFingerprint {
  version: u16,
  key_a: Buffer,
  user_id_a: String,
  key_b: Buffer,
  user_id_b: String,
}

impl Task for AsyncPairwiseFingerprint {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let user_id_a = self
      .user_id_a
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;
    let user_id_b = self
      .user_id_b
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    let output = davey::generate_pairwise_fingerprint(
      self.version,
      &self.key_a,
      user_id_a,
      &self.key_b,
      user_id_b,
    )
    .map_err(|e| napi_invalid_arg_error!("failed to generate pairwise fingerprint: {:?}", e))?;

    Ok(output)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(Buffer::from(output))
  }
}

pub struct AsyncPairwiseFingerprintSession {
  pub fingerprints: Option<[Vec<u8>; 2]>,
  pub error: Option<Error>,
}

impl Task for AsyncPairwiseFingerprintSession {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    if let Some(err) = self.error.take() {
      return Err(err);
    }

    let fingerprints = match self.fingerprints.take() {
      Some(f) => f,
      None => return Err(napi_error!("Invalid fingerprints")),
    };

    let output = davey::pairwise_fingerprints_internal(fingerprints)
      .map_err(|e| napi_invalid_arg_error!("failed to generate pairwise fingerprint: {:?}", e))?;

    Ok(output)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(Buffer::from(output))
  }
}

pub struct AsyncSessionVerificationCode {
  pub fingerprints: Option<[Vec<u8>; 2]>,
  pub error: Option<Error>,
}

impl Task for AsyncSessionVerificationCode {
  type Output = String;
  type JsValue = String;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    if let Some(err) = self.error.take() {
      return Err(err);
    }

    let fingerprints = match self.fingerprints.take() {
      Some(f) => f,
      None => return Err(napi_error!("Invalid fingerprints")),
    };

    let output = davey::pairwise_fingerprints_internal(fingerprints)
      .map_err(|e| napi_invalid_arg_error!("failed to generate pairwise fingerprint: {:?}", e))?;
    let code = davey::generate_displayable_code_internal(&output, 45, 5)
      .map_err(|e| napi_invalid_arg_error!("failed to generate displayable code: {:?}", e))?;

    Ok(code)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(output)
  }
}
