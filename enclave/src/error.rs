#[derive(Debug)]
pub enum EnclaveError {
    FailedToFetchSharedKey,
    GeneratedBadSharedKey,
    EGetKeyFailed,
    FailedToGenerateTlsKey,
    FailedToSeal,
    FailedToUnseal,
    FailedToBuildTlsConfig,
    TlsServerError,
    RunnerConnectionFailed,
    MaxQuoteSizeExceeded,
}
