#[derive(Debug)]
pub enum EnclaveError {
    FailedToFetchSharedKey,
    NoPeersProvided,
    GeneratedBadSharedKey,
    EGetKeyFailed,
    FailedToGenerateTlsKey,
    FailedToSeal,
    FailedToUnseal,
    FailedToBuildTlsConfig,
    TlsServerError,
    RunnerConnectionFailed,
    BadCollateral,
    InvalidArgs,
    BadSavedKey,
}
