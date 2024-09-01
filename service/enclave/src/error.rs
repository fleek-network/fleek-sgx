#[derive(Debug)]
pub enum EnclaveError {
    FailedToFetchSharedKey,
    NoPeersProvided,
    GeneratedBadSharedKey,
    EGetKeyFailed,
    FailedToGenerateTlsKey,
    FailedToSeal,
    FailedToUnseal,
    RunnerConnectionFailed,
    BadCollateral,
    InvalidArgs,
    BadSavedKey,
}
