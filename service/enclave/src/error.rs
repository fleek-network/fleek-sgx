#[derive(Debug)]
pub enum EnclaveError {
    FailedToFetchSharedKey,
    NoPeersProvided,
    GeneratedBadSharedKey,
    EGetKeyFailed,
}
