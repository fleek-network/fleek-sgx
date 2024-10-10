/// Provide the SGX collateral from the given quote.
pub trait CollateralProvider {
    /// Takes a serialized quote and returns the corresponding collateral bytes.
    fn get_collateral(&self, quote: Vec<u8>) -> std::io::Result<Vec<u8>>;
}
