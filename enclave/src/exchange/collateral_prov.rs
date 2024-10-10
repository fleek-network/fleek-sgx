use ra_tls::collateral_prov::CollateralProvider;

use crate::req_res::get_collateral;

#[derive(Default)]
pub struct EnclaveCollateralProvider {}

impl CollateralProvider for EnclaveCollateralProvider {
    fn get_collateral(&self, quote: Vec<u8>) -> std::io::Result<Vec<u8>> {
        get_collateral(&quote).map(|c| serde_json::to_vec(&c).unwrap())
    }
}
