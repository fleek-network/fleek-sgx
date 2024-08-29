{
  description = "Fleek Remote Attestations";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  nixConfig = {
    extra-trusted-substituters = [ "https://cache.garnix.io" ];
    extra-trusted-public-keys = [ "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g=" ];
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      fenix,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-darwin"
      ]
      (
        system:
        let
          pkgs = (
            import nixpkgs {
              inherit system;
              overlays = [
                (
                  final: prev:
                  let
                    # Build a released package from `github.com/fortanix/rust-sgx`
                    mkRustSgxPackage = (
                      {
                        pname,
                        version,
                        hash,
                        cargoHash,
                      }:
                      prev.rustPlatform.buildRustPackage rec {
                        inherit pname version cargoHash;
                        nativeBuildInputs = with prev; [
                          pkg-config
                          protobuf
                        ];
                        buildInputs = with prev; [ openssl_3 ];
                        src = prev.fetchzip {
                          inherit hash;
                          url = "https://crates.io/api/v1/crates/${pname}/${version}/download";
                          extension = "tar.gz";
                        };
                      }
                    );
                  in
                  {
                    # todo(oz): contribute these to upstream nixpkgs
                    fortanix-sgx-tools = mkRustSgxPackage {
                      pname = "fortanix-sgx-tools";
                      version = "0.5.1";
                      hash = "sha256-F0lZG1neAPVvyOxUtDPv0t7o+ZC+aQRtpFeq55QwcmE=";
                      cargoHash = "sha256-jYfsmPwhvt+ccUr4Vwq5q1YzNlxA+Vnpxd4KpWZrYo8=";
                    };
                    sgxs-tools = mkRustSgxPackage {
                      pname = "sgxs-tools";
                      version = "0.8.6";
                      hash = "sha256-24lUhi4IPv+asM51/BfufkOUYVellXoXsbWXWN/zoBw=";
                      cargoHash = "sha256-vtuOCLo7qBOfqMynykqf9folmlETx3or35+CuTurh3s=";
                    };
                  }
                )
              ];
            }
          );
          craneLib = (crane.mkLib pkgs).overrideToolchain (
            fenix.packages.${system}.fromToolchainFile {
              dir = ./.;
              sha256 = "X4me+hn5B6fbQGQ7DThreB/DqxexAhEQT8VNvW6Pwq4=";
            }
          );

          src = craneLib.path ./.;

          # TODO: patch elf into sgxs beforehand
          fn-sgx-enclave = craneLib.buildPackage {
            inherit src;
            pname = "fn-sgx-enclave";
            cargoArtifacts = null;
            doCheck = false;
            cargoToml = "${src}/service/enclave/Cargo.toml";
            cargoLock = "${src}/service/enclave/Cargo.lock";
            postUnpack = ''
              cd $sourceRoot/service/enclave
              sourceRoot="."
            '';
          };

          # Common arguments
          commonArgs = {
            inherit src;
            strictDeps = true;
            pname = "fn-sgx";
            version = "0.1.0";
            packages = [ pkgs.protobuf ];
            nativeBuildInputs = with pkgs; [
              pkg-config
              protobuf
              sgxs-tools
              fortanix-sgx-tools
            ];
            buildInputs = with pkgs; [
              cacert
              openssl_3
              protobufc

              # For linking to `dcap_quoteprov`
              sgx-azure-dcap-client
            ];
          } // commonVars;

          commonVars = {
            OPENSSL_NO_VENDOR = 1;
            OPENSSL_LIB_DIR = "${pkgs.lib.getLib pkgs.openssl_3}/lib";
            OPENSSL_INCLUDE_DIR = "${pkgs.lib.getDev pkgs.openssl_3.dev}/include";

            FN_ENCLAVE_BIN_PATH = "${fn-sgx-enclave}/bin/fleek-service-sgx-enclave";
          };

          # Build *just* the cargo dependencies, so we can reuse all of that
          # work (e.g. via cachix or github artifacts) when running in CI
          cargoArtifacts = craneLib.buildDepsOnly (commonArgs);
        in
        {
          # Allow using `nix flake check` to run tests and lints
          checks = {
            # Check formatting
            fmt = craneLib.cargoFmt {
              inherit (commonArgs) pname src;
              cargoExtraArgs = "--all";
            };

            # Check doc tests
            doc = craneLib.cargoDoc (commonArgs // { inherit cargoArtifacts; });

            # Check clippy lints
            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets --all-features -- -Dclippy::all -Dwarnings";
              }
            );

            # Run tests with cargo-nextest
            nextest = craneLib.cargoNextest (
              commonArgs
              // {
                inherit cargoArtifacts;
                partitions = 1;
                partitionType = "count";
              }
            );
          };

          packages = rec {
            inherit fn-sgx-enclave;

            default = fn-service-3;

            fn-service-3 = craneLib.buildPackage (
              commonArgs
              // {
                inherit cargoArtifacts;
                pname = "fn-service-3";
                doCheck = false;
                cargoExtraArgs = "--locked --bin fn-service-3";
              }
            );

          };

          # Allow using `nix develop` on the project
          devShells.default = craneLib.devShell (
            commonVars
            // {
              # Inherit inputs from checks
              checks = self.checks.${system};
              name = "fleek-sgx-dev";
              packages = with pkgs; [ rust-analyzer ];
              FN_ENCLAVE_BIN_PATH = "";
            }
          );

          # Allow using `nix fmt` on the project
          formatter = pkgs.nixfmt-rfc-style;
        }
      );
}
