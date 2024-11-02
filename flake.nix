{
  description = "Fleek SGX";

  inputs = {
    nixpkgs.url = "github:ozwaldorf/nixpkgs/sgx";
    crane.url = "github:ipetkov/crane";
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
          pkgs = (import nixpkgs { inherit system; });
          craneLib = (crane.mkLib pkgs).overrideToolchain (
            fenix.packages.${system}.fromToolchainFile {
              dir = ./.;
              sha256 = "X4me+hn5B6fbQGQ7DThreB/DqxexAhEQT8VNvW6Pwq4=";
            }
          );

          src = craneLib.path ./.;

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
              sgx-dcap-default-qpl
            ];
          } // commonVars;

          commonVars = {
            OPENSSL_NO_VENDOR = 1;
            OPENSSL_LIB_DIR = "${pkgs.lib.getLib pkgs.openssl_3}/lib";
            OPENSSL_INCLUDE_DIR = "${pkgs.lib.getDev pkgs.openssl_3.dev}/include";
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

            # Check clippy lints
            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets --all-features -- -Dclippy::all -Dwarnings";
              }
            );

            # # Run tests with cargo-nextest
            nextest = craneLib.cargoNextest (
              commonArgs
              // {
                inherit cargoArtifacts;
                partitions = 1;
                partitionType = "count";
                cargoNextestExtraArgs = "--all --exclude fleek-service-sgx-enclave --target x86_64-unknown-linux-gnu";
              }
            );
          };

          packages = rec {
            default = fn-sgx-enclave;
            fn-sgx-enclave =
              let
                # SGXS binary stream parameters
                ENCLAVE_HEAP = "0x100000000";
                ENCLAVE_STACK = "0x200000";
                ENCLAVE_THREADS = "134";
                TARGET = "target/x86_64-fortanix-unknown-sgx/release/fleek-service-sgx-enclave";
              in
              craneLib.buildPackage (
                commonArgs
                // {
                  inherit cargoArtifacts;
                  pname = "fn-sgx-enclave";
                  doCheck = false;
                  cargoExtraArgs = "--locked --bin fleek-service-sgx-enclave";
                  installPhase = ''
                    # Convert elf to sgxs with our parameters
                    ftxsgx-elf2sgxs ${TARGET} \
                        --heap-size ${ENCLAVE_HEAP} \
                        --stack-size ${ENCLAVE_STACK} \
                        --threads ${ENCLAVE_THREADS}

                    # Install to output dir
                    mkdir -p $out
                    mv ${TARGET}.sgxs $out/enclave.sgxs
                  '';
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
            }
          );

          # Allow using `nix fmt` on the project
          formatter = pkgs.nixfmt-rfc-style;
        }
      );
}
