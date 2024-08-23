{
  description = "Lightning - Fleek Network Node";

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
    extra-substituters = [ "https://cache.garnix.io" ];
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
          inherit (pkgs) lib;
          craneLib = (crane.mkLib pkgs).overrideToolchain (
            fenix.packages.${system}.fromToolchainFile {
              dir = ./.;
              sha256 = "X4me+hn5B6fbQGQ7DThreB/DqxexAhEQT8VNvW6Pwq4=";
            }
          );

          src = craneLib.path ./.;

          # Common arguments can be set here to avoid repeating them later
          commonArgs = {
            inherit src;
            strictDeps = true;
            pname = "lightning";
            version = "0.1.0";
            nativeBuildInputs =
              with pkgs;
              [
                pkg-config
                gcc11
                perl
                cmake
                clang
                protobuf
                mold-wrapped
                python3
              ]
              ++ lib.optionals (!pkgs.stdenv.isDarwin) [
                # for sgx service, not available on mac
                fortanix-sgx-tools
                sgxs-tools
              ];
            buildInputs =
              with pkgs;
              [
                libclang
                fontconfig
                freetype
                protobufc
                openssl_3
                zstd
                zlib
                bzip2
                lz4
                (rocksdb.override { enableShared = true; })
                (snappy.override { static = true; })
                boringssl

                # For running nextest
                cacert

                # For ai service
                onnxruntime

                # Ebpf deps needed at runtime for debug builds via `admin ebpf build`
                rust-bindgen
                bpf-linker
              ]
              ++ lib.optionals pkgs.stdenv.isDarwin [
                # MacOS specific packages
                pkgs.libiconv
                pkgs.darwin.apple_sdk.frameworks.QuartzCore
              ];
          } // commonVars;

          commonVars = {
            # Shared and static libraries
            PKG_CONFIG_PATH = "${lib.getDev pkgs.fontconfig}/lib/pkgconfig";
            RUST_FONTCONFIG_DLOPEN = "on";
            LIBCLANG_PATH = "${lib.getLib pkgs.libclang}/lib";
            OPENSSL_NO_VENDOR = 1;
            OPENSSL_LIB_DIR = "${lib.getLib pkgs.openssl_3}/lib";
            OPENSSL_INCLUDE_DIR = "${lib.getDev pkgs.openssl_3.dev}/include";

            ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib";
            Z_LIB_DIR = "${lib.getLib pkgs.zlib}/lib";
            ZSTD_LIB_DIR = "${lib.getLib pkgs.zstd}/lib";
            BZIP2_LIB_DIR = "${lib.getLib pkgs.bzip2}/lib";
            SNAPPY_LIB_DIR = "${lib.getLib pkgs.snappy}/lib";
            ORT_LIB_LOCATION = "${lib.getLib pkgs.onnxruntime}/lib";
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
                CARGO_PROFILE = "dev";
              }
            );

            # Run tests with cargo-nextest
            nextest = craneLib.cargoNextest (
              commonArgs
              // {
                inherit cargoArtifacts;
                partitions = 1;
                partitionType = "count";
                cargoNextestExtraArgs = "--workspace --exclude lightning-e2e";
              }
            );
          };

          # Allow using `nix develop` on the project
          devShells.default = craneLib.devShell (
            commonVars
            // {
              # Inherit inputs from checks
              checks = self.checks.${system};
              name = "lightning-dev";
              packages = with pkgs; [
                rust-analyzer
                wabt # wasm tools, ie wasm2wat
              ];
            }
          );

          # Allow using `nix fmt` on the project
          formatter = pkgs.nixfmt-rfc-style;
        }
      );
}
