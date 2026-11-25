{
  description = "Revvault — age-encrypted secret vault with CLI and Tauri desktop app";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        nodejs = assert pkgs.lib.assertMsg (pkgs.nodejs_26.version == "26.13.1")
          "Update the reviewed Node pin together with nixpkgs"; pkgs.nodejs_26;
        frontend = builtins.fromJSON (builtins.readFile ./frontend/package.json);
        pnpmPackage = pkgs.pnpm_10.override { nodejs-slim = nodejs; };
        pnpm = assert pkgs.lib.assertMsg
          (!(frontend ? packageManager) || frontend.packageManager == "pnpm@${pnpmPackage.version}")
          "Update the Nix manager together with the frontend packageManager pin"; pnpmPackage;
        runtimeHook = ''
          export PATH="${nodejs}/bin:${pnpm}/bin:$PATH"
          if [ "$(node --version)" != "v26.13.1" ] || [ "$(pnpm --version)" != "${pnpm.version}" ]; then
            echo "Nix runtime differs from the reviewed project pins" >&2
            return 1
          fi
        '';

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };

        # Tauri system dependencies (Linux/WSL)
        tauriDeps = with pkgs; [
          pkg-config
          openssl
          glib
          gtk3
          libsoup_3
          webkitgtk_4_1
          librsvg
          libappindicator-gtk3
        ];

        # Mesa drivers for EGL/GL (needed for WebKitGTK rendering)
        mesaDrivers = pkgs.mesa.drivers;

        # All native build inputs
        nativeBuildInputs = with pkgs; [
          rustToolchain
          cargo-tauri
          nodejs
          pnpm
        ] ++ tauriDeps;

      in {
        packages = { inherit nodejs pnpm; };
        checks.runtime = pkgs.runCommand "revvault-nix-runtime" {
          nativeBuildInputs = [ nodejs pnpm ];
        } ''
          ${runtimeHook}
          test "$(command -v node)" = "${nodejs}/bin/node"
          test "$(command -v pnpm)" = "${pnpm}/bin/pnpm"
          node --input-type=module -e 'if (process.versions.modules !== "147") throw new Error("unexpected Node ABI"); await Promise.resolve();'
          touch "$out"
        '';
        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs;

          buildInputs = with pkgs; [
            # Dev tools
            cargo-watch
            cargo-nextest
          ];

          shellHook = runtimeHook + ''
            echo "revvault dev shell ready ($(rustc --version))"
            echo "  cargo build --workspace    # build all crates"
            echo "  cargo tauri dev            # launch Tauri app"
            echo "  cargo nextest run          # run tests"
          '';

          # Tauri needs these at runtime.
          # mesaDrivers provides libEGL_mesa.so.0 (needed by libglvnd) and
          # DRI drivers (d3d12 for WSLg, llvmpipe for software fallback).
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (tauriDeps ++ [ mesaDrivers ]);
          LIBGL_DRIVERS_PATH = "${mesaDrivers}/lib/dri";

          # For openssl-sys
          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
        };
      });
}
