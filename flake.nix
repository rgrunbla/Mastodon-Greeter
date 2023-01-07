{
  description = "The Fediverse development environment.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
  };

  outputs = { self, nixpkgs }:
    with import nixpkgs { system = "x86_64-linux"; }; {
      # Development Shell
      devShell.x86_64-linux = mkShell {
        buildInputs = [
          openssl
          rustup
          rust-analyzer
          meilisearch
          pkgconfig
          nodejs
          yarn
        ];
        shellHook = ''
          export OPENSSL_DIR="${openssl.dev}"
          export OPENSSL_LIB_DIR="${openssl.out}/lib"
        '';
      };
    };
}
