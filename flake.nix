{
  description = "Description for ocaml project";

  inputs = {
    nixpkgs.url = "github:nix-ocaml/nix-overlays";
    flake-parts.url = "github:hercules-ci/flake-parts";
    libbpf-src = {
      url = "github:koonwen/ocaml-libbpf";
      flake = false;
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        let

          inherit (pkgs) dockerTools mkShell;
          inherit (dockerTools) buildImage;
          # Use specific version of ocamlPackages
          # inherit (pkgs) ocamlPackages;
          ocamlPackages = pkgs.ocaml-ng.ocamlPackages_5_4;
          inherit (ocamlPackages) buildDunePackage;
          name = "peerforate";
          version = "0.0.1";
          libbpf = ocamlPackages.buildDunePackage rec {
            pname = "libbpf";
            version = "";
            src = inputs.libbpf-src;
            propagatedBuildInputs = with ocamlPackages; [
              ctypes
              ppx_deriving
              ppx_expect
              pkgs.libbpf
            ];
          };
        in
        {
          devShells = {
            default = mkShell {
              inputsFrom = [ self'.packages.default ];
              buildInputs = with ocamlPackages; [
                utop
                ocamlformat
                ocaml-lsp
                # patch ocaml-lsp so that inlay hints dont hide ghost values
              ];
            };
          };

          packages = {
            default = buildDunePackage {
              inherit version;
              pname = name;
              src = ./.;
              buildInputs = with ocamlPackages; [
                core
                core_unix
                cstruct
                cstruct-sexp
                ppx_cstruct
                ppx_jane
                base
                ctypes
                ctypes-foreign
                ipaddr
                pkgs.libffi
                # libbpf
                mirage-crypto-ec
                mirage-crypto-rng
                dns
                dns-server
                dns-resolver
                dns-stub
                eio
                eio_main
                logs
                domain-name
                ptime
              ];
            };

            docker = buildImage {
              inherit name;
              tag = version;
              config = {
                Cmd = [ "${self'.packages.default}/bin/${name}" ];
                Env = [
                  "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                ];
              };
            };
          };
        };
    };
}
