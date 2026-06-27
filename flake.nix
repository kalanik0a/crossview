{
  description = "Crossview — MITRE CAPEC/CWE/ATT&CK/ATLAS/D3FEND scanner + TUI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # Build for every platform the toolchain supports rather than hardcoding
      # x86_64-linux, so the flake evaluates on Apple Silicon and ARM servers too.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      # Everything that was previously a top-level `let` binding is now produced
      # per-system, since `pkgs` (and thus every derivation) depends on `system`.
      perSystem = system:
        let
          pkgs = import nixpkgs { inherit system; };

          # ── Python env ────────────────────────────────────────────────────────
          # venv-in-nix approach: nix provides Python + build deps, then we
          # pip-install the package via buildPythonPackage so the crossview CLI
          # lands on PATH without a manual venv bootstrap.
          python = pkgs.python313;

          # Native build-time libs needed by some Python deps (tree-sitter C ext)
          buildInputs = with pkgs; [
            gcc
            cmake
            pkg-config
          ];

          # Runtime Python deps available in nixpkgs
          pythonDeps = with python.pkgs; [
            typer
            httpx
            rich
            xmltodict
            networkx
            jinja2
            sqlglot
            strawberry-graphql
            # SAST / secrets
            bandit
            detect-secrets
            # SARIF
            sarif-tools
            # Textual TUI
            textual
          ];

          # crossview package — pip-install from local source
          crossviewPkg = python.pkgs.buildPythonPackage {
            pname   = "crossview";
            version = "0.1.0";
            format  = "pyproject";
            src     = ./.;

            build-system = [ python.pkgs.hatchling ];

            propagatedBuildInputs = pythonDeps ++ [
              python.pkgs.setuptools
            ];

            # tree-sitter / ast-grep / crawl4ai are not in nixpkgs; they install
            # at runtime when the venv is used.  The core scanner still works
            # without them (harnesses degrade gracefully).
            doCheck = false;
          };

          # ── External scanner tools ────────────────────────────────────────────
          scannerTools = with pkgs; [
            # Secrets scanning
            trufflehog   # live-credential verification
            gitleaks     # git-history secret scanning

            # Container / IaC
            trivy        # CVE + IaC + SBOM scanner
            hadolint     # Dockerfile linter

            # Dependency CVE
            osv-scanner  # OSV DB lockfile scanner

            # SAST (Semgrep ships its own binary)
            semgrep

            # Shell SAST
            shellcheck
          ];

          devShell = pkgs.mkShell {
            name = "crossview";

            packages = [
              (python.withPackages (ps: pythonDeps ++ [ ps.pip ]))
            ] ++ scannerTools ++ buildInputs ++ (with pkgs; [
              # Convenience
              sqlite          # inspect the reference + cohort DBs directly
              jq              # pretty-print SARIF / STIX JSON output
              git             # needed by gitleaks repo mode
            ]);

            # Point Semgrep to its Nix-managed binary so it doesn't try to download
            SEMGREP_SKIP_UPDATE = "1";

            shellHook = ''
              # Editable install into the Nix Python env (user site-packages)
              export PYTHONPATH="$PWD:$PYTHONPATH"

              # Create a wrapper so `crossview` CLI works without pip install
              crossview() { python3 -m crossview.cli "$@"; }
              export -f crossview

              echo ""
              echo "  Crossview dev shell"
              echo "  ────────────────────────────────────────────────────────"
              echo "  crossview --help          show all commands"
              echo "  crossview update          download / rebuild MITRE silo"
              echo "  crossview scan <path>     full 5-stage pipeline"
              echo "  crossview triage <path>   prod-only finding filter"
              echo "  crossview tui             interactive TUI explorer"
              echo "  make dev-stats            DB row counts"
              echo ""
              echo "  Scanner tools on PATH:"
              echo "    trufflehog  gitleaks  trivy  hadolint  osv-scanner  semgrep  shellcheck"
              echo ""
            '';
          };
        in {
          inherit crossviewPkg devShell;
        };
    in {
      # ── devShell ───────────────────────────────────────────────────────────────
      devShells = forAllSystems (system: {
        default = (perSystem system).devShell;
      });

      # ── Package export (nix build / nix run) ───────────────────────────────────
      packages = forAllSystems (system:
        let pkg = (perSystem system).crossviewPkg; in {
          default   = pkg;
          crossview = pkg;
        });

      apps = forAllSystems (system: {
        default = {
          type    = "app";
          program = "${(perSystem system).crossviewPkg}/bin/crossview";
          meta.description = "Crossview CLI — MITRE silo + 5-stage code scanner";
        };
      });
    };
}
