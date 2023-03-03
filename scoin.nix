# to get a reproducable shell using nix:
# run `nix-shell scoin.nix -A clangEnv`
# for scala-native be sure to include the `-A clangEnv`
# for scala-jvm and scalajs, the `-A clangEnv` is not necessary
# 

let
  pkgs = import <nixpkgs> {};
  stdenv = pkgs.stdenv;
in rec {
  # change rev and sha256 below to use specific version of secp256k1
  secp256k1Latest = pkgs.secp256k1.overrideAttrs 
    (finalAttrs: previousAttrs: 
        { 
          src = pkgs.fetchFromGitHub {
                owner = "bitcoin-core"; 
                repo = "secp256k1";
                # below corresponds with unreleased 0.2 version on github 
                rev = "e025ccdf7473702a76bb13d763dc096548ffefba"; 
                sha256 = "PNfxO5svk8rIVt2MbVDmYh+q5VdPaJG341lDQZ7yPmQ="; 
          }; 
        }
    );
  clangEnv = stdenv.mkDerivation rec {
    name = "clang-env";
    shellHook = ''
    alias cls=clear
    '';
    LLVM_BIN = pkgs.clang + "/bin";
    buildInputs = with pkgs; [
      stdenv
      sbt
      openjdk
      boehmgc
      libunwind
      clang
      zlib
      secp256k1Latest
      nodejs
      yarn 
    ];
  };
} 
