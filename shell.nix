let
  pkgs = import <nixpkgs> { inherit config; };
  config = {
    allowUnfree = true;
    packageOverrides = pkgs: with pkgs; rec {
      jemalloc = pkgs.callPackage ./nixdeps/jemalloc.nix {};
    };
  };
in with pkgs; haskell.lib.buildStackProject {
  name = "servant-auth-token";
  nativeBuildInputs = [ git pkgconfig ];
  buildInputs = [
    zlib
    postgresql96
    rocksdb
    leveldb
   ];
}
