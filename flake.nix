{
  description = "very minimal flake";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        libs = with pkgs; [
          glfw
          libGL
          libglvnd
          wayland
          libxkbcommon
          alsa-lib
          libx11
          libxcursor
          libxi
          libxinerama
          libxrandr
          libxext
          libxrender
          libxxf86vm
        ];
      in
      {
        legacyPackages = pkgs;
        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            stdenv.cc
            clang
            pkg-config
          ] ++ libs;
          # raylib/GLFW dlopen these at runtime. `/run/opengl-driver/lib` is
          # the NixOS Mesa vendor (libGLX_mesa) — without it GLX fails to load.
          LD_LIBRARY_PATH =
            "lib:"
            + pkgs.lib.makeLibraryPath libs
            + ":/run/opengl-driver/lib";
        };
      }
    );
}
