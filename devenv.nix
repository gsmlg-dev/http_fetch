{ pkgs, lib, config, inputs, ... }:

let
  pkgs-stable = import inputs.nixpkgs-stable { system = pkgs.stdenv.system; };
in
{
  env.GREET = "HTTP";

  packages = with pkgs-stable; [
    git
    figlet
    lolcat
    openssl
    openssl.dev
    pkg-config
    stdenv.cc
    watchman
  ] ++ lib.optionals stdenv.isLinux [
    inotify-tools
  ];

  languages.elixir.enable = true;
  languages.elixir.package = pkgs-stable.beam28Packages.elixir;

  # Independent protocol peers and the compiled TLS identity fixture.
  languages.python.enable = true;
  languages.python.package = pkgs-stable.python312;
  languages.python.venv.enable = true;
  languages.python.venv.requirements = builtins.readFile ./scripts/requirements-http2-stream-clients.txt;

  scripts.hello.exec = ''
    figlet -w 120 $GREET | lolcat
  '';

  enterShell = ''
    hello
  '';

}
