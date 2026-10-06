# Homebrew formula for qsh: for the tap yzfly/homebrew-tap first, then homebrew-core.
# On a version bump: url and sha256 (`brew fetch --build-from-source qsh` prints it).
#
# Builds from source like every Rust formula in homebrew-core. The cargo feature self-install is
# enabled here because macOS users most often connect to Linux hosts that do not have qsh-server
# yet, and `qsh HOST` then offers to install it there; it never updates qsh itself (brew does).
class Qsh < Formula
  desc "Remote shell over QUIC whose sessions survive network changes"
  homepage "https://github.com/yzfly/qsh"
  url "https://github.com/yzfly/qsh/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "48bffc66548c16c2f2c2b45c6ad2b020cbcc199d690dea73ab1df57e7bbcdca3"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/yzfly/qsh.git", branch: "main"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--features", "self-install", *std_cargo_args(path: "crates/qsh-cli")

    man1.install "man/qsh.1", "man/qsh-server.1"
    man5.install "man/qsh_config.5"
    bash_completion.install "completions/qsh.bash" => "qsh"
    bash_completion.install "completions/qsh-server.bash" => "qsh-server"
    zsh_completion.install "completions/_qsh", "completions/_qsh-server"
    fish_completion.install "completions/qsh.fish", "completions/qsh-server.fish"
  end

  # `brew services start qsh`: keep the per-user daemon running. Optional; `qsh HOST` starts it on
  # demand over ssh.
  service do
    run [opt_bin/"qsh-server", "daemon", "--foreground"]
    keep_alive successful_exit: false
    log_path var/"log/qsh-server.log"
    error_log_path var/"log/qsh-server.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/qsh --version")
    assert_match version.to_s, shell_output("#{bin}/qsh-server --version")

    # A real session on this machine: an ssh stand-in runs the remote command locally, so qsh
    # bootstraps qsh-server, which starts its daemon, and the client connects to it over QUIC.
    (testpath/"bin/ssh").write <<~SH
      #!/bin/sh
      if [ "$1" = -G ]; then echo "hostname 127.0.0.1"; exit 0; fi
      while [ $# -gt 0 ]; do
        case "$1" in
          -o|-p|-l|-i|-J|-F|-E|-b|-c|-m) shift 2 ;;
          --) shift; break ;;
          -*) shift ;;
          *) break ;;
        esac
      done
      shift
      exec sh -c "$*"
    SH
    chmod 0755, testpath/"bin/ssh"
    (testpath/"run").mkpath
    chmod 0700, testpath/"run"
    ENV["PATH"] = "#{testpath}/bin:#{bin}:/usr/bin:/bin"
    ENV["XDG_RUNTIME_DIR"] = (testpath/"run").to_s
    ENV["XDG_STATE_HOME"] = (testpath/"state").to_s
    ENV["XDG_CONFIG_HOME"] = (testpath/"config").to_s
    ENV["QSH_SERVER_PORTS"] = "61443-61463"
    begin
      output = pipe_output("#{bin}/qsh testhost -- 'echo hello from qsh; exit 3'", "", 3)
      assert_equal "hello from qsh\n", output
    ensure
      system bin/"qsh-server", "stop"
    end
  end
end
