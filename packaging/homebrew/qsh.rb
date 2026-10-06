# Homebrew formula template for qsh (a tap first: yzfly/homebrew-tap, then homebrew-core).
# Placeholders: url version and sha256 (`brew fetch --build-from-source` prints it).
#
# Builds from source like every Rust formula in homebrew-core. The cargo feature self-install is
# enabled here because macOS users most often connect to Linux hosts that do not have qsh-server
# yet, and `qsh HOST` then offers to install it there; it never updates qsh itself (brew does).
class Qsh < Formula
  desc "Remote shell over QUIC whose sessions survive network changes"
  homepage "https://github.com/yzfly/qsh"
  url "https://github.com/yzfly/qsh/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/yzfly/qsh.git", branch: "main"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--features", "self-install", *std_cargo_args(path: "crates/qsh-cli")

    man1.install "man/qsh.1", "man/qsh-server.1" if (buildpath/"man/qsh.1").exist?
    man5.install "man/qsh_config.5" if (buildpath/"man/qsh_config.5").exist?
    if (buildpath/"completions").exist?
      bash_completion.install "completions/qsh.bash" => "qsh"
      bash_completion.install "completions/qsh-server.bash" => "qsh-server"
      zsh_completion.install "completions/_qsh", "completions/_qsh-server"
      fish_completion.install "completions/qsh.fish", "completions/qsh-server.fish"
    end
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
    # No ssh server on port 1: qsh fails cleanly with ssh's exit code for connection errors.
    shell_output("#{bin}/qsh -o BatchMode=yes -o ConnectTimeout=2 -p 1 127.0.0.1 true 2>&1", 255)
  end
end
