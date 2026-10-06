# RPM spec for qsh, following the Fedora Rust packaging guidelines
# (https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/) with cargo-rpm-macros.
# Builds offline against the distribution's rust-*-devel crate packages; with
# `--with vendor` it uses a `cargo vendor` tarball instead (EPEL, openSUSE, older releases).
#
# Placeholders to fill in when updating: Version, the changelog, and for vendored builds the
# Source1 tarball (`cargo vendor --locked vendor && tar cJf qsh-VERSION-vendor.tar.xz vendor`).
#
# The cargo feature self-install (downloads release binaries at runtime) is off by default and
# stays off: this build makes no network access at build time or at runtime.

%bcond check 1
%bcond vendor 0

Name:           qsh
Version:        0.1.0
Release:        %autorelease
Summary:        Remote shell over QUIC whose sessions survive network changes

SourceLicense:  MIT OR Apache-2.0
# Of the statically linked crates; regenerate with %%{cargo_license_summary} on every update.
License:        MIT OR Apache-2.0
URL:            https://github.com/yzfly/qsh
Source0:        %{url}/archive/v%{version}/qsh-%{version}.tar.gz
%if %{with vendor}
Source1:        qsh-%{version}-vendor.tar.xz
%endif

BuildRequires:  cargo-rpm-macros >= 26
BuildRequires:  systemd-rpm-macros

Requires:       openssh-clients

%global _description %{expand:
qsh is used like ssh: the same destinations, ~/.ssh/config, keys, agent,
known_hosts and ProxyJump. The first connection runs over ssh to start the
session; after that the session lives on the server and the client talks to it
over QUIC, so it survives Wi-Fi/cellular switches, sleep and roaming, and
replays the output that was missed. When UDP is blocked, qsh falls back to TLS
over TCP or to an ssh pipe.}

%description %{_description}

This package contains the client, qsh.

%package        server
Summary:        Server side of qsh, a remote shell over QUIC
License:        MIT OR Apache-2.0
%{?systemd_requires}

%description    server %{_description}

This package contains qsh-server, which the client starts over ssh as the
logged-in user. It needs no root and no configuration; a systemd user unit is
included for those who want the daemon supervised.

%prep
%autosetup -n qsh-%{version} -p1 %{?with_vendor:-a1}
%if %{with vendor}
%cargo_prep -v vendor
%else
%cargo_prep
%endif

%if %{without vendor}
%generate_buildrequires
%cargo_generate_buildrequires
%endif

%build
%cargo_build
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies
%if %{with vendor}
%{cargo_vendor_manifest}
%endif

%install
# A virtual workspace: %%cargo_install handles single crates, so install the two binaries from
# cargo-rpm-macros' target directory.
install -Dpm 0755 target/rpm/qsh %{buildroot}%{_bindir}/qsh
install -Dpm 0755 target/rpm/qsh-server %{buildroot}%{_bindir}/qsh-server
install -Dpm 0644 packaging/systemd/qsh-server.service %{buildroot}%{_userunitdir}/qsh-server.service
install -Dpm 0644 -t %{buildroot}%{_mandir}/man1 man/qsh.1 man/qsh-server.1
install -Dpm 0644 -t %{buildroot}%{_mandir}/man5 man/qsh_config.5
install -Dpm 0644 completions/qsh.bash %{buildroot}%{bash_completions_dir}/qsh
install -Dpm 0644 completions/qsh-server.bash %{buildroot}%{bash_completions_dir}/qsh-server
install -Dpm 0644 -t %{buildroot}%{zsh_completions_dir} completions/_qsh completions/_qsh-server
install -Dpm 0644 -t %{buildroot}%{fish_completions_dir} completions/qsh.fish completions/qsh-server.fish

%if %{with check}
%check
%cargo_test
%endif

%post server
%systemd_user_post qsh-server.service

%preun server
%systemd_user_preun qsh-server.service

%files
%license LICENSE-MIT LICENSE-APACHE LICENSE.dependencies
%if %{with vendor}
%license cargo-vendor.txt
%endif
%doc README.md CHANGELOG.md docs/DESIGN.md docs/protocol.md docs/security.md
%{_bindir}/qsh
%{_mandir}/man1/qsh.1*
%{_mandir}/man5/qsh_config.5*
%{bash_completions_dir}/qsh
%{zsh_completions_dir}/_qsh
%{fish_completions_dir}/qsh.fish

%files server
%license LICENSE-MIT LICENSE-APACHE LICENSE.dependencies
%doc README.md docs/security.md
%{_bindir}/qsh-server
%{_userunitdir}/qsh-server.service
%{_mandir}/man1/qsh-server.1*
%{bash_completions_dir}/qsh-server
%{zsh_completions_dir}/_qsh-server
%{fish_completions_dir}/qsh-server.fish

%changelog
%autochangelog
