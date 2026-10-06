# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_qsh_global_optspecs
    string join \n p= l= i= J= F= o= 4 6 v h/help V/version
end

function __fish_qsh_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_qsh_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_qsh_using_subcommand
    set -l cmd (__fish_qsh_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c qsh -n "__fish_qsh_needs_command" -s p -d 'Port of the ssh server (ssh -p)' -r
complete -c qsh -n "__fish_qsh_needs_command" -s l -d 'User to log in as (ssh -l)' -r
complete -c qsh -n "__fish_qsh_needs_command" -s i -d 'Identity file (ssh -i); may be repeated' -r -F
complete -c qsh -n "__fish_qsh_needs_command" -s J -d 'Jump hosts (ssh -J)' -r
complete -c qsh -n "__fish_qsh_needs_command" -s F -d 'ssh configuration file (ssh -F)' -r -F
complete -c qsh -n "__fish_qsh_needs_command" -s o -d 'ssh option (ssh -o); may be repeated' -r
complete -c qsh -n "__fish_qsh_needs_command" -s 4 -d 'Use IPv4 addresses only (ssh -4)'
complete -c qsh -n "__fish_qsh_needs_command" -s 6 -d 'Use IPv6 addresses only (ssh -6)'
complete -c qsh -n "__fish_qsh_needs_command" -s v -d 'Verbose: qsh\'s own messages, and ssh -v; may be repeated'
complete -c qsh -n "__fish_qsh_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c qsh -n "__fish_qsh_needs_command" -s V -l version -d 'Print version'
complete -c qsh -n "__fish_qsh_needs_command" -a "attach" -d 'Reattach a detached session, replaying the output it produced meanwhile'
complete -c qsh -n "__fish_qsh_needs_command" -a "ls" -d 'List sessions: on DESTINATION (over ssh), or the saved ones of every host'
complete -c qsh -n "__fish_qsh_needs_command" -a "kill" -d 'End a session: its programs get SIGHUP'
complete -c qsh -n "__fish_qsh_needs_command" -a "install" -d 'Install qsh-server into ~/.local/bin on DESTINATION (builds with feature self-install)'
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s p -d 'Port of the ssh server (ssh -p)' -r
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s l -d 'User to log in as (ssh -l)' -r
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s i -d 'Identity file (ssh -i); may be repeated' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s J -d 'Jump hosts (ssh -J)' -r
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s F -d 'ssh configuration file (ssh -F)' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s o -d 'ssh option (ssh -o); may be repeated' -r
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s 4 -d 'Use IPv4 addresses only (ssh -4)'
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s 6 -d 'Use IPv6 addresses only (ssh -6)'
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s v -d 'Verbose: qsh\'s own messages, and ssh -v; may be repeated'
complete -c qsh -n "__fish_qsh_using_subcommand attach" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s p -d 'Port of the ssh server (ssh -p)' -r
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s l -d 'User to log in as (ssh -l)' -r
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s i -d 'Identity file (ssh -i); may be repeated' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s J -d 'Jump hosts (ssh -J)' -r
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s F -d 'ssh configuration file (ssh -F)' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s o -d 'ssh option (ssh -o); may be repeated' -r
complete -c qsh -n "__fish_qsh_using_subcommand ls" -l json -d 'Print JSON, for scripts'
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s 4 -d 'Use IPv4 addresses only (ssh -4)'
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s 6 -d 'Use IPv6 addresses only (ssh -6)'
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s v -d 'Verbose: qsh\'s own messages, and ssh -v; may be repeated'
complete -c qsh -n "__fish_qsh_using_subcommand ls" -s h -l help -d 'Print help'
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s p -d 'Port of the ssh server (ssh -p)' -r
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s l -d 'User to log in as (ssh -l)' -r
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s i -d 'Identity file (ssh -i); may be repeated' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s J -d 'Jump hosts (ssh -J)' -r
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s F -d 'ssh configuration file (ssh -F)' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s o -d 'ssh option (ssh -o); may be repeated' -r
complete -c qsh -n "__fish_qsh_using_subcommand kill" -l all -d 'End every session on DESTINATION'
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s 4 -d 'Use IPv4 addresses only (ssh -4)'
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s 6 -d 'Use IPv6 addresses only (ssh -6)'
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s v -d 'Verbose: qsh\'s own messages, and ssh -v; may be repeated'
complete -c qsh -n "__fish_qsh_using_subcommand kill" -s h -l help -d 'Print help'
complete -c qsh -n "__fish_qsh_using_subcommand install" -l from -d 'Copy this qsh-server binary instead (built for the host\'s system)' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand install" -s p -d 'Port of the ssh server (ssh -p)' -r
complete -c qsh -n "__fish_qsh_using_subcommand install" -s l -d 'User to log in as (ssh -l)' -r
complete -c qsh -n "__fish_qsh_using_subcommand install" -s i -d 'Identity file (ssh -i); may be repeated' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand install" -s J -d 'Jump hosts (ssh -J)' -r
complete -c qsh -n "__fish_qsh_using_subcommand install" -s F -d 'ssh configuration file (ssh -F)' -r -F
complete -c qsh -n "__fish_qsh_using_subcommand install" -s o -d 'ssh option (ssh -o); may be repeated' -r
complete -c qsh -n "__fish_qsh_using_subcommand install" -s 4 -d 'Use IPv4 addresses only (ssh -4)'
complete -c qsh -n "__fish_qsh_using_subcommand install" -s 6 -d 'Use IPv6 addresses only (ssh -6)'
complete -c qsh -n "__fish_qsh_using_subcommand install" -s v -d 'Verbose: qsh\'s own messages, and ssh -v; may be repeated'
complete -c qsh -n "__fish_qsh_using_subcommand install" -s h -l help -d 'Print help (see more with \'--help\')'
