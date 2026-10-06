# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_qsh_server_global_optspecs
    string join \n v h/help V/version
end

function __fish_qsh_server_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_qsh_server_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_qsh_server_using_subcommand
    set -l cmd (__fish_qsh_server_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c qsh-server -n "__fish_qsh_server_needs_command" -s v -d 'Log more (repeat for more)'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -s V -l version -d 'Print version'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -f -a "bootstrap" -d 'Create a session for the client (run over ssh; request on stdin, reply on stdout)'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -f -a "pipe" -d 'Carry a connection over ssh\'s stdin and stdout (run over ssh by the client)'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -f -a "daemon" -d 'Run the per-user daemon (started on demand by bootstrap otherwise)'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -f -a "status" -d 'Show the running daemon and its sessions (JSON)'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -f -a "stop" -d 'Stop the running daemon; its sessions end'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -f -a "upgrade" -d 'Replace the running daemon with a newer qsh-server in place; sessions are kept'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -f -a "handoff-probe" -d 'Print the version and the handoff state formats this program reads (used by upgrades)'
complete -c qsh-server -n "__fish_qsh_server_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand bootstrap" -s v -d 'Log more (repeat for more)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand bootstrap" -s h -l help -d 'Print help'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand pipe" -l version -d 'Protocol version' -r
complete -c qsh-server -n "__fish_qsh_server_using_subcommand pipe" -s v -d 'Log more (repeat for more)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand pipe" -s h -l help -d 'Print help'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -l ports -d 'Ports to try, FIRST-LAST; the first free on both UDP and TCP is used' -r
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -l state-fd -d 'The descriptor of the sealed state (with --resume)' -r
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -l key-fd -d 'The descriptor of the pipe with the state\'s key (with --resume)' -r
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -l fallback-exe-fd -d 'The descriptor of the previous program, run again if resuming fails (with --resume)' -r
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -l foreground -d 'Stay in the foreground (for service managers); otherwise start in the background'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -l on-demand -d 'Exit after an hour without sessions (set when started on demand)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -l resume -d 'Resume from the state an older image of this daemon handed over (an upgrade in place)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -l fell-back -d 'The new program could not resume; this is the previous one again (with --resume)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -s v -d 'Log more (repeat for more)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand daemon" -s h -l help -d 'Print help'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand status" -s v -d 'Log more (repeat for more)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand status" -s h -l help -d 'Print help'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand stop" -s v -d 'Log more (repeat for more)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand stop" -s h -l help -d 'Print help'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand upgrade" -l exe -d 'The qsh-server to run (default: this program)' -r -F
complete -c qsh-server -n "__fish_qsh_server_using_subcommand upgrade" -l force -d 'Upgrade even to a version that is not newer'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand upgrade" -s v -d 'Log more (repeat for more)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand upgrade" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand handoff-probe" -s v -d 'Log more (repeat for more)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand handoff-probe" -s h -l help -d 'Print help'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand help; and not __fish_seen_subcommand_from bootstrap pipe daemon status stop upgrade handoff-probe help" -f -a "bootstrap" -d 'Create a session for the client (run over ssh; request on stdin, reply on stdout)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand help; and not __fish_seen_subcommand_from bootstrap pipe daemon status stop upgrade handoff-probe help" -f -a "pipe" -d 'Carry a connection over ssh\'s stdin and stdout (run over ssh by the client)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand help; and not __fish_seen_subcommand_from bootstrap pipe daemon status stop upgrade handoff-probe help" -f -a "daemon" -d 'Run the per-user daemon (started on demand by bootstrap otherwise)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand help; and not __fish_seen_subcommand_from bootstrap pipe daemon status stop upgrade handoff-probe help" -f -a "status" -d 'Show the running daemon and its sessions (JSON)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand help; and not __fish_seen_subcommand_from bootstrap pipe daemon status stop upgrade handoff-probe help" -f -a "stop" -d 'Stop the running daemon; its sessions end'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand help; and not __fish_seen_subcommand_from bootstrap pipe daemon status stop upgrade handoff-probe help" -f -a "upgrade" -d 'Replace the running daemon with a newer qsh-server in place; sessions are kept'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand help; and not __fish_seen_subcommand_from bootstrap pipe daemon status stop upgrade handoff-probe help" -f -a "handoff-probe" -d 'Print the version and the handoff state formats this program reads (used by upgrades)'
complete -c qsh-server -n "__fish_qsh_server_using_subcommand help; and not __fish_seen_subcommand_from bootstrap pipe daemon status stop upgrade handoff-probe help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
