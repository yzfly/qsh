complete -c qsh -s p -d 'Port of the ssh server (ssh -p)' -r
complete -c qsh -s l -d 'User to log in as (ssh -l)' -r
complete -c qsh -s i -d 'Identity file (ssh -i); may be repeated' -r -F
complete -c qsh -s J -d 'Jump hosts (ssh -J)' -r
complete -c qsh -s F -d 'ssh configuration file (ssh -F)' -r -F
complete -c qsh -s o -d 'ssh option (ssh -o); may be repeated' -r
complete -c qsh -s 4 -d 'Use IPv4 addresses only (ssh -4)'
complete -c qsh -s 6 -d 'Use IPv6 addresses only (ssh -6)'
complete -c qsh -s v -d 'Verbose: qsh\'s own messages, and ssh -v; may be repeated'
complete -c qsh -s h -l help -d 'Print help (see more with \'--help\')'
complete -c qsh -s V -l version -d 'Print version'
