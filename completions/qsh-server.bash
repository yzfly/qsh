_qsh__server() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="qsh__server"
                ;;
            qsh__server,bootstrap)
                cmd="qsh__server__subcmd__bootstrap"
                ;;
            qsh__server,daemon)
                cmd="qsh__server__subcmd__daemon"
                ;;
            qsh__server,handoff-probe)
                cmd="qsh__server__subcmd__handoff__subcmd__probe"
                ;;
            qsh__server,help)
                cmd="qsh__server__subcmd__help"
                ;;
            qsh__server,pipe)
                cmd="qsh__server__subcmd__pipe"
                ;;
            qsh__server,status)
                cmd="qsh__server__subcmd__status"
                ;;
            qsh__server,stop)
                cmd="qsh__server__subcmd__stop"
                ;;
            qsh__server,upgrade)
                cmd="qsh__server__subcmd__upgrade"
                ;;
            qsh__server__subcmd__help,bootstrap)
                cmd="qsh__server__subcmd__help__subcmd__bootstrap"
                ;;
            qsh__server__subcmd__help,daemon)
                cmd="qsh__server__subcmd__help__subcmd__daemon"
                ;;
            qsh__server__subcmd__help,handoff-probe)
                cmd="qsh__server__subcmd__help__subcmd__handoff__subcmd__probe"
                ;;
            qsh__server__subcmd__help,help)
                cmd="qsh__server__subcmd__help__subcmd__help"
                ;;
            qsh__server__subcmd__help,pipe)
                cmd="qsh__server__subcmd__help__subcmd__pipe"
                ;;
            qsh__server__subcmd__help,status)
                cmd="qsh__server__subcmd__help__subcmd__status"
                ;;
            qsh__server__subcmd__help,stop)
                cmd="qsh__server__subcmd__help__subcmd__stop"
                ;;
            qsh__server__subcmd__help,upgrade)
                cmd="qsh__server__subcmd__help__subcmd__upgrade"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        qsh__server)
            opts="-v -h -V --help --version bootstrap pipe daemon status stop upgrade handoff-probe help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__bootstrap)
            opts="-v -h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__daemon)
            opts="-v -h --foreground --ports --on-demand --resume --state-fd --key-fd --fallback-exe-fd --fell-back --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --ports)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --state-fd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-fd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fallback-exe-fd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__handoff__subcmd__probe)
            opts="-v -h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help)
            opts="bootstrap pipe daemon status stop upgrade handoff-probe help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help__subcmd__bootstrap)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help__subcmd__daemon)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help__subcmd__handoff__subcmd__probe)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help__subcmd__pipe)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help__subcmd__stop)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__help__subcmd__upgrade)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__pipe)
            opts="-v -h --version --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__status)
            opts="-v -h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__stop)
            opts="-v -h --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        qsh__subcmd__server__subcmd__upgrade)
            opts="-v -h --exe --force --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --exe)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _qsh__server -o nosort -o bashdefault -o default qsh-server
else
    complete -F _qsh__server -o bashdefault -o default qsh-server
fi
