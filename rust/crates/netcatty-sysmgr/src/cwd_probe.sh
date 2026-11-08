SELF=$$
    TARGET_LOGIN=@@TARGET_LOGIN@@
    ALLOW_HOME_FALLBACK=@@ALLOW_HOME@@
    ALLOW_LOGIN_FALLBACK=@@ALLOW_LOGIN@@
    find_login_shell() {
      _shell=$(ps -e -o pid= -o ppid= -o tty= -o comm= 2>/dev/null | awk -v pp="$1" -v self="$SELF" '
        function isshell(c) { sub(/^.*\//, "", c); sub(/^-/, "", c); return c ~ /^(ba|z|fi|k|da|a|c|tc)?sh$/ }
        $1 != self && $2 == pp && isshell($4) {
          if ($3 !~ /^\?+$/) { print $1; found=1; exit }
          if (any == "") any=$1
        }
        END { if (!found && any != "") print any }
      ')
      [ -n "$_shell" ] && { echo "$_shell"; return; }
      _conn=$(tr '\0' '\n' < /proc/$SELF/environ 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -n1)
      [ -z "$_conn" ] && return
      _any=""
      for _d in /proc/[0-9]*; do
        _pid=$(basename "$_d")
        [ "$_pid" = "$SELF" ] && continue
        [ -r "$_d/environ" ] || continue
        _conn2=$(tr '\0' '\n' < "$_d/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -n1)
        [ "$_conn2" = "$_conn" ] || continue
        _comm=$(cat "$_d/comm" 2>/dev/null)
        case "$_comm" in
          sh|bash|zsh|fish|ksh|dash|ash|csh|tcsh) ;;
          *) continue ;;
        esac
        _tty=$(ps -p "$_pid" -o tty= 2>/dev/null | tr -d '[:space:]')
        if [ "$_tty" != "?" ] && [ -n "$_tty" ]; then
          echo "$_pid"
          return
        fi
        [ -z "$_any" ] && _any="$_pid"
      done
      [ -n "$_any" ] && echo "$_any"
    }
    find_active_shell() {
      ps -e -o pid= -o ppid= -o stat= -o comm= 2>/dev/null | awk -v start="$1" '
        { pp[$1]=$2; st[$1]=$3; cm[$1]=$4; ord[NR]=$1 }
        function isshell(c) { sub(/^.*\//, "", c); sub(/^-/, "", c); return c ~ /^(ba|z|fi|k|da|a|c|tc)?sh$/ }
        function depth(p,   d) { d=0; while (p != "" && d < 64) { if (p == start) return d; p=pp[p]; d++ } return -1 }
        END {
          best=-1; bp="";
          for (i=1; i<=NR; i++) {
            p=ord[i];
            if (!isshell(cm[p])) continue;
            if (index(st[p], "+") == 0) continue;
            d=depth(p); if (d < 0) continue;
            if (d > best) { best=d; bp=p }
          }
          print (bp != "" ? bp : start)
        }
      '
    }
    read_shell_cwd() {
      _rc_cwd=$(readlink "/proc/$1/cwd" 2>/dev/null)
      if [ -n "$_rc_cwd" ]; then printf '%s\n' "$_rc_cwd"; return 0; fi
      if command -v lsof >/dev/null 2>&1; then
        _rc_cwd=$(LC_ALL=C lsof -a -p "$1" -d cwd -Fnt 2>/dev/null | awk '
          /^f/ { is_dir=0 }
          /^t/ { is_dir=($0 == "tDIR" || $0 == "tVDIR") }
          /^n/ && is_dir {
            name=substr($0, 2)
            if (name ~ / \([A-Za-z][A-Za-z0-9]*: .*\)$/) print "?" name
            else print name
            exit
          }
        ')
        case "$_rc_cwd" in
          \?*)
            _rc_cwd=${_rc_cwd#?}
            _rc_test_cwd=$(printf '%s' "$_rc_cwd" | LC_ALL=C awk '
              function hex(c) { return index("0123456789abcdef", tolower(c)) - 1 }
              {
                for (i=1; i<=length($0); i++) {
                  c=substr($0,i,1)
                  if (c!="\\") { printf "%s", c; continue }
                  e=substr($0,++i,1)
                  if (e=="x") {
                    hi=hex(substr($0,++i,1)); lo=hex(substr($0,++i,1))
                    if (hi<0 || lo<0) exit 1
                    printf "%c", hi*16+lo
                  } else if (e=="\\") printf "\\"
                  else if (e=="n") printf "\n"
                  else if (e=="r") printf "\r"
                  else if (e=="t") printf "\t"
                  else if (e=="b") printf "%c", 8
                  else if (e=="f") printf "%c", 12
                  else if (e=="v") printf "%c", 11
                  else if (e ~ /^[0-7]$/) {
                    n=e+0
                    for (j=0; j<2 && substr($0,i+1,1) ~ /^[0-7]$/; j++) {
                      n=n*8+substr($0,++i,1)
                    }
                    printf "%c", n
                  } else exit 1
                }
              }
            ') || return 1
            [ -d "$_rc_test_cwd" ] || return 1
            ;;
        esac
        if [ -n "$_rc_cwd" ]; then printf 'NETCATTY_LSOF_CWD=%s\n' "$_rc_cwd"; return 0; fi
      fi
      return 1
    }
    login="$TARGET_LOGIN"
    [ -n "$login" ] || login=$(find_login_shell "${NC_SSHD_PPID:-$PPID}")
    if [ -n "$login" ]; then
      printf 'NETCATTY_LOGIN_PID=%s\n' "$login" >&2
      pid=$(find_active_shell "$login")
      [ -n "$pid" ] || pid="$login"
      cwd=$(read_shell_cwd "$pid")
      if [ -z "$cwd" ] && [ "$pid" != "$login" ] && [ "$ALLOW_LOGIN_FALLBACK" = "1" ]; then
        cwd=$(read_shell_cwd "$login")
      fi
      [ -n "$cwd" ] && printf '%s\n' "$cwd" && exit 0
    fi
    [ "$ALLOW_HOME_FALLBACK" = "1" ] || exit 1
    emit_home() {
      case "$1" in
        /*) printf '%s\n' "$1"; exit 0 ;;
      esac
    }
    home=$(eval echo "~" 2>/dev/null)
    emit_home "$home"
    uid=$(id -u 2>/dev/null)
    if [ -n "$uid" ]; then
      home=$(getent passwd "$uid" 2>/dev/null | awk -F: 'NR == 1 { print $6; exit }')
      emit_home "$home"
      home=$(awk -F: -v uid="$uid" '$3 == uid { print $6; exit }' /etc/passwd 2>/dev/null)
      emit_home "$home"
    fi
    home=$(id -P 2>/dev/null | awk -F: 'NR == 1 { print $9; exit }')
    emit_home "$home"
    emit_home "$HOME"
    exit 1