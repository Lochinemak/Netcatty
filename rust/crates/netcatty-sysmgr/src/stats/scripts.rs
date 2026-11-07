//! Remote stats scripts, extracted verbatim from Electron's
//! `electron/bridges/sshBridge/sessionOps.cjs` (generated; keep byte-identical).

/// macOS stats segment (terminal / full sample).
pub const MACOS_STATS_FULL: &str = r#####"cores=$(sysctl -n hw.logicalcpu 2>/dev/null || echo "1"); pagesize=$(sysctl -n hw.pagesize 2>/dev/null || echo "4096"); memsize=$(sysctl -n hw.memsize 2>/dev/null || echo "0"); cpupct=$(ps -A -o %cpu= 2>/dev/null | awk -v c="$cores" '{s+=$1} END{if(c<=0)c=1;s=s/c;if(s<0)s=0;if(s>100)s=100;printf "%.0f",s}'); vmmem=$(vm_stat 2>/dev/null | awk -v ps="$pagesize" '/^Pages free:/{gsub(/[^0-9]/,"",$NF);free=$NF+0} /^Pages speculative:/{gsub(/[^0-9]/,"",$NF);spec=$NF+0} /^Pages inactive:/{gsub(/[^0-9]/,"",$NF);inact=$NF+0} /^Pages purgeable:/{gsub(/[^0-9]/,"",$NF);purg=$NF+0} END{mfree=int((free+spec)*ps/1024/1024);mcached=int((inact+purg)*ps/1024/1024);printf "%d %d",mfree,mcached}'); memtotal=$(echo "$memsize" | awk '{printf "%d",$1/1024/1024}'); memfree=$(echo "$vmmem" | awk '{print $1}'); memcached=$(echo "$vmmem" | awk '{print $2}'); swapraw=$(sysctl vm.swapusage 2>/dev/null); swaptotal=$(echo "$swapraw" | awk '{for(i=1;i<=NF;i++){if($i=="total"&&$(i+1)=="="){v=$(i+2);m=1;if(v~/G/)m=1024;gsub(/[MmGg]/,"",v);st=v*m}};printf "%.0f",st+0}'); swapused=$(echo "$swapraw" | awk '{for(i=1;i<=NF;i++){if($i=="used"&&$(i+1)=="="){v=$(i+2);m=1;if(v~/G/)m=1024;gsub(/[MmGg]/,"",v);su=v*m}};printf "%.0f",su+0}'); swapfree=$(echo "$swaptotal $swapused" | awk '{printf "%.0f",$1-$2}'); procs=$(ps -A -o pid= -o %mem= -o comm= 2>/dev/null | sort -k2 -rn | head -10 | awk '{gsub(/;/,"_",$3);printf "%s;%.1f;%s,",$1,$2,$3}' | sed 's/,$//'); mounts=$(mount 2>/dev/null || true); disks=$({ printf "%s
" "$mounts"; printf "__NETCATTY_DF__
"; df -kP 2>/dev/null; } | awk '$0=="__NETCATTY_DF__"{in_df=1;next} !in_df{if(index($1,"/dev/disk")==1&&(index($0,"(apfs,")||index($0,"(apfs)"))){key=$1;sub(/s[0-9].*$/,"",key);capacity[$1]="apfs:" key}next} $1=="Filesystem"{next} index($1,"/dev/")==1{m=$6;if(m=="/"||index(m,"/Volumes/")==1){t=$2/1048576;key=(($1 in capacity)?capacity[$1]:$1);if(key~/^apfs:/){u=($2-$4)/1048576;p=(t>0?int(u*100/t+0.5):0)}else{u=$3/1048576;p=$5;gsub(/%/,"",p)}printf "%s:%.6f:%.6f:%s:%s,",m,u,t,p,key}}' | sed 's/,$//'); net=$(netstat -ibn 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++){if($i=="Ibytes")ib=i;if($i=="Obytes")ob=i}next} ib&&ob&&$1~/^[[:alpha:]]/&&$1!~/^lo/&&$0~/<Link#/{name=$1;gsub(/[*]/,"",name);rx=$(ib)+0;tx=$(ob)+0;if(rx>0||tx>0){seen[name]=rx ":" tx}} END{for(name in seen)printf "%s:%s,",name,seen[name]}' | sed 's/,$//'); hostname_value=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo ""); osname=$(printf "%s %s" "$(sw_vers -productName 2>/dev/null)" "$(sw_vers -productVersion 2>/dev/null)" | sed 's/[[:space:]]*$//'); kernel=$(uname -r 2>/dev/null || echo ""); bootsec=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[ ,]+' '{for(i=1;i<=NF;i++){if($i=="sec"){print $(i+2);exit}}}'); nowsec=$(date +%s 2>/dev/null || echo "0"); uptime=$(awk -v n="$nowsec" -v b="$bootsec" 'BEGIN{if(n>0&&b>0)printf "%.0f",n-b}'); loadavg=$(sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' | awk '{print $1" "$2" "$3"}'); echo "CPU:$cpupct|CORES:$cores|MEMINFO:$memtotal $memfree 0 $memcached $swaptotal $swapfree|PROCS:$procs|DISKS:$disks|NET:$net|HOST:$hostname_value|OS:$osname|KERNEL:$kernel|UPTIME:$uptime|LOAD:$loadavg""#####;

/// macOS stats segment for the monitor (no process list).
pub const MACOS_STATS_MONITOR: &str = r#####"cores=$(sysctl -n hw.logicalcpu 2>/dev/null || echo "1"); pagesize=$(sysctl -n hw.pagesize 2>/dev/null || echo "4096"); memsize=$(sysctl -n hw.memsize 2>/dev/null || echo "0"); cpupct=$(ps -A -o %cpu= 2>/dev/null | awk -v c="$cores" '{s+=$1} END{if(c<=0)c=1;s=s/c;if(s<0)s=0;if(s>100)s=100;printf "%.0f",s}'); vmmem=$(vm_stat 2>/dev/null | awk -v ps="$pagesize" '/^Pages free:/{gsub(/[^0-9]/,"",$NF);free=$NF+0} /^Pages speculative:/{gsub(/[^0-9]/,"",$NF);spec=$NF+0} /^Pages inactive:/{gsub(/[^0-9]/,"",$NF);inact=$NF+0} /^Pages purgeable:/{gsub(/[^0-9]/,"",$NF);purg=$NF+0} END{mfree=int((free+spec)*ps/1024/1024);mcached=int((inact+purg)*ps/1024/1024);printf "%d %d",mfree,mcached}'); memtotal=$(echo "$memsize" | awk '{printf "%d",$1/1024/1024}'); memfree=$(echo "$vmmem" | awk '{print $1}'); memcached=$(echo "$vmmem" | awk '{print $2}'); swapraw=$(sysctl vm.swapusage 2>/dev/null); swaptotal=$(echo "$swapraw" | awk '{for(i=1;i<=NF;i++){if($i=="total"&&$(i+1)=="="){v=$(i+2);m=1;if(v~/G/)m=1024;gsub(/[MmGg]/,"",v);st=v*m}};printf "%.0f",st+0}'); swapused=$(echo "$swapraw" | awk '{for(i=1;i<=NF;i++){if($i=="used"&&$(i+1)=="="){v=$(i+2);m=1;if(v~/G/)m=1024;gsub(/[MmGg]/,"",v);su=v*m}};printf "%.0f",su+0}'); swapfree=$(echo "$swaptotal $swapused" | awk '{printf "%.0f",$1-$2}'); mounts=$(mount 2>/dev/null || true); disks=$({ printf "%s
" "$mounts"; printf "__NETCATTY_DF__
"; df -kP 2>/dev/null; } | awk '$0=="__NETCATTY_DF__"{in_df=1;next} !in_df{if(index($1,"/dev/disk")==1&&(index($0,"(apfs,")||index($0,"(apfs)"))){key=$1;sub(/s[0-9].*$/,"",key);capacity[$1]="apfs:" key}next} $1=="Filesystem"{next} index($1,"/dev/")==1{m=$6;if(m=="/"||index(m,"/Volumes/")==1){t=$2/1048576;key=(($1 in capacity)?capacity[$1]:$1);if(key~/^apfs:/){u=($2-$4)/1048576;p=(t>0?int(u*100/t+0.5):0)}else{u=$3/1048576;p=$5;gsub(/%/,"",p)}printf "%s:%.6f:%.6f:%s:%s,",m,u,t,p,key}}' | sed 's/,$//'); net=$(netstat -ibn 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++){if($i=="Ibytes")ib=i;if($i=="Obytes")ob=i}next} ib&&ob&&$1~/^[[:alpha:]]/&&$1!~/^lo/&&$0~/<Link#/{name=$1;gsub(/[*]/,"",name);rx=$(ib)+0;tx=$(ob)+0;if(rx>0||tx>0){seen[name]=rx ":" tx}} END{for(name in seen)printf "%s:%s,",name,seen[name]}' | sed 's/,$//'); hostname_value=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo ""); osname=$(printf "%s %s" "$(sw_vers -productName 2>/dev/null)" "$(sw_vers -productVersion 2>/dev/null)" | sed 's/[[:space:]]*$//'); kernel=$(uname -r 2>/dev/null || echo ""); bootsec=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[ ,]+' '{for(i=1;i<=NF;i++){if($i=="sec"){print $(i+2);exit}}}'); nowsec=$(date +%s 2>/dev/null || echo "0"); uptime=$(awk -v n="$nowsec" -v b="$bootsec" 'BEGIN{if(n>0&&b>0)printf "%.0f",n-b}'); loadavg=$(sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' | awk '{print $1" "$2" "$3"}'); echo "CPU:$cpupct|CORES:$cores|MEMINFO:$memtotal $memfree 0 $memcached $swaptotal $swapfree|PROCS:$procs|DISKS:$disks|NET:$net|HOST:$hostname_value|OS:$osname|KERNEL:$kernel|UPTIME:$uptime|LOAD:$loadavg""#####;

/// Linux stats segment (terminal / full sample).
pub const LINUX_STATS_FULL: &str = r#####"cores=$(nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "1"); cpuraw=$(awk '/^cpu / {total=0; for(i=2;i<=NF;i++) total+=$i; printf "%d %d", total, $5}' /proc/stat 2>/dev/null || echo ""); percoreraw=$(awk '/^cpu[0-9]/ {total=0; for(i=2;i<=NF;i++) total+=$i; printf "%d:%d,", total, $5}' /proc/stat 2>/dev/null | sed 's/,$//' || echo ""); meminfo=$(awk '/^MemTotal:/{t=$2} /^MemFree:/{f=$2} /^Buffers:/{b=$2} /^Cached:/{c=$2} /^SReclaimable:/{s=$2} /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2} END{printf "%d %d %d %d %d %d", t/1024, f/1024, b/1024, (c+s)/1024, st/1024, sf/1024}' /proc/meminfo 2>/dev/null || echo ""); procs=$(if procraw=$(ps -eo pid,%mem,comm --sort=-%mem 2>/dev/null); then printf "%s
" "$procraw" | awk 'NR>1 && NR<=11 {gsub(/;/, "_", $3); printf "%s;%.1f;%s,", $1, $2, $3}' | sed 's/,$//'; elif topraw=$(top -b -n 1 2>/dev/null); then printf "%s
" "$topraw" | awk '$1 == "PID" {for(i=1;i<=NF;i++){if($i=="%VSZ") mem_col=i; else if($i=="COMMAND") cmd_col=i} next} $1 ~ /^[0-9]+$/ && mem_col && cmd_col {pct=$(mem_col); gsub(/%/, "", pct); cmd=$(cmd_col); gsub(/;/, "_", cmd); print pct ";" $1 ";" cmd}' | sort -t ';' -k1,1rn | head -10 | awk -F';' '{printf "%s;%.1f;%s,", $2, $1, $3}' | sed 's/,$//'; else ps ww 2>/dev/null | awk -v total=$(awk '/^MemTotal:/{print $2}' /proc/meminfo) '$1 ~ /^[0-9]+$/ {v=$3; unit=substr(v,length(v),1); mult=1; if(unit=="m"||unit=="M")mult=1024; else if(unit=="g"||unit=="G")mult=1048576; sub(/[mMgG]$/, "", v); pct=total>0?v*mult*100/total:0; cmd=$5; gsub(/;/, "_", cmd); print pct, $1, cmd}' | sort -rn | head -10 | awk '{printf "%s;%.1f;%s,", $2, $1, $3}' | sed 's/,$//'; fi); net=$(cat /proc/net/dev 2>/dev/null | awk 'NR>2 {gsub(/^[ \t]+/, ""); split($0, a, ":"); iface=a[1]; if(iface != "lo" && iface !~ /^veth/ && iface !~ /^docker/ && iface !~ /^br-/) {split(a[2], b); printf "%s:%s:%s,", iface, b[1], b[9]}}' | sed 's/,$//' || echo ""); hostname_value=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo ""); osname=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2;exit}' /etc/os-release 2>/dev/null || uname -s 2>/dev/null || echo ""); kernel=$(uname -r 2>/dev/null || echo ""); uptime=$(awk '{printf "%.0f",$1}' /proc/uptime 2>/dev/null || echo ""); loadavg=$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || echo ""); gpustat=$(gpucsv=$(timeout -s KILL 2 nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>/dev/null) && printf '%s\n' "$gpucsv" | awk -F', *' 'NF >= 5 {idx=$1; util=$(NF-2); used=$(NF-1); total=$NF; gsub(/^[ \t"]+|[ \t"]+$/, "", idx); gsub(/^[ \t"]+|[ \t"]+$/, "", util); gsub(/^[ \t"]+|[ \t"]+$/, "", used); gsub(/^[ \t"]+|[ \t"]+$/, "", total); if (idx !~ /^[0-9]+$/) next; name=$2; for (i=3; i<=NF-3; i++) name=name ", " $i; gsub(/^[ \t"]+|[ \t"]+$/, "", name); gsub(/\t/, " ", name); gsub(/\|/, "/", name); gsub(/ ;; /, " ", name); g++; if (util ~ /^[0-9]+$/) {n++; u+=util} if (used ~ /^[0-9]+$/) {mu+=used; uc++} if (total ~ /^[0-9]+$/) {mt+=total; tc++} if (name0=="") name0=name; utilOut=(util ~ /^[0-9]+$/) ? util : "N/A"; usedOut=(used ~ /^[0-9]+$/) ? used : "N/A"; totalOut=(total ~ /^[0-9]+$/) ? total : "N/A"; rec=idx "\t" name "\t" utilOut "\t" usedOut "\t" totalOut; list=(list=="") ? rec : list " ;; " rec} END{if (n>0) {printf "%.0f %s %s %s", u/n, (uc==g ? sprintf("%.0f", mu) : "N/A"), (tc==g ? sprintf("%.0f", mt) : "N/A"), name0; if (list != "") printf " ;; %s", list}}' 2>/dev/null || echo ""); diskio=$(if [ -r /proc/uptime ]; then awk '{printf "%s;",$1}' /proc/uptime; for d in /sys/block/*; do [ -e "$d/device" ] && [ -r "$d/stat" ] || continue; awk -v path="$d" 'NF>=7 {n=split(path,a,"/");printf "%s:%s:%s,",a[n],$3,$7}' "$d/stat"; done; fi); partitionio=$(if [ -r /proc/uptime ]; then awk 'NR==1 {printf "%s;",$1;next} NF>=7 {n=split(FILENAME,a,"/");gsub(/:/,"-",a[n-1]);printf "%s:%s:%s,",a[n-1],$3,$7}' /proc/uptime /sys/dev/block/*/stat 2>/dev/null; fi); diskmounts=$(awk '{gsub(/:/,"-",$3);printf "%s:%s,",$5,$3}' /proc/self/mountinfo 2>/dev/null); echo "CPURAW:$cpuraw|CORES:$cores|PERCORERAW:$percoreraw|MEMINFO:$meminfo|PROCS:$procs|NET:$net|GPU:$gpustat|DISKIO:$diskio|PARTITIONIO:$partitionio|DISKMOUNTS:$diskmounts|HOST:$hostname_value|OS:$osname|KERNEL:$kernel|UPTIME:$uptime|LOAD:$loadavg""#####;

/// Linux stats segment for the monitor (no process list, no GPU).
pub const LINUX_STATS_MONITOR: &str = r#####"cores=$(nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "1"); cpuraw=$(awk '/^cpu / {total=0; for(i=2;i<=NF;i++) total+=$i; printf "%d %d", total, $5}' /proc/stat 2>/dev/null || echo ""); percoreraw=$(awk '/^cpu[0-9]/ {total=0; for(i=2;i<=NF;i++) total+=$i; printf "%d:%d,", total, $5}' /proc/stat 2>/dev/null | sed 's/,$//' || echo ""); meminfo=$(awk '/^MemTotal:/{t=$2} /^MemFree:/{f=$2} /^Buffers:/{b=$2} /^Cached:/{c=$2} /^SReclaimable:/{s=$2} /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2} END{printf "%d %d %d %d %d %d", t/1024, f/1024, b/1024, (c+s)/1024, st/1024, sf/1024}' /proc/meminfo 2>/dev/null || echo ""); net=$(cat /proc/net/dev 2>/dev/null | awk 'NR>2 {gsub(/^[ \t]+/, ""); split($0, a, ":"); iface=a[1]; if(iface != "lo" && iface !~ /^veth/ && iface !~ /^docker/ && iface !~ /^br-/) {split(a[2], b); printf "%s:%s:%s,", iface, b[1], b[9]}}' | sed 's/,$//' || echo ""); hostname_value=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo ""); osname=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2;exit}' /etc/os-release 2>/dev/null || uname -s 2>/dev/null || echo ""); kernel=$(uname -r 2>/dev/null || echo ""); uptime=$(awk '{printf "%.0f",$1}' /proc/uptime 2>/dev/null || echo ""); loadavg=$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || echo ""); diskio=$(if [ -r /proc/uptime ]; then awk '{printf "%s;",$1}' /proc/uptime; for d in /sys/block/*; do [ -e "$d/device" ] && [ -r "$d/stat" ] || continue; awk -v path="$d" 'NF>=7 {n=split(path,a,"/");printf "%s:%s:%s,",a[n],$3,$7}' "$d/stat"; done; fi); partitionio=$(if [ -r /proc/uptime ]; then awk 'NR==1 {printf "%s;",$1;next} NF>=7 {n=split(FILENAME,a,"/");gsub(/:/,"-",a[n-1]);printf "%s:%s:%s,",a[n-1],$3,$7}' /proc/uptime /sys/dev/block/*/stat 2>/dev/null; fi); diskmounts=$(awk '{gsub(/:/,"-",$3);printf "%s:%s,",$5,$3}' /proc/self/mountinfo 2>/dev/null); echo "CPURAW:$cpuraw|CORES:$cores|PERCORERAW:$percoreraw|MEMINFO:$meminfo|PROCS:$procs|NET:$net|GPU:$gpustat|DISKIO:$diskio|PARTITIONIO:$partitionio|DISKMOUNTS:$diskmounts|HOST:$hostname_value|OS:$osname|KERNEL:$kernel|UPTIME:$uptime|LOAD:$loadavg""#####;

/// Linux mounted-disk probe (separate request: Dropbear 9000-byte limit).
pub const LINUX_DISK_STATS: &str = r#####"disks=$( { { LC_ALL=C mount 2>/dev/null; printf "%s\n" "__NETCATTY_DF__"; LC_ALL=C df -kPT 2>/dev/null || LC_ALL=C df -kP 2>/dev/null; }; } | awk '
        $0 == "__NETCATTY_DF__" { in_df = 1; next }
        !in_df {
          on_marker = index($0, " on ");
          if (on_marker > 1) {
            mount_rest = substr($0, on_marker + 4);
            type_marker = index(mount_rest, " type ");
            if (type_marker > 1) {
              mount_point = substr(mount_rest, 1, type_marker - 1);
              filesystem_type = substr(mount_rest, type_marker + 6);
              sub(/[[:space:]].*$/, "", filesystem_type);
              mount_filesystem_types[mount_point] = filesystem_type;
            }
          }
          next
        }
        $1 == "Filesystem" { has_type = ($2 == "Type"); next }
        NF > 0 {
          source = $1;
          if (has_type) {
            filesystem_type = $2;
            total_kb = $3;
            used_kb = $4;
            percent = $6;
            mount_point = $7;
          } else {
            filesystem_type = "";
            total_kb = $2;
            used_kb = $3;
            percent = $5;
            mount_point = $6;
          }
          if ((filesystem_type == "" || filesystem_type == "-") && (mount_point in mount_filesystem_types)) {
            filesystem_type = mount_filesystem_types[mount_point];
          }
          if (mount_point == "") next;
          if (source ~ /^\/dev\/loop/ && mount_point != "/") next;
          if (mount_point != "/" && mount_point ~ /^\/(etc|proc|sys|dev|snap)(\/|$)/) next;
          if (mount_point != "/" && source ~ /^(overlay|overlayfs)(\/|$|:)/) next;
          fstype = tolower(filesystem_type);
          source_lower = tolower(source);
          is_network_or_fuse = 0;
          if (fstype ~ /^fuse\.(rclone|sshfs|s3fs|gcsfuse|ufs|mergerfs|unionfs|unionfs-fuse|ceph|ceph-fuse|cephfs|glusterfs)$/) is_network_or_fuse = 1;
          if (fstype ~ /clouddrive/) is_network_or_fuse = 1;
          if (fstype ~ /^(fuse|rclone|sshfs|s3fs|gcsfuse|mergerfs|unionfs|unionfs-fuse|nfs|nfs4|cifs|smb|smb3|smbfs|afs|ceph|cephfs|glusterfs)$/) is_network_or_fuse = 1;
          if ((filesystem_type == "" || filesystem_type == "-") && source_lower ~ /clouddrive/) is_network_or_fuse = 1;
          if ((filesystem_type == "" || filesystem_type == "-") && source_lower ~ /^(fuse|fuse\..*|rclone|rclone:.*|sshfs|s3fs|gcsfuse|mergerfs|unionfs|unionfs-fuse|ceph|ceph-fuse|cephfs|gluster|glusterfs|ufs)$/) is_network_or_fuse = 1;
          if ((filesystem_type == "" || filesystem_type == "-") && source_lower ~ /^\/\//) is_network_or_fuse = 1;
          if ((filesystem_type == "" || filesystem_type == "-") && source_lower !~ /^(apfs|overlay|overlayfs):/ && source_lower ~ /^([a-z0-9._-]+|\[[0-9a-f:]+(%[a-z0-9._-]+)?\]):\//) is_network_or_fuse = 1;
          if (is_network_or_fuse) next;
          pseudo_type = (fstype != "" && fstype != "-") ? fstype : source_lower;
          if (mount_point != "/" && pseudo_type ~ /^(tmpfs|shm|devtmpfs|udev|none|proc|sysfs|cgroup|cgroup2|devpts|mqueue|hugetlbfs|debugfs|tracefs|securityfs|pstore|bpf|fusectl|configfs|ramfs|rpc_pipefs|binfmt_misc|efivarfs)$/) next;
          total = total_kb / 1048576;
          used = used_kb / 1048576;
          if (total <= 0) next;
          gsub(/%/, "", percent);
          if (percent !~ /^[0-9]+$/) percent = int(used * 100 / total + 0.5);
          metadata = source;
          if (filesystem_type != "" && filesystem_type != "-") metadata = "fs=" filesystem_type ":" source;
          printf "%s:%.6f:%.6f:%s:%s,", mount_point, used, total, percent, metadata;
        }
      ' | sed 's/,$//' ); [ -n "$disks" ] || disks=$( { { LC_ALL=C mount 2>/dev/null; printf "%s\n" "__NETCATTY_DF__"; LC_ALL=C df -kPT / 2>/dev/null || LC_ALL=C df -kP / 2>/dev/null; }; } | awk '
        $0 == "__NETCATTY_DF__" { in_df = 1; next }
        !in_df {
          on_marker = index($0, " on ");
          if (on_marker > 1) {
            mount_rest = substr($0, on_marker + 4);
            type_marker = index(mount_rest, " type ");
            if (type_marker > 1) {
              mount_point = substr(mount_rest, 1, type_marker - 1);
              filesystem_type = substr(mount_rest, type_marker + 6);
              sub(/[[:space:]].*$/, "", filesystem_type);
              mount_filesystem_types[mount_point] = filesystem_type;
            }
          }
          next
        }
        $1 == "Filesystem" { has_type = ($2 == "Type"); next }
        NF > 0 {
          source = $1;
          if (has_type) {
            filesystem_type = $2;
            total_kb = $3;
            used_kb = $4;
            percent = $6;
            mount_point = $7;
          } else {
            filesystem_type = "";
            total_kb = $2;
            used_kb = $3;
            percent = $5;
            mount_point = $6;
          }
          if ((filesystem_type == "" || filesystem_type == "-") && (mount_point in mount_filesystem_types)) {
            filesystem_type = mount_filesystem_types[mount_point];
          }
          if (mount_point == "") next;
          if (source ~ /^\/dev\/loop/ && mount_point != "/") next;
          if (mount_point != "/" && mount_point ~ /^\/(etc|proc|sys|dev|snap)(\/|$)/) next;
          if (mount_point != "/" && source ~ /^(overlay|overlayfs)(\/|$|:)/) next;
          fstype = tolower(filesystem_type);
          source_lower = tolower(source);
          is_network_or_fuse = 0;
          if (fstype ~ /^fuse\.(rclone|sshfs|s3fs|gcsfuse|ufs|mergerfs|unionfs|unionfs-fuse|ceph|ceph-fuse|cephfs|glusterfs)$/) is_network_or_fuse = 1;
          if (fstype ~ /clouddrive/) is_network_or_fuse = 1;
          if (fstype ~ /^(fuse|rclone|sshfs|s3fs|gcsfuse|mergerfs|unionfs|unionfs-fuse|nfs|nfs4|cifs|smb|smb3|smbfs|afs|ceph|cephfs|glusterfs)$/) is_network_or_fuse = 1;
          if ((filesystem_type == "" || filesystem_type == "-") && source_lower ~ /clouddrive/) is_network_or_fuse = 1;
          if ((filesystem_type == "" || filesystem_type == "-") && source_lower ~ /^(fuse|fuse\..*|rclone|rclone:.*|sshfs|s3fs|gcsfuse|mergerfs|unionfs|unionfs-fuse|ceph|ceph-fuse|cephfs|gluster|glusterfs|ufs)$/) is_network_or_fuse = 1;
          if ((filesystem_type == "" || filesystem_type == "-") && source_lower ~ /^\/\//) is_network_or_fuse = 1;
          if ((filesystem_type == "" || filesystem_type == "-") && source_lower !~ /^(apfs|overlay|overlayfs):/ && source_lower ~ /^([a-z0-9._-]+|\[[0-9a-f:]+(%[a-z0-9._-]+)?\]):\//) is_network_or_fuse = 1;
          if (is_network_or_fuse) next;
          pseudo_type = (fstype != "" && fstype != "-") ? fstype : source_lower;
          if (mount_point != "/" && pseudo_type ~ /^(tmpfs|shm|devtmpfs|udev|none|proc|sysfs|cgroup|cgroup2|devpts|mqueue|hugetlbfs|debugfs|tracefs|securityfs|pstore|bpf|fusectl|configfs|ramfs|rpc_pipefs|binfmt_misc|efivarfs)$/) next;
          total = total_kb / 1048576;
          used = used_kb / 1048576;
          if (total <= 0) next;
          gsub(/%/, "", percent);
          if (percent !~ /^[0-9]+$/) percent = int(used * 100 / total + 0.5);
          metadata = source;
          if (filesystem_type != "" && filesystem_type != "-") metadata = "fs=" filesystem_type ":" source;
          printf "%s:%.6f:%.6f:%s:%s,", mount_point, used, total, percent, metadata;
        }
      ' | sed 's/,$//' ); echo "DISKS:$disks""#####;

/// Monitor-only GPU probe body.
pub const MONITOR_GPU_PROBE: &str = r#####"if [ "$(uname -s 2>/dev/null)" = "Linux" ]; then gpustat=$(gpucsv=$(timeout -s KILL 2 nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>/dev/null) && printf '%s\n' "$gpucsv" | awk -F', *' 'NF >= 5 {idx=$1; util=$(NF-2); used=$(NF-1); total=$NF; gsub(/^[ \t"]+|[ \t"]+$/, "", idx); gsub(/^[ \t"]+|[ \t"]+$/, "", util); gsub(/^[ \t"]+|[ \t"]+$/, "", used); gsub(/^[ \t"]+|[ \t"]+$/, "", total); if (idx !~ /^[0-9]+$/) next; name=$2; for (i=3; i<=NF-3; i++) name=name ", " $i; gsub(/^[ \t"]+|[ \t"]+$/, "", name); gsub(/\t/, " ", name); gsub(/\|/, "/", name); gsub(/ ;; /, " ", name); g++; if (util ~ /^[0-9]+$/) {n++; u+=util} if (used ~ /^[0-9]+$/) {mu+=used; uc++} if (total ~ /^[0-9]+$/) {mt+=total; tc++} if (name0=="") name0=name; utilOut=(util ~ /^[0-9]+$/) ? util : "N/A"; usedOut=(used ~ /^[0-9]+$/) ? used : "N/A"; totalOut=(total ~ /^[0-9]+$/) ? total : "N/A"; rec=idx "\t" name "\t" utilOut "\t" usedOut "\t" totalOut; list=(list=="") ? rec : list " ;; " rec} END{if (n>0) {printf "%.0f %s %s %s", u/n, (uc==g ? sprintf("%.0f", mu) : "N/A"), (tc==g ? sprintf("%.0f", mt) : "N/A"), name0; if (list != "") printf " ;; %s", list}}' 2>/dev/null || echo ""); echo "GPU:$gpustat"; fi"#####;
