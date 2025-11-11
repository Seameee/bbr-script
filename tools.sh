#!/usr/bin/env bash
Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

# 检测是否为Debian 13系统
is_debian13() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "debian" && "$VERSION_ID" == "13" ]]; then
            return 0
        fi
    fi
    return 1
}

# 通用sysctl配置写入函数
write_sysctl_config() {
    local config_name="$1"
    local config_file
    
    if is_debian13; then
        config_file="/etc/sysctl.d/99-${config_name}.conf"
        printf "%s 检测到Debian 13系统，将配置写入 %s\n" "${Info}" "${config_file}" >&2
    else
        config_file="/etc/sysctl.conf"
        printf "%s 检测到非Debian 13系统，将配置写入 %s\n" "${Info}" "${config_file}" >&2
    fi
    
    # 确保目录存在
    mkdir -p "$(dirname "$config_file")"
    
    echo "$config_file"
}

copyright(){
    clear
echo "\
############################################################

Linux网络优化脚本
Powered by NNC.SH
Modified by Seamee

############################################################
"
}

tcp_tune(){ # 优化TCP窗口
    local config_file
    config_file=$(write_sysctl_config "bbr")
    
    # 删除现有配置（如果文件不存在则静默失败）
    sed -i '/net.ipv4.tcp_no_metrics_save/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_ecn/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_frto/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_mtu_probing/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_rfc1337/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_sack/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_fack/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_window_scaling/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_adv_win_scale/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_moderate_rcvbuf/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_rmem/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_wmem/d' "$config_file" 2>/dev/null || true
    sed -i '/net.core.rmem_max/d' "$config_file" 2>/dev/null || true
    sed -i '/net.core.wmem_max/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.udp_rmem_min/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.udp_wmem_min/d' "$config_file" 2>/dev/null || true
    sed -i '/net.core.default_qdisc/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d' "$config_file" 2>/dev/null || true
    
    # 写入新配置
    cat >> "$config_file" << EOF
# TCP优化配置
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 16384 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    
    sysctl -p "$config_file" && sysctl --system
}

enable_forwarding(){ #开启内核转发
    local config_file
    config_file=$(write_sysctl_config "forwarding")
    
    # 删除现有配置（如果文件不存在则静默失败）
    sed -i '/net.ipv4.conf.all.route_localnet/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.ip_forward/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.conf.all.forwarding/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.conf.default.forwarding/d' "$config_file" 2>/dev/null || true
    
    # 写入新配置
    cat >> "$config_file" << EOF
# 内核转发配置
net.ipv4.conf.all.route_localnet=1
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
EOF
    
    sysctl -p "$config_file" && sysctl --system
}

banping(){
    local config_file
    config_file=$(write_sysctl_config "banping")
    
    # 删除现有配置（如果文件不存在则静默失败）
    sed -i '/net.ipv4.icmp_echo_ignore_all/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' "$config_file" 2>/dev/null || true
    
    # 写入新配置
    cat >> "$config_file" << EOF
# 禁止ping配置
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
EOF
    
    sysctl -p "$config_file" && sysctl --system
}

unbanping(){
    local config_file
    config_file=$(write_sysctl_config "banping")
    
    # 删除禁止ping配置（如果文件不存在则静默失败）
    sed -i '/net.ipv4.icmp_echo_ignore_all/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' "$config_file" 2>/dev/null || true
    
    # 写入允许ping配置
    cat >> "$config_file" << EOF
# 允许ping配置
net.ipv4.icmp_echo_ignore_all=0
net.ipv4.icmp_echo_ignore_broadcasts=0
EOF
    
    sysctl -p "$config_file" && sysctl --system
}

ulimit_tune(){
    local config_file
    config_file=$(write_sysctl_config "ulimit")
    
    echo "1000000" > /proc/sys/fs/file-max
    sed -i '/fs.file-max/d' "$config_file"
    cat >> "$config_file" << EOF
fs.file-max=1000000
EOF

    ulimit -SHn 1000000 && ulimit -c unlimited
    echo "root     soft   nofile    1000000
root     hard   nofile    1000000
root     soft   nproc     1000000
root     hard   nproc     1000000
root     soft   core      1000000
root     hard   core      1000000
root     hard   memlock   unlimited
root     soft   memlock   unlimited

*     soft   nofile    1000000
*     hard   nofile    1000000
*     soft   nproc     1000000
*     hard   nproc     1000000
*     soft   core      1000000
*     hard   core      1000000
*     hard   memlock   unlimited
*     soft   memlock   unlimited
">/etc/security/limits.conf
    if grep -q "ulimit" /etc/profile; then
      :
    else
      sed -i '/ulimit -SHn/d' /etc/profile
      echo "ulimit -SHn 1000000" >>/etc/profile
    fi
    if grep -q "pam_limits.so" /etc/pam.d/common-session; then
      :
    else
      sed -i '/required pam_limits.so/d' /etc/pam.d/common-session
      echo "session required pam_limits.so" >>/etc/pam.d/common-session
    fi

    sed -i '/DefaultTimeoutStartSec/d' /etc/systemd/system.conf
    sed -i '/DefaultTimeoutStopSec/d' /etc/systemd/system.conf
    sed -i '/DefaultRestartSec/d' /etc/systemd/system.conf
    sed -i '/DefaultLimitCORE/d' /etc/systemd/system.conf
    sed -i '/DefaultLimitNOFILE/d' /etc/systemd/system.conf
    sed -i '/DefaultLimitNPROC/d' /etc/systemd/system.conf

    cat >>'/etc/systemd/system.conf' <<EOF
[Manager]
#DefaultTimeoutStartSec=90s
DefaultTimeoutStopSec=30s
#DefaultRestartSec=100ms
DefaultLimitCORE=infinity
DefaultLimitNOFILE=65535
DefaultLimitNPROC=65535
EOF

    systemctl daemon-reload
}

bbr(){

    if uname -r|grep -q "^5."
    then
        echo "已经是 5.x 内核，不需要更新"
    else
        wget -N "http://sh.nekoneko.cloud/bbr/bbr.sh" -O bbr.sh && bash bbr.sh
    fi
    
}

Update_Shell(){
  wget -N "https://raw.githubusercontent.com/Seameee/bbr-script/refs/heads/master/tools.sh" -O tools.sh && chmod +x tools.sh && ./tools.sh
}

get_opsy() {
  [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
  [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
  [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}
virt_check() {
  # if hash ifconfig 2>/dev/null; then
  # eth=$(ifconfig)
  # fi

  virtualx=$(dmesg) 2>/dev/null

  if [[ $(which dmidecode) ]]; then
    sys_manu=$(dmidecode -s system-manufacturer) 2>/dev/null
    sys_product=$(dmidecode -s system-product-name) 2>/dev/null
    sys_ver=$(dmidecode -s system-version) 2>/dev/null
  else
    sys_manu=""
    sys_product=""
    sys_ver=""
  fi

  if grep docker /proc/1/cgroup -qa; then
    virtual="Docker"
  elif grep lxc /proc/1/cgroup -qa; then
    virtual="Lxc"
  elif grep -qa container=lxc /proc/1/environ; then
    virtual="Lxc"
  elif [[ -f /proc/user_beancounters ]]; then
    virtual="OpenVZ"
  elif [[ "$virtualx" == *kvm-clock* ]]; then
    virtual="KVM"
  elif [[ "$cname" == *KVM* ]]; then
    virtual="KVM"
  elif [[ "$cname" == *QEMU* ]]; then
    virtual="KVM"
  elif [[ "$virtualx" == *"VMware Virtual Platform"* ]]; then
    virtual="VMware"
  elif [[ "$virtualx" == *"Parallels Software International"* ]]; then
    virtual="Parallels"
  elif [[ "$virtualx" == *VirtualBox* ]]; then
    virtual="VirtualBox"
  elif [[ -e /proc/xen ]]; then
    virtual="Xen"
  elif [[ "$sys_manu" == *"Microsoft Corporation"* ]]; then
    if [[ "$sys_product" == *"Virtual Machine"* ]]; then
      if [[ "$sys_ver" == *"7.0"* || "$sys_ver" == *"Hyper-V" ]]; then
        virtual="Hyper-V"
      else
        virtual="Microsoft Virtual Machine"
      fi
    fi
  else
    virtual="Dedicated母鸡"
  fi
}
get_system_info() {
  cname=$(awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \\t]*//;s/[ \\t]*$//')
  #cores=$(awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo)
  #freq=$(awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \\t]*//;s/[ \\t]*$//')
  #corescache=$(awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \\t]*//;s/[ \\t]*$//')
  #tram=$(free -m | awk '/Mem/ {print $2}')
  #uram=$(free -m | awk '/Mem/ {print $3}')
  #bram=$(free -m | awk '/Mem/ {print $6}')
  #swap=$(free -m | awk '/Swap/ {print $2}')
  #uswap=$(free -m | awk '/Swap/ {print $3}')
  #up=$(awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days %d hour %d min\n",a,b,c)}' /proc/uptime)
  #load=$(w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \\t]*//;s/[ \\t]*$//')
  opsy=$(get_opsy)
  arch=$(uname -m)
  #lbit=$(getconf LONG_BIT)
  kern=$(uname -r)
  # disk_size1=$( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|overlay|shm|udev|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $2}' )
  # disk_size2=$( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|overlay|shm|udev|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $3}' )
  # disk_total_size=$( calc_disk ${disk_size1[@]} )
  # disk_used_size=$( calc_disk ${disk_size2[@]} )
  #tcpctrl=$(sysctl net.ipv4.tcp_congestion_control | awk -F ' ' '{print $3}')
  virt_check
}

# 检测系统内存大小（字节）
detect_memory() {
    local mem_bytes
    mem_bytes=$(free --bytes | awk '/Mem:/ {print $2}')
    echo "$mem_bytes"
}

# 根据内存大小确定优化级别
get_optimization_level() {
    local mem_bytes=$1
    local mem_gb=$((mem_bytes / 1024 / 1024 / 1024))
    
    if [[ $mem_gb -ge 4 ]]; then
        echo "aggressive"  # 激进优化 ≥4GB
    elif [[ $mem_gb -ge 1 ]]; then
        echo "balanced"    # 平衡优化 1-4GB
    else
        echo "conservative" # 保守优化 <1GB
    fi
}

# 全面系统优化（智能分级）
comprehensive_tune() {
    local config_file
    config_file=$(write_sysctl_config "comprehensive")
    
    printf "%s 开始全面系统优化...\n" "${Info}"
    
    # 检测内存和优化级别
    local mem_bytes
    mem_bytes=$(detect_memory)
    local optimization_level
    optimization_level=$(get_optimization_level "$mem_bytes")
    local mem_gb=$((mem_bytes / 1024 / 1024 / 1024))
    
    printf "%s 检测到系统内存: %d GB，使用 %s 优化级别\n" "${Info}" "$mem_gb" "$optimization_level"
    
    # 安装和配置随机数生成器（参考 optimize.sh）
    printf "%s 优化随机数生成器...\n" "${Info}"
    if [[ -z "$(command -v haveged)" ]]; then
        printf "%s 安装 haveged 改善随机数生成器性能\n" "${Info}"
        apt install haveged -y > /dev/null 2>&1 && systemctl enable haveged > /dev/null 2>&1
    fi
    if [[ -z "$(command -v rngd)" ]]; then
        printf "%s 安装 rng-tools 改善随机数生成器性能\n" "${Info}"
        apt install rng-tools -y > /dev/null 2>&1 && systemctl enable rng-tools > /dev/null 2>&1
    fi
    
    # 禁用 KSM（参考 optimize.sh）
    printf "%s 禁用 KSM 调优...\n" "${Info}"
    if [[ ! -z "$(command -v ksmtuned)" ]]; then
        echo 2 > /sys/kernel/mm/ksm/run 2>/dev/null || true
        apt purge tuned --autoremove -y > /dev/null 2>&1 || true
        apt purge ksmtuned --autoremove -y > /dev/null 2>&1 || true
        rm -rf /etc/systemd/system/ksmtuned.service 2>/dev/null || true
        mv /usr/sbin/ksmtuned /usr/sbin/ksmtuned.bak 2>/dev/null || true
        touch /usr/sbin/ksmtuned 2>/dev/null || true
        echo "# KSMTUNED DISABLED" > /usr/sbin/ksmtuned 2>/dev/null || true
    fi
    
    # 禁用透明大页面（参考 optimize.sh）
    printf "%s 禁用透明大页面...\n" "${Info}"
    cat > /etc/systemd/system/disable-transparent-huge-pages.service << EOF
[Unit]
Description=Disable Transparent Huge Pages (THP)
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=mongod.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null'
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/defrag > /dev/null'
[Install]
WantedBy=basic.target
EOF
    
    systemctl daemon-reload > /dev/null 2>&1
    systemctl start disable-transparent-huge-pages > /dev/null 2>&1
    systemctl enable disable-transparent-huge-pages > /dev/null 2>&1
    
    # 删除现有 sysctl 配置
    sed -i '/# 全面系统优化配置/d' "$config_file" 2>/dev/null || true
    sed -i '/net.core.netdev_max_backlog/d' "$config_file" 2>/dev/null || true
    sed -i '/net.core.somaxconn/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.conf.all.rp_filter/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.conf.default.rp_filter/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.ip_default_ttl/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_abort_on_overflow/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_adv_win_scale/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_autocorking/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_base_mss/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_collapse_max_bytes/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_dsack/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_fastopen/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_fastopen_blackhole_timeout_sec/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_fin_timeout/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_keepalive_intvl/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_keepalive_probes/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_keepalive_time/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_max_orphans/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_max_tw_buckets/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_no_ssthresh_metrics_save/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_slow_start_after_idle/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_orphan_retries/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_retries1/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_retries2/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_rfc1337/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_shrink_window/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_syn_retries/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_synack_retries/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_syncookies/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_timestamps/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_tw_reuse/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_notsent_lowat/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_low_latency/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv6.conf.all.forwarding/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv6.conf.default.forwarding/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_generic_timeout/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_gre_timeout/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_gre_timeout_stream/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_icmp_timeout/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_icmpv6_timeout/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_max/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_close/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_close_wait/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_established/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_fin_wait/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_last_ack/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_max_retrans/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_syn_recv/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_syn_sent/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_time_wait/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_tcp_timeout_unacknowledged/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_udp_timeout/d' "$config_file" 2>/dev/null || true
    sed -i '/net.netfilter.nf_conntrack_udp_timeout_stream/d' "$config_file" 2>/dev/null || true
    sed -i '/vm.overcommit_memory/d' "$config_file" 2>/dev/null || true
    sed -i '/vm.swappiness/d' "$config_file" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_mem/d' "$config_file" 2>/dev/null || true
    
    # 根据优化级别设置参数
    local rmem_max wmem_max conntrack_max
    case "$optimization_level" in
        "aggressive")
            rmem_max=536870912    # 512MB
            wmem_max=536870912    # 512MB
            conntrack_max=1048576 # 100万连接
            ;;
        "balanced")
            rmem_max=268435456    # 256MB
            wmem_max=268435456    # 256MB
            conntrack_max=524288  # 50万连接
            ;;
        "conservative")
            rmem_max=134217728    # 128MB
            wmem_max=134217728    # 128MB
            conntrack_max=209715  # 20万连接
            ;;
    esac
    
    # 计算 TCP 内存参数（基于系统内存）
    local page_size
    page_size=$(getconf PAGESIZE)
    local pages=$((mem_bytes / page_size))
    local tcp_mem_min=$((pages / 100 * 12))
    local tcp_mem_default=$((pages / 100 * 50))
    local tcp_mem_max=$((pages / 100 * 70))
    
    # 写入新配置
    cat >> "$config_file" << EOF
# 全面系统优化配置
# 优化级别: $optimization_level (内存: ${mem_gb}GB)
kernel.panic = 1
kernel.task_delayacct = 1
net.core.netdev_max_backlog = 32768
net.core.default_qdisc = fq
net.core.somaxconn = 32768
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.ip_default_ttl = 128
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_abort_on_overflow = 0
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_autocorking = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_collapse_max_bytes = 6291456
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 1027
net.ipv4.tcp_fastopen_blackhole_timeout_sec = 10
net.ipv4.tcp_fin_timeout = 3
net.ipv4.tcp_frto = 1
net.ipv4.tcp_keepalive_intvl = 2
net.ipv4.tcp_keepalive_probes = 2
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_max_orphans = 8192
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 4096
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_ssthresh_metrics_save = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_orphan_retries = 4
net.ipv4.tcp_retries1 = 2
net.ipv4.tcp_retries2 = 2
net.ipv4.tcp_rfc1337 = 1
net.core.rmem_default = 262144
net.core.rmem_max = $rmem_max
net.ipv4.tcp_rmem = 8192 262144 $rmem_max
net.core.wmem_default = 16384
net.core.wmem_max = $wmem_max
net.ipv4.tcp_wmem = 4096 16384 $wmem_max
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_no_metrics_save = 0
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_low_latency = 1
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 4096
net.ipv4.route.flush = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.netfilter.nf_conntrack_generic_timeout = 10
net.netfilter.nf_conntrack_gre_timeout = 5
net.netfilter.nf_conntrack_gre_timeout_stream = 30
net.netfilter.nf_conntrack_icmp_timeout = 5
net.netfilter.nf_conntrack_icmpv6_timeout = 5
net.netfilter.nf_conntrack_max = $conntrack_max
net.netfilter.nf_conntrack_tcp_timeout_close = 5
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 5
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 5
net.netfilter.nf_conntrack_tcp_timeout_max_retrans = 5
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 5
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 5
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_unacknowledged = 5
net.netfilter.nf_conntrack_udp_timeout = 5
net.netfilter.nf_conntrack_udp_timeout_stream = 60
vm.overcommit_memory = 1
vm.swappiness = 0
net.ipv4.tcp_mem = $tcp_mem_min $tcp_mem_default $tcp_mem_max
EOF
    
    # 加载内核模块
    printf "%s 加载内核模块...\n" "${Info}"
    echo "nf_conntrack" > /usr/lib/modules-load.d/sukka-network-optimized.conf 2>/dev/null || true
    echo "tls" >> /usr/lib/modules-load.d/sukka-network-optimized.conf 2>/dev/null || true
    
    # 应用配置
    sysctl -p "$config_file" > /dev/null 2>&1
    sysctl --system > /dev/null 2>&1
    
    # 调整 journald 配置（参考 optimize.sh）
    printf "%s 调整 journald 配置...\n" "${Info}"
    cat > /etc/systemd/journald.conf <<EOF
[Journal]
SystemMaxUse=384M
SystemMaxFileSize=128M
SystemMaxFiles=3
RuntimeMaxUse=256M
RuntimeMaxFileSize=128M
RuntimeMaxFiles=3
MaxRetentionSec=86400
MaxFileSec=259200
ForwardToSyslog=no
EOF
    
    # 重启 journald 服务
    systemctl restart systemd-journald > /dev/null 2>&1
    
    printf "%s 全面系统优化完成！优化级别: %s\n" "${Info}" "$optimization_level"
    printf "%s 已优化: 随机数生成器、KSM、大页面、网络参数、连接跟踪、内存管理、日志系统\n" "${Info}"
}

menu() {
  echo -e "\
${Green_font_prefix}0.${Font_color_suffix} 升级脚本
${Green_font_prefix}1.${Font_color_suffix} 安装BBR原版内核(已经是5.x的不需要)
${Green_font_prefix}2.${Font_color_suffix} TCP窗口调优
${Green_font_prefix}3.${Font_color_suffix} 开启内核转发
${Green_font_prefix}4.${Font_color_suffix} 系统资源限制调优
${Green_font_prefix}5.${Font_color_suffix} 屏蔽ICMP ${Green_font_prefix}6.${Font_color_suffix} 开放ICMP
${Green_font_prefix}7.${Font_color_suffix} 全面系统优化(基于内存智能分级)
"

get_system_info
echo -e "当前系统信息: ${Font_color_suffix}$opsy ${Green_font_prefix}$virtual${Font_color_suffix} $arch ${Green_font_prefix}$kern${Font_color_suffix}
"

  read -p "请输入数字: " num
  case "$num" in
  0)
    Update_Shell
    ;;
  1)
    bbr
    ;;
  2)
    tcp_tune
    ;;
  3)
    enable_forwarding
    ;;
  4)
    ulimit_tune
    ;;
  5)
    banping
    ;;
  6)
    unbanping
    ;;
  7)
    comprehensive_tune
    ;;
  *)
  clear
    echo -e "${Error}:请输入正确数字 [0-99]"
    sleep 5s
    start_menu
    ;;
  esac
}

copyright

menu
