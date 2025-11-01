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
        echo -e "${Info} 检测到Debian 13系统，将配置写入 ${config_file}"
    else
        config_file="/etc/sysctl.conf"
        echo -e "${Info} 检测到非Debian 13系统，将配置写入 ${config_file}"
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
    
    # 删除现有配置
    sed -i '/net.ipv4.tcp_no_metrics_save/d' "$config_file"
    sed -i '/net.ipv4.tcp_ecn/d' "$config_file"
    sed -i '/net.ipv4.tcp_frto/d' "$config_file"
    sed -i '/net.ipv4.tcp_mtu_probing/d' "$config_file"
    sed -i '/net.ipv4.tcp_rfc1337/d' "$config_file"
    sed -i '/net.ipv4.tcp_sack/d' "$config_file"
    sed -i '/net.ipv4.tcp_fack/d' "$config_file"
    sed -i '/net.ipv4.tcp_window_scaling/d' "$config_file"
    sed -i '/net.ipv4.tcp_adv_win_scale/d' "$config_file"
    sed -i '/net.ipv4.tcp_moderate_rcvbuf/d' "$config_file"
    sed -i '/net.ipv4.tcp_rmem/d' "$config_file"
    sed -i '/net.ipv4.tcp_wmem/d' "$config_file"
    sed -i '/net.core.rmem_max/d' "$config_file"
    sed -i '/net.core.wmem_max/d' "$config_file"
    sed -i '/net.ipv4.udp_rmem_min/d' "$config_file"
    sed -i '/net.ipv4.udp_wmem_min/d' "$config_file"
    sed -i '/net.core.default_qdisc/d' "$config_file"
    sed -i '/net.ipv4.tcp_congestion_control/d' "$config_file"
    
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
    
    echo -e "${Info} TCP优化配置已写入 ${config_file}"
    sysctl -p "$config_file" && sysctl --system
}

enable_forwarding(){ #开启内核转发
    local config_file
    config_file=$(write_sysctl_config "forwarding")
    
    # 删除现有配置
    sed -i '/net.ipv4.conf.all.route_localnet/d' "$config_file"
    sed -i '/net.ipv4.ip_forward/d' "$config_file"
    sed -i '/net.ipv4.conf.all.forwarding/d' "$config_file"
    sed -i '/net.ipv4.conf.default.forwarding/d' "$config_file"
    
    # 写入新配置
    cat >> "$config_file" << EOF
# 内核转发配置
net.ipv4.conf.all.route_localnet=1
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
EOF
    
    echo -e "${Info} 内核转发配置已写入 ${config_file}"
    sysctl -p "$config_file" && sysctl --system
}

banping(){
    local config_file
    config_file=$(write_sysctl_config "banping")
    
    # 删除现有配置
    sed -i '/net.ipv4.icmp_echo_ignore_all/d' "$config_file"
    sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' "$config_file"
    
    # 写入新配置
    cat >> "$config_file" << EOF
# 禁止ping配置
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
EOF
    
    echo -e "${Info} 禁止ping配置已写入 ${config_file}"
    sysctl -p "$config_file" && sysctl --system
}

unbanping(){
    local config_file
    config_file=$(write_sysctl_config "banping")
    
    # 删除禁止ping配置
    sed -i '/net.ipv4.icmp_echo_ignore_all/d' "$config_file"
    sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' "$config_file"
    
    # 写入允许ping配置
    cat >> "$config_file" << EOF
# 允许ping配置
net.ipv4.icmp_echo_ignore_all=0
net.ipv4.icmp_echo_ignore_broadcasts=0
EOF
    
    echo -e "${Info} 已解除禁止ping配置，配置写入 ${config_file}"
    sysctl -p "$config_file" && sysctl --system
}
