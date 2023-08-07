#!/usr/bin/env bash

#######################################################################################################
#
# Zack's - Debian Initial Customization script
# Version: 1.0
#
# This script will automate initial customization of Debian minimal installation.
# Supported Debian versions >= 11 (codename Bullseye)
#
# © 2023 Zack's. All rights reserved.
#
#######################################################################################################

################
## INITIALIZE ##
################

function initialize ()
{

	# Misc items
	declare -gr SPACER='----------------------------------------------------------------------------------------------------'
	declare -gr E=$'\e[1;31;103m'			# (E) Error: highlighted text.
	declare -gr W=$'\e[1;31;103m'			# (W) Warning: highlighted text.
	declare -gr B=$'\e[1m'				# B for Bold.
	declare -gr R=$'\e[0m'				# R for Reset.

	# Display a warning.
	clear

	# Show a warning.
	cat <<-END

		${SPACER}

		    ${B}** IMPORTANT **${R}

		    This script will automate initial customization of Debian minimal installations. Please refer to
		    https://zacks.eu/debian-server-initial-customization/ and
		    https://github.com/zjagust/debian-server-initial-customization/
		    for more information.

		    !! SCRIPT WILL REBOOT YOR SERVER UPON COMPLETION !!

		${SPACER}

	END

	# Ask for confirmation.
	local ANSWER
	read -rp "Type ${B}Y${R} to proceed, or anything else to cancel, and press Enter: ${B}" ANSWER
	echo "${R}"

	# Terminate if required.
	if [[ "${ANSWER,}" != 'y' ]]
	then
		echo
		echo 'Terminated. Nothing done.'
		echo
		exit 1
	fi

	# Check if user is root
	if [[ "$(whoami)" != "root" ]]
	then
		echo
		echo "${E}Script must be run as root user! Execution will abort now, please run script again as root user.${R}"
		echo
		exit 1
	fi

} # initialize end

##########################
## DEBIAN VERSION CHECK ##
##########################

function debianVersion ()
{
	
	# Get release codename and version
	OS_CODENAME=$(grep VERSION_CODENAME /etc/os-release | awk -F '=' '{print $2}')
	OS_VERSION=$(grep VERSION_ID /etc/os-release | awk -F '=' '{print $2}' | tr -d '"')

	# Do a version check
	if [[ "$OS_VERSION" -lt "11" ]]
	then
	    echo
		echo "${W}This script can only run on Debian version 11 (codename bullseye) or greater.${R}"
		echo "${E}Your Debian version is lower than that, thus script will abort now.${R}"
		echo
		exit 1
	fi

}
#############################
## INITIALIZE PRESEED FILE ##
#############################

function preseedInitialize ()
{

	# Initialize debian.preseed
	cd "$(dirname -- "$0")" || exit
	debconf-set-selections preseed/debian-initial-customization.preseed

} # preseedInitialize end

##########################
## SET SOFTWARE SOURCES ##
##########################

function setSources ()
{
	# Purge default sources.list
	echo -n > /etc/apt/sources.list

	# Set sources.list per Debian version
	if [[ "$OS_VERSION" -ge "12" ]]
	then
		echo -e "# Main Repos
deb http://deb.debian.org/debian $OS_CODENAME main contrib non-free-firmware
deb http://deb.debian.org/debian-security/ $OS_CODENAME-security main contrib non-free-firmware
deb http://deb.debian.org/debian $OS_CODENAME-updates main contrib non-free-firmware
# Sources - enable only when needed
#deb-src http://deb.debian.org/debian $OS_CODENAME main
#deb-src http://deb.debian.org/debian-security/ $OS_CODENAME-security main
#deb-src http://deb.debian.org/debian $OS_CODENAME-updates main
# Backports - For software like Git, Redis, etc.
deb http://deb.debian.org/debian $OS_CODENAME-backports main contrib non-free-firmware" > /etc/apt/sources.list
	else
		echo -e "# Main Repos
deb http://deb.debian.org/debian $OS_CODENAME main contrib non-free
deb http://deb.debian.org/debian-security/ $OS_CODENAME-security main contrib non-free
deb http://deb.debian.org/debian $OS_CODENAME-updates main contrib non-free
# Sources - enable only when needed
#deb-src http://deb.debian.org/debian $OS_CODENAME main
#deb-src http://deb.debian.org/debian-security/ $OS_CODENAME-security main
#deb-src http://deb.debian.org/debian $OS_CODENAME-updates main
# Backports - For software like Git, Redis, etc.
deb http://deb.debian.org/debian $OS_CODENAME-backports main contrib non-free" > /etc/apt/sources.list
	fi

	# Update repositories
	apt update

} # setSources end

########################
## GRUB MODIFICATIONS ##
########################

function modifyGrub ()
{

	# Set boot verbosity
	sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT=""/g' /etc/default/grub
	# Enforce legacy interfaces names
	sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/g' /etc/default/grub
	# Update GRUB
	update-grub

} # modifyGrub end

##########################
## NET INTERFACES NAMES ##
##########################

function interfacesName ()
{

	# Get current interface name
	INTERFACE_CURRENT=$(ip a | grep "2: " | awk '{print $2;}' | cut -d: -f1)
	# Set interface name
	sed -i "s/$INTERFACE_CURRENT/eth0/" /etc/network/interfaces

} # interfacesName end

#########################
## DEBCONF MIN DETAILS ##
#########################

function debconfMinimal ()
{

	# Reconfigure debconf - minimal details
	echo -e "debconf debconf/frontend select Noninteractive\ndebconf debconf/priority select critical" | debconf-set-selections

} # debconfMinimal end

#########################
## ADDITIONAL SOFTWARE ##
#########################

function sysdigRepo ()
{

	# Install required software for repo setup
	apt install -y --no-install-recommends curl gnupg2 ca-certificates
	# Set Sysdig repo key
	curl -s https://download.sysdig.com/DRAIOS-GPG-KEY.public | apt-key add -
	# Define Sysdig repo source file
	curl -o /etc/apt/sources.list.d/draios.list https://download.sysdig.com/stable/deb/draios.list
	# Update APT
	apt update

} # sysdigRepo end

#################################
## INSTALL APTITUDE AND UPDATE ##
#################################

function installAptitude ()
{

	# Install Aptitude
	apt install --no-install-recommends -y aptitude apt-transport-https
	# Update repos with Aptitude
	aptitude update -q2
	# Forget new packages
	aptitude forget-new
	# Perform full system upgrade
	aptitude full-upgrade --purge-unused -y

} # installAptitude end

###############################
## STANDARD SOFTWARE INSTALL ##
###############################

function standardSoftware ()
{

	# Install standard software packages
	aptitude install -R -y busybox_ bash-completion bind9-host busybox-static dnsutils dosfstools \
	friendly-recovery ftp fuse geoip-database groff-base hdparm info install-info iputils-tracepath \
	lshw lsof ltrace man-db manpages mlocate mtr-tiny parted powermgmt-base psmisc rsync sgml-base strace \
	tcpdump telnet time uuid-runtime xml-core iptables resolvconf lsb-release openssh-server

	# Force resolvconf to update all its subscribers
	resolvconf -u
	sleep 5

} # standardSoftware end

###############################
## DEVELOPMENT TOOLS INSTALL ##
###############################

function develSoftware ()
{

	# Install development tools
	aptitude install -R -y linux-headers-amd64 build-essential

} # develSoftware end

#################################
## ADDITIONAL SOFTWARE INSTALL ##
#################################

function additionalSoftware ()
{

	# Install additiona software
	aptitude install -R -y safecat sharutils lynx zip unzip lrzip pbzip2 p7zip p7zip-full rar pigz unrar acpid \
	zstd inotify-tools sysfsutils dstat htop lsscsi iotop itop nmap ifstat iftop tcptrack whois atop netcat \
	sysstat gpm localepurge mc screen vim ethtool apt-file sysdig net-tools sudo wget bsd-mailx dma pwgen
	# Update apt-file
	apt-file update
	# Turn off screen startup message
	sed -i 's/^#startup_message/startup_message/g' /etc/screenrc

} # additionalSoftware end

######################
## SET VIM FOR ROOT ##
######################

function vimRoot ()
{

	# Configure Vim for root user
	mkdir -p /root/.vim/saves
	cat <<-EOF > /root/.vimrc
set tabstop=4
set softtabstop=4
set expandtab
set shiftwidth=4
set backupdir=~/.vim/saves/
set mousemodel=popup
	EOF

} # vimRoot end

#######################
## SET CUSTOM BASHRC ##
#######################

function setBashrc ()
{

	# Backup distribution .bashrc
	if [ -f "/root/.bashrc" ]
	then
		cp /root/.bashrc /root/.bachrc.dist
	else
		echo "No default .bashrc found, no backup required."
	fi
	# Set custom bashrc env file
	cd "$(dirname -- "$0")" || exit
	cp environment/.bashrc /root/.
	
} # bashrcCleanup end

#######################
## LOCAL ROOT ACCESS ##
#######################

function rootSSH ()
{
	# Generate root SSH keys
	ssh-keygen -b 4096 -t rsa -f /root/.ssh/id_rsa -q -N ""

	# Generate auth keys file for root
	touch /root/.ssh/authorized_keys
	chmod 0600 /root/.ssh/authorized_keys

	# Add root's pub key to auth files
	echo -e "from=\"127.0.0.1\" $(cat /root/.ssh/id_rsa.pub)\n" >> /root/.ssh/authorized_keys

} # rootSSH end

########################
## REMOTE USER ACCESS ##
########################

function remoteSSH ()
{

	cat <<-END
        
		${SPACER}

		    THIS IS A MANDATORY STEP, YOU NEED TO HAVE A PUBLIC KEY READY AS PASSWORD LOGIN WILL
		    BE DISABLED. INSTRUCTIONS ON HOW TO INSERT KEY TO SERVER WILL BE GIVEN IN NEXT STEP.

		${SPACER}

	END

	# Ask for confirmation.
	local ANSWER
	read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
	echo "${R}"

	# Allow access with password temporarily
	sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
	sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config

	# Restart SSH
	systemctl restart ssh 

	# Set default machine IP
	MACHINE_IP=$(ip route get "$(ip route show 0.0.0.0/0 | grep -oP 'via \K\S+')" | grep -oP 'src \K\S+')

	# Request user public key - external
	echo -e "On Windows (OpenSSH client must be enabled!), open ${B}Windows PowerShell${R} and please execute the following: "
	echo -e "${B}type C:\Users\\\$Env:USERNAME\.ssh\id_rsa.pub | ssh root@$MACHINE_IP -T \"cat >> /root/.ssh/authorized_keys\"${R}"
	echo
	echo -e "On Linux, open ${B}Terminal${R} and please execute the following: "
	echo -e "${B}cat /home/\$(whoami)/.ssh/id_rsa.pub | ssh root@$MACHINE_IP -T \"cat >> /root/.ssh/authorized_keys\"${R}"
	echo

	# Complete pub key insert
	local ANSWER
	read -rp "Once keys are inserted, type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
	echo "${R}"

	# Set a proper line endings - just in case
	sed -i 's/\r$//' /root/.ssh/authorized_keys

} # remoteSSH end

#######################
## SECURE SSH ACCESS ##
#######################

function secureSSH ()
{

	# Secure SSH access
	sed -i 's/^PermitRootLogin yes/PermitRootLogin without-password/g' /etc/ssh/sshd_config
	sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config

	# Restart SSH
	systemctl restart ssh

} # secureSSH end

#################################
## LOCAL RESOLVE - NTP SERVERS ##
#################################

function resolveNTP ()
{

	# Add a comment
	echo -e "\n# Debian NTP Pool Servers" >> /etc/hosts

	# Set NTP variables
	POOL_NTP_0=$(dig +short 0.pool.ntp.org | head -n1)
	POOL_NTP_1=$(dig +short 1.pool.ntp.org | head -n1)
	POOL_NTP_2=$(dig +short 2.pool.ntp.org | head -n1)
	POOL_NTP_3=$(dig +short 3.pool.ntp.org | head -n1)
	
	# Gather NTP IPs and add records to /etc/hosts
	{

		echo -e "$POOL_NTP_0 0.debian.pool.ntp.org"
		echo -e "$POOL_NTP_1 1.debian.pool.ntp.org"
		echo -e "$POOL_NTP_2 2.debian.pool.ntp.org"
		echo -e "$POOL_NTP_3 3.debian.pool.ntp.org"
	
	} >> /etc/hosts

} # resolveNTP end

###################################
## FIREWALL - SET DEFAULT CHAINS ##
###################################

function fwDefaultChains ()
{

	# Flush default iptables chains
	iptables -F INPUT
	iptables -F FORWARD
	iptables -F OUTPUT

	# Create default chains
	iptables -N GENERAL-ALLOW
	iptables -N REJECT-ALL

	# INPUT chain jump
	iptables -I INPUT -m comment --comment "No rules of any kind below this rule" -j GENERAL-ALLOW
	iptables -A INPUT -j REJECT-ALL


} # fwDefaultChains end

####################################
## FIREWALL - DEFAULT BASIC RULES ##
####################################

function fwBasicRules ()
{

	# Established connections
	iptables -I GENERAL-ALLOW -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "Established Connections" -j ACCEPT

	# Allow SSH connections
	iptables -A GENERAL-ALLOW -p tcp -m tcp --dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "SSH Access" -j ACCEPT

	# Allow DNS (Google Servers)
	iptables -A GENERAL-ALLOW -s 8.8.4.4/32 -p udp -m udp --sport 53 -m comment --comment "Google DNS UDP" -j ACCEPT
	iptables -A GENERAL-ALLOW -s 8.8.4.4/32 -p tcp -m tcp --sport 53 -m comment --comment "Google DNS TCP" -j ACCEPT
	iptables -A GENERAL-ALLOW -s 8.8.8.8/32 -p udp -m udp --sport 53 -m comment --comment "Google DNS UDP" -j ACCEPT
	iptables -A GENERAL-ALLOW -s 8.8.8.8/32 -p tcp -m tcp --sport 53 -m comment --comment "Google DNS TCP" -j ACCEPT

	# Allow NTP
	iptables -A GENERAL-ALLOW -s $POOL_NTP_0/32 -p udp -m udp --sport 123 -m comment --comment "NTP Pool Servers" -j ACCEPT
	iptables -A GENERAL-ALLOW -s $POOL_NTP_1/32 -p udp -m udp --sport 123 -m comment --comment "NTP Pool Servers" -j ACCEPT
	iptables -A GENERAL-ALLOW -s $POOL_NTP_2/32 -p udp -m udp --sport 123 -m comment --comment "NTP Pool Servers" -j ACCEPT
	iptables -A GENERAL-ALLOW -s $POOL_NTP_3/32 -p udp -m udp --sport 123 -m comment --comment "NTP Pool Servers" -j ACCEPT

	# Allow ping and loopback communication
	iptables -A GENERAL-ALLOW -p icmp -j ACCEPT
	iptables -A GENERAL-ALLOW -i lo -j ACCEPT

	# Reject everything else
	iptables -A REJECT-ALL -p tcp -j REJECT --reject-with tcp-reset
	iptables -A REJECT-ALL -p udp -j REJECT --reject-with icmp-port-unreachable
	iptables -A REJECT-ALL -p icmp -j DROP

	# Install iptables-persistent and save rules
	aptitude install -R -y iptables-persistent

} # fwBasicRules end

#########################
## GENERAL CHANGES LOG ##
#########################

function changesLog ()
{

	# Set asset log
	cd "$(dirname -- "$0")" || exit
	cp motd/20-changes-log /etc/update-motd.d/.
	chmod 0755 /etc/update-motd.d/20-changes-log

} # changesLog end

function workDir ()
{

	# Create root work directory
	mkdir /root/.work

} # workDir end

function cleanupReboot ()
{

	# Clean APT cache
	apt autoremove -y
	aptitude clean
	aptitude autoclean
	# Reset debconf to full details
	echo -e "debconf debconf/frontend select Dialog\ndebconf debconf/priority select low" | debconf-set-selections
	# Reboot the machines
	shutdown -r now

} # cleanupReboot end

initialize
debianVersion
preseedInitialize
setSources
modifyGrub
interfacesName
debconfMinimal
sysdigRepo
installAptitude
standardSoftware
develSoftware
additionalSoftware
vimRoot
setBashrc
rootSSH
remoteSSH
secureSSH
resolveNTP
fwDefaultChains
fwBasicRules
changesLog
workDir
cleanupReboot
