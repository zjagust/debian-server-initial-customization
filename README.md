# Initial Customization for Debian Server minimal installations

This script will automatize the initial customization of Debian Server minimal Installations. For more details, please consult the following articles:

- [Home/Small Office – Debian Server](https://zacks.eu/home-small-office-debian-server/)
- [Home/Small Office – Debian Server Initial Customization](https://zacks.eu/debian-server-initial-customization/)

# Usage

This scritp is intended to run on minimal installations of the Debian server systems. Usually those systems are as bare as they can be, and since **git** is a requirement to even get this script, it will need to be installed first. You can install it following the steps below:

01) Set the variable which will extract the correct *codename* of your Debian server:

```bash
OS_CODENAME=$(grep VERSION_CODENAME /etc/os-release | awk -F '=' '{print $2}')
```

02) Add the main repository source to */etc/apt/sources.list* file:

```bash
echo -e "deb http://deb.debian.org/debian $OS_CODENAME main" > /etc/apt/sources.list
```

03) Update APT and install git:

```bash
apt update
apt install -y --no-install-recommends git ca-certificates
```

## Script Installation

You can clone this repository anywhere on VPS, i.e.:

```bash
cd /tmp && git clone https://github.com/zjagust/debian-server-initial-customization.git
```

Once repository is cloned, execute the following commands:

```bash
cd /tmp/debian-server-initial-customization
. debian-server-initial-customization.sh
```

Let the script do its work!