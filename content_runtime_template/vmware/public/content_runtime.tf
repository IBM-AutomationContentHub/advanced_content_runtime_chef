# Licensed Materials - Property of IBM
# 5737-E67
# @ Copyright IBM Corporation 2016, 2017 All Rights Reserved
# US Government Users Restricted Rights - Use, duplication or disclosure restricted by GSA ADP Schedule Contract with IBM Corp.

### Input Section

 variable "runtime_hostname" { type = "string" }
 variable "docker_registry_token" { type = "string" }
 variable "docker_registry" { type = "string" }
 variable "docker_registry_camc_pattern_manager_version" { type = "string" }
 variable "docker_registry_camc_sw_repo_version" { type = "string" }
 variable "chef_version" { type = "string" }
 variable "ibm_sw_repo_user" { type = "string" }
 variable "ibm_sw_repo_password" { type = "string" }
 variable "ibm_im_repo_user_hidden" { type = "string" }
 variable "ibm_im_repo_password_hidden" { type = "string" }
 variable "ibm_contenthub_git_access_token" { type = "string" }
 variable "ibm_contenthub_git_host" { type = "string" }
 variable "ibm_contenthub_git_organization" { type = "string" }
 variable "ibm_openhub_git_organization" { type = "string" }
 variable "chef_org" { type = "string" }
 variable "chef_admin" { type = "string" }
 variable "ibm_pm_access_token" { type = "string" }
 variable "ibm_pm_admin_token" { type = "string" }
 variable "network_visibility" { type = "string" }
 variable "ibm_pm_public_ssh_key_name" { type = "string" }
 variable "ibm_pm_private_ssh_key" { type = "string" }
 variable "ibm_pm_public_ssh_key" { type = "string" }
 variable "user_public_ssh_key" { type = "string" }
 variable "docker_ee_repo" { type = "string" }
 variable "template_timestamp_hidden" { type = "string" }
 variable "vsphere_datacenter" { type = "string" }
 variable "vsphere_cluster" { type = "string" }
 variable "vsphere_folder" { type = "string" }
 variable "vsphere_datastore" { type = "string" }
 variable "runtime_domain" { type = "string" }
 variable "cores" { type = "string" }
 variable "memory" { type = "string" }
 variable "nfs_mount" { type = "string" }
 variable "vsphere_dns" { type = "list" }
 variable "disk1_template" { type = "string" }
 variable "disk2_name" { type = "string" }
 variable "disk2_size" { type = "string" }
 variable "network_label" { type = "string" }
 variable "ipv4_address" { type = "string" }
 variable "ipv4_gateway" { type = "string" }
 variable "ipv4_prefix_length" { type = "string" }
 variable "vmware_image_ssh_user" { type = "string" }
 variable "vmware_image_ssh_password" { type = "string" }
 variable "vmware_image_ssh_private_key" { type = "string" }
 variable "prereq_strictness" { type = "string" }

### End Input Section

provider "vsphere" {
  allow_unverified_ssl = true
}

resource "vsphere_virtual_machine" "singlenode" {
  name = "${var.runtime_hostname}"
  vcpu = "${var.cores}"
  memory = "${var.memory}"
  domain = "${var.runtime_domain}"
  datacenter = "${var.vsphere_datacenter}"
  dns_servers = "${var.vsphere_dns}"
  cluster = "${var.vsphere_cluster}"


  network_interface {
    label = "${var.network_label}"
    ipv4_address = "${var.ipv4_address}"
    ipv4_gateway = "${var.ipv4_gateway}"
    ipv4_prefix_length = "${var.ipv4_prefix_length}"
  }

  disk {
    # template or vmdk
    template = "${var.disk1_template}"
    datastore="${var.vsphere_datastore}"
    # size = "${var.disk1_size}"
    # name = "${var.disk1_name}"
  }

  disk {
    size = "${var.disk2_size}"
    name = "${var.disk2_name}"
    datastore="${var.vsphere_datastore}"
  }

  # Set the ssh connection using the private generted ssh key
  connection {
    type = "ssh"
    user = "${var.vmware_image_ssh_user}"
    password = "${var.vmware_image_ssh_password}"
    private_key = "${ length(var.vmware_image_ssh_private_key) > 0 ? base64decode(var.vmware_image_ssh_private_key) : var.vmware_image_ssh_private_key}"
  }

  provisioner "remote-exec" {
    inline = [
        "mkdir -p ./advanced-content-runtime"
      ]
   }

provisioner "file" {
   content     = <<EndOfFile
#!/bin/bash
#
# Copyright : IBM Corporation 2016, 2017
#
######################################################################################
# Script to check the requirements necessary for an installation
# # Usage: ./prereq-check-install.sh MODE(strict/lenient) CHEF_VERSION_OR_URL PM_PUBLIC_KEY PM_PRIVATE_KEY DOCKER_EE_REPO
######################################################################################
RESULT=0

. `dirname $0`/utilities.sh

# Declare the default chef and docker compose versions for their installations
CHEF_VERSION=12.11.1
DOCKER_COMPOSE_VERSION=1.11.2

function wait_apt_lock()
{
    sleepC=5
    while [[ -f /var/lib/dpkg/lock  || -f /var/lib/apt/lists/lock ]]
    do
      sleep $sleepC
      echo "    Checking lock file /var/lib/dpkg/lock or /var/lib/apt/lists/lock"
      [[ `sudo lsof 2>/dev/null | egrep 'var.lib.dpkg.lock|var.lib.apt.lists.lock'` ]] || break
      let 'sleepC++'
      if [ "$sleepC" -gt "50" ] ; then
 	lockfile=`sudo lsof 2>/dev/null | egrep 'var.lib.dpkg.lock|var.lib.apt.lists.lock'|rev|cut -f1 -d' '|rev`
        echo "Lock $lockfile still exists, waited long enough, attempt apt-get. If failure occurs, you will need to cleanup $lockfile"
        continue
      fi
    done
}

# Identify the platform and version using Python
if command_exists python; then
  PLATFORM=`python -c "import platform;print(platform.platform())" | rev | cut -d '-' -f3 | rev | tr -d '".' | tr '[:upper:]' '[:lower:]'`
  PLATFORM_VERSION=`python -c "import platform;print(platform.platform())" | rev | cut -d '-' -f2 | rev`
else
  if command_exists python3; then
    PLATFORM=`python3 -c "import platform;print(platform.platform())" | rev | cut -d '-' -f3 | rev | tr -d '".' | tr '[:upper:]' '[:lower:]'`
    PLATFORM_VERSION=`python3 -c "import platform;print(platform.platform())" | rev | cut -d '-' -f2 | rev`
  fi
fi

# Check if the executing platform is supported
if [[ $PLATFORM == *"ubuntu"* ]] || [[ $PLATFORM == *"redhat"* ]] || [[ $PLATFORM == *"rhel"* ]] || [[ $PLATFORM == *"centos"* ]]; then
  echo "[*] Platform identified as: $PLATFORM $PLATFORM_VERSION"
else
  echo "[ERROR] Platform $PLATFORM not supported"
  exit 1
fi

# Change the string 'redhat' to 'rhel'
if [[ $PLATFORM == *"redhat"* ]]; then
  PLATFORM="rhel"
fi

# If executing from unsupported distro versions
MAIN_VERSION=`echo $PLATFORM_VERSION | cut -d '.' -f1`
if ([[ $PLATFORM == *"ubuntu"* ]] && [[ $MAIN_VERSION -lt "14" ]]) || [[ $MAIN_VERSION -lt "7" ]]; then
  echo "[ERROR] This OS version ($PLATFORM_VERSION) is not supported"
  exit 1
fi

echo "[*] Checking permissions"
sudo -n cat /etc/sudoers > /dev/null
if [ $? -ne "0" ]; then
  echo "[ERROR] This script requires root permissions with the NOPASSWD option enabled for executing"
  exit 1
fi

# Check for the cloud provider
CLOUD_PROVIDER=$(sudo dmidecode -s bios-version)

echo "[*] Checking internet connection"
OFFLINE="false"
if [[ `ping -c 3 -w 10 www.ibm.com | egrep "0 received,"` ]]; then
  OFFLINE="true"
  echo "[*] The virtual machine is not connected to the internet. Offline mode activated."
else
  OFFLINE="false"
fi

if [[ $OFFLINE == *"false"* ]]; then
  echo "[*] Updating packages"
  # Check if the script is being run as root
  if [[ $PLATFORM == *"ubuntu"* ]]; then
    wait_apt_lock 
    PACKAGE_MANAGER=apt-get
    sudo -n apt-get -qqy update
  else
    PACKAGE_MANAGER=yum
    sudo -n yum -y update
  fi

  if [ $? -ne "0" ]; then
    echo "[ERROR] This script requires $PACKAGE_MANAGER permissions for executing"
    exit 1
  fi
fi

# Check if there is at least 1GB of disk available
FREE_MEM=`df -k --output=avail "$PWD" | tail -n1`
if [ $FREE_MEM -lt 5242880 ]; then # 1GB = 1024 * 1024
  echo "[ERROR] This script requires at least 5GB of available disk space"
  exit 1
fi

# Check if strict mode is enabled, if it is, the program will not attempt to install requirements
MODE="lenient"
if [[ $1 == *"strict"* ]]; then
  MODE="strict"
  echo "[*] Strict mode enabled"
fi

# Get chef's URL from parameter
URL_REGEX='(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
if [ -n "$2" ]; then
  if [[ $2 =~ $URL_REGEX ]]; then
    echo "[*] Chef URL was provided: $2"
    CHEF_URL=$2
  else
    CHEF_VERSION=$2
    if [[ $PLATFORM == *"ubuntu"* ]]; then
    		CHEF_URL=https://packages.chef.io/files/stable/chef-server/$CHEF_VERSION/ubuntu/$PLATFORM_VERSION/chef-server-core_$CHEF_VERSION-1_amd64.deb
    else
      if [[ $PLATFORM == *"rhel"* ]] || [[ $PLATFORM == *"centos"* ]]; then
        CHEF_URL=https://packages.chef.io/files/stable/chef-server/$CHEF_VERSION/el/$MAIN_VERSION/chef-server-core-$CHEF_VERSION-1.el$MAIN_VERSION.x86_64.rpm
      fi
    fi
    echo "[*] Using chef installation URL: $CHEF_URL"
  fi
fi

# Verify the provided private ($4) and public ($3) keys match
PM_PUBLIC_KEY=`echo $3 | head -n1 | cut -d " " -f2`

echo $4 | base64 --decode > key.decoded
chmod 600 key.decoded
ssh-keygen -p -P '' -N '' -f key.decoded > /dev/null

if [ $? -gt 0 ]; then
 echo "[ERROR] The provided encoded private key contains a password. Pattern Manager requires the use of a passwordless private key."
 exit 1
fi

PM_PRIVATE_KEY=`ssh-keygen -y -f key.decoded | head -n1 | cut -d " " -f2`
if [[ $PM_PUBLIC_KEY == $PM_PRIVATE_KEY ]]; then
  echo "[*] The provided SSH keys for Pattern Manager were validated succesfully."
else
  echo "[ERROR] The provided SSH public and private keys for Pattern Manager do not match, please provide a matching pair of keys."
  exit 1;
fi
rm -rf key.decoded

# Verify the machine's hostname is in lower case
h=`hostname`
H=`hostname |tr '[:upper:]' '[:lower:]'`

if [[ "$h" =~ [A-Z] ]]; then
  echo "[*] Found an uppercase letter on the hostname"
  if [[ $MODE == *"lenient"* ]]; then
    sudo sed -i "s/$h/$H/g" /etc/hosts
    sudo sed -i "s/$h/$H/g" /etc/hostname
    sudo hostname `hostname | tr '[:upper:]' '[:lower:]'`
    echo "[*] Hostname was changed from $h to $H"
  else
    echo "[ERROR] The sever's hostname can not contain uppercase letters"
    exit 1
  fi
fi

# Get Docker EE repo URL
if ! command_exists docker; then
  if [ -n "$5" ]; then
    DOCKER_EE_REPO=$5
    echo "[*] Identified Docker EE repository: $5"
  else
    echo "[*] No Docker EE repository provided"
    if [[ $PLATFORM == *"rhel"* ]]; then
      echo "[ERROR] Docker CE for Red Hat Enterprise is not supported, please provide a valid Docker EE repository URL"
      exit 1
    fi
  fi
fi

# Check for the machine's IP Address
which ip > /dev/null
if [ $? -ne "0" ]; then
  if [[ $MODE == *"strict"* ]]; then
    echo "[ERROR] Failed obtaining the machine's IP address"
    exit 1
  else
    export PATH=$PATH:/usr/sbin
  fi
fi

# Check if a command is installed, if not, install it using rpm or apt-get
# Usage: check_command_and_install commandNameToCheck packageNameUbuntu packageNameRedHat
# Or: check_command_and_install commandNameToCheck installerFunction
function check_command_and_install() {
	command=$1
  string="[*] Checking installation of: $command"
  line="......................................................................."
  if command_exists $command; then
    printf "%s %s [INSTALLED]\n" "$string" "$${line:$${#string}}"
  else
    printf "%s %s [MISSING]\n" "$string" "$${line:$${#string}}"
    if [[ $MODE == *"lenient"* ]]; then # If not using strict mode, install the package
      if [ $# == 3 ]; then # If the package name is provided
        if [[ $PLATFORM == *"ubuntu"* ]]; then
          sudo $PACKAGE_MANAGER install -y $2
        else
          sudo $PACKAGE_MANAGER install -y $3
        fi
      else # If a function name is provided
        eval $2
      fi
      if [ $? -ne "0" ]; then
        echo "[ERROR] Failed while installing $command"
        exit 1
      fi
    else # If strict mode is not being used, return an error code
      RESULT=1
    fi
  fi
}

function install_chef() {
  # pull the checksum from the install download
  CHEFCHECKSUM_URL=$CHEF_URL.sha1
  check_command_and_install curl curl curl
  download_file 'Chef checksum' $CHEFCHECKSUM_URL chef-server.sha1
  CHEFCHECKSUM=`cat chef-server.sha1`
  download_file 'Chef server' $CHEF_URL chef-server
  echo "$CHEFCHECKSUM chef-server" > chef.sums
  sha1sum -c chef.sums

  if [[ $PLATFORM == *"ubuntu"* ]]; then
  		sudo dpkg -i chef-server
  else
    if [[ $PLATFORM == *"rhel"* ]] || [[ $PLATFORM == *"centos"* ]]; then
    		sudo rpm -ivh chef-server
    fi
  fi
  if [ $? -ne "0" ]; then
    echo "[ERROR] There was an error installing the requested chef server"
    echo "[ERROR] The provided URL was $CHEF_URL"
    exit 1
  fi
}

function install_docker() {
  # Install Docker EE if the repo was provided
  if [[ -n $DOCKER_EE_REPO ]]; then
    if [[ $PLATFORM == *"ubuntu"* ]]; then
      wait_apt_lock
      if [[ $PLATFORM_VERSION == *"14.04"* ]]; then
        sudo apt-get -y install linux-image-extra-$(uname -r) linux-image-extra-virtual
      fi
      sudo apt-get -y install apt-transport-https ca-certificates software-properties-common
      curl -fsSL $DOCKER_EE_REPO/ubuntu/gpg | sudo apt-key add -
      sudo add-apt-repository "deb [arch=amd64] "$DOCKER_EE_REPO"/ubuntu $(lsb_release -cs) stable-17.03"
      sudo apt-get -y update
      sudo apt-get -y install docker-ee
    else
      if [[ $PLATFORM == *"rhel"* ]] || [[ $PLATFORM == *"centos"* ]]; then
        # Configure the repository
        sudo sh -c 'echo "'$DOCKER_EE_REPO'/'$PLATFORM'" > /etc/yum/vars/dockerurl'
        sudo sh -c 'echo "'$MAIN_VERSION'" > /etc/yum/vars/dockerosversion'
        sudo yum install -y yum-utils device-mapper-persistent-data lvm2
        sudo yum-config-manager --add-repo $DOCKER_EE_REPO/rhel/docker-ee.repo
        # Install Docker EE
        sudo yum makecache fast
        if [[ $CLOUD_PROVIDER = *"amazon"* ]]; then
          sudo yum -y install docker-ee --enablerepo=rhui-REGION-rhel-server-extras
        else
          sudo yum -y install docker-ee --enablerepo=rhel-7-server-extras-rpms
          if [ $? -ne "0" ]; then
            echo "[ERROR] There was an error enabling the rhel7-server-extras repository. Attempting installation without it."
            sudo yum -y install docker-ee
          fi
        fi
      fi
    fi
    if [ $? -ne "0" ]; then
      echo "[ERROR] There was an error installing Docker EE from the provided repository"
      echo "[ERROR] Repo: $DOCKER_EE_REPO"
      exit 1
    fi
  else # Otherwise install CE in supported platforms
    if [[ $PLATFORM == *"ubuntu"* ]] || [[ $PLATFORM == *"centos"* ]]; then
        [[ $PLATFORM == *"ubuntu"* ]] && wait_apt_lock
        curl -fsSL https://get.docker.com/ | sudo sh
        if [ $? -ne "0" ]; then # Retry on failure
            [[ $PLATFORM == *"ubuntu"* ]] && wait_apt_lock
            curl -fsSL https://get.docker.com/ | sudo sh
        fi  
    fi
    if [ $? -ne "0" ]; then
      echo "[ERROR] There was an error installing Docker CE"
      exit 1
    fi
  fi
  # Start docker as a service on reboot
  [[ `sudo systemctl is-enabled docker` = "disabled" ]] && sudo systemctl enable docker || true
}

function check_firewall {
  # Check for a firewall and allow docker through it
  if command_exists firewall-cmd; then
    firewall-cmd --state > /dev/null
    if [ $? == "0" ]; then
      echo "[*] Firewall detectected, opening ports"
      firewall-cmd --permanent --zone=public --change-interface=docker0
      firewall-cmd --permanent --zone=public --add-port=443/tcp
      firewall-cmd --reload
    fi
  fi
}

function install_docker_compose {
   sudo curl -o /usr/local/bin/docker-compose -L https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-`uname -s`-`uname -m`
   sudo chmod +x /usr/local/bin/docker-compose
}

echo "[*] Verifying requirements"
# Easy installs
check_command_and_install python python-minimal python
check_command_and_install thin_check thin-provisioning-tools thin-provisioning-tools
check_command_and_install pvcreate lvm2 'lvm2*'

# Custom installs
check_command_and_install /usr/bin/chef-server-ctl install_chef
check_command_and_install docker install_docker
check_command_and_install docker-compose install_docker_compose

# Additional fixes
check_firewall

if [ $RESULT -eq 1 ]; then
  echo "Please ensure the installation of all requirements and execute this script again"
  exit 1
fi
EndOfFile
   destination = "./advanced-content-runtime/prereq-check-install.sh"
 }

 provisioner "file" {
    content     = <<EndOfFile
#!/bin/bash
#
# Copyright : IBM Corporation 2016, 2017
#
######################################################################################
# Script to verify the installation and configuration of the content runtime
# Usage: ./verify-installation
######################################################################################

CURRENT_DIR=`dirname $0 | cut -c1`
[[ $CURRENT_DIR == '/' ]] && CONFIG_PATH=`dirname $0` || CONFIG_PATH=`pwd`/`dirname $0`

PARAM_FILE="$CONFIG_PATH/.advanced-runtime-config/.launch-docker-compose.sh"
LOG_FILE="$CONFIG_PATH/.advanced-runtime-config/verification.log"
CHEF_FILE="$CONFIG_PATH/.advanced-runtime-config/chef-install.log"

. $CONFIG_PATH/utilities.sh

log_firewall() {
  if command_exists firewall-cmd; then
    echo "[*] Firewall information:"
    firewall-cmd --state | tee -a $LOG_FILE
    firewall-cmd --zone=public --list-all | tee -a $LOG_FILE
  fi
}

verify_docker() {
  # Verify docker installation
  if command_exists docker; then
    echo "[SUCCESS] Docker is installed" | tee -a $LOG_FILE
  else
    echo "[ERROR] Docker is currently not installed on the system" | tee -a $LOG_FILE
    exit 1
  fi

  # Verify docker is up
  pgrep -f docker > /dev/null
  if [ $? -ne "0" ]; then
    echo "[ERROR] Docker is currently not running" | tee -a $LOG_FILE
  else
    echo "[SUCCESS] Docker is currently running" | tee -a $LOG_FILE
  fi
}

verify_docker_service() {
  if [[ `which systemctl` ]] ; then
    echo "[INFORMATIONAL] Docker is `sudo systemctl is-enabled docker` on boot"
  elif [[ `ls /etc/init.d/docker` ]] ; then
    echo "[INFORMATIONAL] Docker service is started via /etc/init.d/docker  on boot"
  else
    echo "[INFORMATIONAL] Docker service /etc/init.d/docker file not found, docker service may not start on reboot"
  fi

}

verify_containers() {
  PATTERN_MANAGER_CONTAINER="camc-pattern-manager"
  SW_REPO_CONTAINER="camc-sw-repo"

  # Verify pattern manager container is up
  if [ "$(sudo docker ps | grep $PATTERN_MANAGER_CONTAINER)" ]; then
    echo "[SUCCESS] The Pattern Manager image is running correctly" | tee -a $LOG_FILE
    sudo docker inspect --format='{{.Image}}' $PATTERN_MANAGER_CONTAINER | tee -a $LOG_FILE
  else
    echo "[ERROR] The Pattern Manager image is currently not running" | tee -a $LOG_FILE
    echo "$(sudo docker ps | grep $PATTERN_MANAGER_CONTAINER)" >> $LOG_FILE
    echo "[*] Docker Log..." | tee -a $LOG_FILE
    sudo docker ps | grep $PATTERN_MANAGER_CONTAINER | tee -a $LOG_FILE
    sudo docker ps -a | tee -a $LOG_FILE
    exit 1
  fi

  # Verify repo container is up
  if [ "$(sudo docker ps | grep $SW_REPO_CONTAINER)" ]; then
    echo "[SUCCESS] The Software Repository image is running correctly" | tee -a $LOG_FILE
    sudo docker inspect --format='{{.Image}}' $SW_REPO_CONTAINER | tee -a $LOG_FILE
  else
    echo "[ERROR] The Software Repository image is currently not running" | tee -a $LOG_FILE
    echo "$(sudo docker ps | grep $SW_REPO_CONTAINER)" >> $LOG_FILE
    echo "[*] Docker Log..." | tee -a $LOG_FILE
    sudo docker ps | grep $SW_REPO_CONTAINER | tee -a $LOG_FILE
    sudo docker ps -a | tee -a $LOG_FILE
    exit 1
  fi
}

verify_pattern_manager() {
  # Verify connection to Pattern Manager
  # Get port number
  PM_PORT=`cat $CONFIG_PATH/camc-pattern-manager.tmpl | egrep -A1 "ports" | tail -1 | cut -f2 -d"\"" | cut -f1 -d":"`
  # Get AccessToken
  PM_ACCESSTOKEN=`cat $PARAM_FILE | egrep "ibm_pm_access_token" | cut -f2 -d"="`
  PM_CHECK=`curl -s --write-out %{http_code} --output pm_version.out --request POST -k -H "Authorization:Bearer $PM_ACCESSTOKEN" -X GET https://localhost:$PM_PORT/version`
  if [ $PM_CHECK == 200 ]; then
    echo "[SUCCESS] Connection to the Pattern Manager image was established correctly" | tee -a $LOG_FILE
  else
    echo "[ERROR] Could not establish connection to the Pattern Manager image" | tee -a $LOG_FILE
    echo "curl -s --write-out %{http_code} --output pm_version.out --request POST -k -H \"Authorization:Bearer $PM_ACCESSTOKEN\" -X GET https://localhost:$PM_PORT/version" >> $LOG_FILE
    curl -s --write-out %{http_code} --output pm_version.out --request POST -k -H "Authorization:Bearer $PM_ACCESSTOKEN" -X GET https://localhost:$PM_PORT/version | tee -a $LOG_FILE
    log_firewall
    exit 1
  fi
}

verify_sw_repo() {
  # Verify connection to Software Repo
  # Get port for software repo
  # SW_PORT=`cat camc-sw-repo.tmpl | egrep -A1 "ports" | tail -1 | cut -f2 -d"\"" | cut -f1 -d":"`
  # Get user and password for software repo
  SW_USER=`cat $PARAM_FILE | egrep "software_repo_user" | cut -f2 -d"="`
	SW_PASS=`cat $PARAM_FILE | egrep "software_repo_pass" | cut -f2 -d"="`

  SW_CHECK=`curl -s -u $SW_USER:$SW_PASS -k --write-out %{http_code} --output sw_repo.out -X GET https://localhost:9999`

  if [ $SW_CHECK == 403 ]; then
    echo "[SUCCESS] Connection to the Software Repo image was established correctly" | tee -a $LOG_FILE
  else
    echo "[ERROR] Could not establish connection to the Software Repo image" | tee -a $LOG_FILE
    echo "curl -s --write-out %{http_code} --output sw_repo.out -k $SW_USER:$SW_PASS -X GET https://localhost:9999" >> $LOG_FILE
    curl -s --write-out %{http_code} --output sw_repo.out -k $SW_USER:$SW_PASS -X GET https://localhost:9999 | tee -a $LOG_FILE
    log_firewall
    exit 1
  fi
}

verify_pattern_manager_connection() {
  IPADDR=`cat $PARAM_FILE | egrep "static_ip_address" | cut -f2 -d"="`
  sudo docker exec -i camc-pattern-manager /bin/bash -c "nc -v -w 30 -z $IPADDR 443"
  if [ $? -gt 0 ]; then
    echo "[ERROR] Couldn't establish a connection between Pattern Manager and host using port 443" | tee -a $LOG_FILE
    log_firewall
    exit 1
  else
    echo "[SUCCESS] Connection from Pattern Manager to host has been established successfully" | tee -a $LOG_FILE
  fi
}

verify_chef() {
  # Check the status of the running nodes every second for a minute, if an error is found, exit
  ATTEMPT=0
  echo "[*] Verifying Chef status" | tee -a $LOG_FILE
  while [ $ATTEMPT -lt 10 ];
  do
    sudo /usr/bin/chef-server-ctl status > /dev/null
    if [ $? -gt 0 ]; then
      sudo /usr/bin/chef-server-ctl status | tee -a $LOG_FILE
      echo "[ERROR] The Chef server nodes are not running correctly" | tee -a $LOG_FILE
      exit 1
    fi
    let ATTEMPT=ATTEMPT+1
    sleep 1
  done
  echo "[SUCCESS] Chef server nodes are running correctly" | tee -a $LOG_FILE
}

verify_cookbooks() {
  IPADDR=`cat $PARAM_FILE | egrep "static_ip_address" | cut -f2 -d"="`
  PM_ACCESSTOKEN=`cat $PARAM_FILE | egrep "ibm_pm_access_token" | cut -f2 -d"="`
  LOOPIT=0; LOOPCOUNT=0
	while test $LOOPIT -eq 0 # We need to loop because chef sometimes returns bad data, the response code is not 200, we will retry a few times to get past the error
	do
	  CHECK=`curl -s -k --write-out %{http_code} --output cookbooks.out -H "Authorization:Bearer $PM_ACCESSTOKEN" -X GET https://$IPADDR:5443/v1/info/chef`
    if [ "$CHECK" = 200 ]; then
      LOOPIT=1
    else
      let 'LOOPCOUNT=LOOPCOUNT+1'
      if [ "$LOOPCOUNT" = "10" ]; then
        LOOPIT=1
      fi
    fi
	done
	if [ "$CHECK" = 200 ]; then
		echo "[SUCCESS] Chef Cookbooks verified successfully" | tee -a $LOG_FILE
	else
    echo "curl -k --write-out %{http_code} --output cookbooks.out -H 'Authorization:Bearer $PM_ACCESSTOKEN' -X GET https://$IPADDR:5443/v1/info/chef" > $LOG_FILE
		echo "[ERROR] There was a problem verifying Chef Cookbooks" | tee -a $LOG_FILE
	fi
	if [[ `egrep '"roles":' cookbooks.out` && `egrep '"cookbooks":' cookbooks.out` ]]; then
    echo "[SUCCESS] Cookbooks response verified successfully" | tee -a $LOG_FILE
  else
    echo "[ERROR] There was a problem verifying Chef Cookbook's response" | tee -a $LOG_FILE
  fi
	# check to see if there were some roles and cookbooks written
	CB_COUNT=0
	CB_START=`egrep -n ' .cookbooks.: \[' cookbooks.out |cut -f1 -d:`
	CB_END=`egrep -n '\],' cookbooks.out|cut -f1 -d:`

	let 'CB_COUNT=CB_END-CB_START'
	if [ "$CB_COUNT" -gt "5" ] ; then
    echo "[SUCCESS] Total Chef Cookbook count $CB_COUNT" | tee -a $LOG_FILE
	else
    echo "[ERROR] Total Chef Cookbook count $CB_COUNT, at least 6 expected" | tee -a $LOG_FILE
	fi

  ROLE_COUNT=0
  ROLE_START=`egrep -n ' .roles.: \[' cookbooks.out|cut -f1 -d:`
	ROLE_END=`egrep -n '\]$' cookbooks.out|cut -f1 -d:`
	let 'ROLE_COUNT=ROLE_END-ROLE_START'
  if [ "$ROLE_COUNT" -gt "5" ] ; then
    echo "[SUCCESS] Total Chef role count $ROLE_COUNT" | tee -a $LOG_FILE
  else
    echo "[ERROR] Total Chef role count $ROLE_COUNT, at least 6 expected" | tee -a $LOG_FILE
  fi
  cat cookbooks.out >> $LOG_FILE
}

function verify_software_directory()
{
  FAIL_COUNT=0
  mkdirFile=$CONFIG_PATH/mkdir.properties
  ABS_PATH=`egrep 'ROOT : ' $mkdirFile | cut -f2 -d':' | tr -d ' '`
  set `cat $mkdirFile | egrep -v "^#"`
  while test $# -gt 0 ; do
    ls $ABS_PATH/$1 2> /dev/null > /dev/null
    if [[ ! "$?" = "0" ]] ; then
      echo "    Missing directory : $ABS_PATH/$1"
      FAIL_COUNT=1
    fi
    shift
  done
  if [ "$FAIL_COUNT" -gt "0" ] ; then
     echo "[ERROR] $ABS_PATH is not setup as expected, see previous message" | tee -a $LOG_FILE
  else
    echo "[SUCCESS] $ABS_PATH is setup as expected" | tee -a $LOG_FILE
  fi
}

function echo_log_file_locations()
{
  echo "[INFORMATIONAL] Addition information can be located in log files :"
  echo -e "\tverification log : \n\t\t$LOG_FILE"
  echo -e "\tchef installation log : \n\t\t$CHEF_FILE"
  echo -e "\tpattern manager logs : \n`sudo ls -1 /var/log/ibm/docker/pattern-manager/* | xargs -i echo -e '\t\t{}'`"
}

TIMESTAMP=`date '+%Y-%m-%d %H:%M:%S'`
echo "[*] Verifying Content Runtime installation, started on $TIMESTAMP" | tee -a $LOG_FILE
echo "[*] Content Runtime template version: `cat $PARAM_FILE | egrep 'template_timestamp' | cut -f2 -d'='`"
echo "[*] Hostname : `hostname`, Domain : `hostname -d`" | tee -a $LOG_FILE
echo -e "/etc/hosts:\n`cat /etc/hosts`\n" >> $LOG_FILE
echo_log_file_locations
verify_chef
verify_docker
verify_docker_service
verify_containers
verify_cookbooks
verify_sw_repo
verify_pattern_manager
verify_pattern_manager_connection
verify_software_directory
EndOfFile
    destination = "./advanced-content-runtime/verify-installation.sh"
  }

  provisioner "file" {
   content     = <<EndOfFile
#!/bin/bash
#
# Copyright : IBM Corporation 2016, 2017
#
######################################################################################
# Script that contains functions used on other files
# Usage: . ./utilities.sh
######################################################################################

# download_file name url file-name
download_file() {
  rm -rf *.prg
  curl -o $3 --retry 5 --progress-bar $2 2> $3.prg &
  CURL_PID=$!
  string="[*] Downloading: $1"
  line="......................................................."
  LAST_PROGRESS='0.0'

  while kill -0 $CURL_PID > /dev/null 2>&1
  do
    sleep 10
    PROGRESS=`grep -o -a "..0..%" $3.prg | tail -n1`
    if [ "$PROGRESS%" != "$LAST_PROGRESS%" ]; then
      LAST_PROGRESS=$PROGRESS
      printf "%s %s [$PROGRESS%]\n" "$string" "$${line:$${#string}}"
    fi
  done
  rm -rf $3.prg
  printf "%s %s [COMPLETE]\n" "$string" "$${line:$${#string}}"
}

# Check if a command exists
command_exists() {
  type "$1" &> /dev/null;
}
EndOfFile
   destination = "./advanced-content-runtime/utilities.sh"
 }

 provisioner "file" {
    content     = <<EndOfFile
#!/bin/bash
# encoding: UTF-8
########################################################
# Copyright IBM Corp. 2016, 2016
#
#  Note to U.S. Government Users Restricted Rights:  Use,
#  duplication or disclosure restricted by GSA ADP Schedule
#  Contract with IBM Corp.
############################################################

if [ "$DEBUG" = "true" ] ; then set -x ; fi
set -o errexit
set -o nounset

# change to script path
cd /opt

# This is a patch for issue : https://github.com/chef/chef_backup/issues/26
sed -i  "s#configs\[config\]\['config'\]#configs[config]['data_dir']#g" /opt/opscode/embedded/lib/ruby/gems/2.2.0/gems/chef_backup-0.0.1/lib/chef_backup/data_map.rb

echo 'Pushing memory limits higher'
/sbin/sysctl -w kernel.shmmax=8589934592
/sbin/sysctl -w kernel.shmall=2097152
/sbin/sysctl -p /etc/sysctl.conf

# Use a random admin user password if none is provided
if [ ".$ADMIN_PASSWORD" = "."  ] ; then export ADMIN_PASSWORD=$(< /dev/urandom |head -c64 | md5sum|head -c12); fi
# Self signed SSL cert params defaults (using IBM Headquarters)
if [ ".$SSL_CERT_COUNTRY" = "."  ] ; then export SSL_CERT_COUNTRY="US"; fi
if [ ".$SSL_CERT_STATE" = "."  ] ; then export SSL_CERT_STATE="New York"; fi
if [ ".$SSL_CERT_CITY" = "." ] ; then export SSL_CERT_CITY="Armonk"; fi

echo 'Chef Server - CONFIG START'
# Make sure we have the right config
chefconfig="/etc/opscode/chef-server.rb"
certsdir="/etc/opscode/ca"

cp /opt/chef-server.rb $chefconfig
# parse config to update certificates paths if needed
custompem=`ls -1 $certsdir/*.pem 2> /dev/null|head -1`
customkey=`ls -1 $certsdir/*.key 2> /dev/null|head -1`
if test -n "$custompem" && test -n "$customkey"  && test -f $custompem && test -f $customkey; then
    # we're going to use the customer provided certs
    echo 'Using customer provided SSL certificates'
    sed -i "s#CUSTOMPEM#$custompem#g" $chefconfig
    sed -i "s#CUSTOMKEY#$customkey#g" $chefconfig
else
    # remove ssl related configs and use self-generated certs
    echo 'Using self-signed SSL certificates'
    sed -i "/ssl_/d" $chefconfig
    # generate self-signed certs with sha256 encryption instead of sha1
    certpath="/var/opt/opscode/nginx/ca/"
    [[ ! -d "$certpath" ]] && mkdir -p $certpath
    certname="/var/opt/opscode/nginx/ca/$HOSTNAME"
    openssl genrsa > "$certname.key"
    openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048\
        -key "$certname.key" -out "$certname.crt"\
        -subj "/C=$SSL_CERT_COUNTRY/ST=$SSL_CERT_STATE/L=$SSL_CERT_CITY/O=$ORG_NAME/CN=$HOSTNAME"
fi

# Start Chef own runservice
/opt/opscode/embedded/bin/runsvdir-start &

# Drop old running context
rm -f /etc/opscode/chef-server-running.json
rm -f /opt/opscode/embedded/service/oc_id/tmp/pids/server.pid

# Configure/post crash reconfigure
echo "Doing initial configuration of Chef server"
/usr/bin/chef-server-ctl reconfigure  2>&1 | tee $CHEF_LOG | egrep ": Processing directory|: Processing cookbook_file"  # do not display lines string w/blanks

# Initial configuration for Chef Manage Web-GUI if installed
if test -f /usr/bin/chef-manage-ctl; then
    echo "Doing initial configuration of Chef Manage"
    /usr/bin/chef-manage-ctl reconfigure
fi

# Create admin user if it's not there
if [ `/usr/bin/chef-server-ctl user-list|grep -cE $ADMIN_NAME` -eq 0 ]; then
    echo "Creating admin user: $ADMIN_NAME"
    /usr/bin/chef-server-ctl user-create $ADMIN_NAME $ADMIN_NAME $ADMIN_NAME $ADMIN_MAIL "$ADMIN_PASSWORD" -f /etc/opscode/$ADMIN_NAME.pem
fi

# Create chef organization
SHORT_ORG_NAME=`echo $ORG_NAME | tr '[:upper:]' '[:lower:]'`
if [ `/usr/bin/chef-server-ctl org-list|grep -cE $SHORT_ORG_NAME` -eq 0 ]; then
    echo "Creating organization: $SHORT_ORG_NAME"
    /usr/bin/chef-server-ctl org-create $SHORT_ORG_NAME $ORG_NAME -f /etc/opscode/$SHORT_ORG_NAME.pem --association_user $ADMIN_NAME
fi

echo 'Chef Server - CONFIG DONE'
echo "Chef Server - running on host: $HOSTNAME"
/usr/bin/chef-server-ctl status
rc=$?
if [ $rc -gt 0 ]; then
	tail -f $CHEF_LOG
fi
exit $rc
EndOfFile
    destination = "./advanced-content-runtime/setupchef.sh"
  }

 provisioner "file" {
    content = <<EndOfFile
#!/usr/bin/env python

""" Create a PM config file from input values
"""

import argparse
import base64
import json
import sys

parser = argparse.ArgumentParser(description="Create PM configuration file")
parser.add_argument("access_token")
parser.add_argument("admin_token")
parser.add_argument("cam_service_key_loc")
parser.add_argument("-c", nargs="?", default="unencoded")
parser.add_argument("chef_pem_loc")
parser.add_argument("-p", nargs="?", default="unencoded")
parser.add_argument("chef_fqdn")
parser.add_argument("chef_org")
parser.add_argument("chef_ip")
parser.add_argument("chef_admin_id")
parser.add_argument("software_repo_ip")
parser.add_argument("software_repo_unsecured_port")
parser.add_argument("target_file", default="pm_config.json")
args = parser.parse_args()

with open(args.cam_service_key_loc, "r") as f:
    key_data = f.read()
if args.c == "unencoded":
    cam_key_raw = base64.b64encode(key_data)
else:
    cam_key_raw = key_data

with open(args.chef_pem_loc, "r") as f:
    pem_data = f.read()
if args.p == "unencoded":
    pem_raw = base64.b64encode(pem_data)
else:
    pem_raw = pem_data

pm_config = {
    "access_tokens": {
        "access_token": args.access_token,
        "admin_token": args.admin_token
                     },
    "cam_service_keys": {"default": {"raw_key": cam_key_raw}},
    "chef_servers": {"default":
                     {"pem": pem_raw, "fqdn": args.chef_fqdn,
                      "org": args.chef_org, "ip": args.chef_ip,
                      "admin_id": args.chef_admin_id,
                      "software_repo_ip": args.software_repo_ip,
                      "software_repo_unsecured_port":
                          args.software_repo_unsecured_port
                      }
                     }
             }
en_pm_config = base64.b64encode(json.dumps(pm_config))

with open(args.target_file, "w") as f:
    f.write(en_pm_config)

sys.exit()
EndOfFile
    destination = "./advanced-content-runtime/crtconfig.py"
  }

 provisioner "file" {
    content     = <<EndOfFile
opscode_erchef['s3_url_ttl'] = 3600
nginx['ssl_certificate'] = "CUSTOMPEM"
nginx['ssl_certificate_key'] = "CUSTOMKEY"
nginx['ssl_ciphers'] = "HIGH:MEDIUM:!LOW:!kEDH:!aNULL:!ADH:!eNULL:!EXP:!SSLv2:!SEED:!CAMELLIA:!PSK"
nginx['ssl_protocols'] = "TLSv1 TLSv1.1 TLSv1.2"
nginx['stub_status'] = { :listen_port => 7777, :listen_host => '127.0.0.1' }
EndOfFile
    destination = "./advanced-content-runtime/chef-server.rb"
  }

  provisioner "file" {
    content     = <<EndOfFile
{ 
	"authorization": { 
		"personal_access_token": "$CAMHUB_ACCESS_TOKEN"
	},
        "github_hostname": "$CAMHUB_HOST",
        "org": "$CAMHUB_ORG",
        "repos": "cookbook_.*"
}
EndOfFile
    destination = "./advanced-content-runtime/load.tmpl"
  }

  provisioner "file" {
    content     = <<EndOfFile
  #camc-pattern-manager
  camc-pattern-manager:
    image: $DOCKER_REGISTRY_PATH/camc-pattern-manager:$PATTERN_MGR_VERSION
    restart: always
    container_name: camc-pattern-manager
    hostname: $PATTERN_MGR_FQDN
    volumes:
      - /var/log/ibm/docker/pattern-manager:/var/log/pattern-manager
      - /var/log/ibm/docker/pattern-manager:/var/log/apache2
      - /etc/opscode:/home/chef-user/opscode
      - /opt/ibm/docker/pattern-manager/certs:/opt/ibm/pattern-manager/flask_application/certs
      - /opt/ibm/docker/pattern-manager:/opt/ibm/pattern-manager/ssl
      - /opt/ibm/docker/pattern-manager/config:/opt/ibm/pattern-manager/config
    tmpfs: /tmp
    environment:
      - PM_CONFIG=/opt/ibm/pattern-manager/config/config.json
      - PATTERN_MGR_FQDN=$PATTERN_MGR_FQDN
    ports:
      - "5443:443"
    extra_hosts:
      - $CHEF_HOST_FQDN:$CHEF_IPADDR
      - $SOFTWARE_REPO_FQDN:$SOFTWARE_REPO_IP
EndOfFile
    destination = "./advanced-content-runtime/camc-pattern-manager.tmpl"
  }

  provisioner "file" {
    content     = <<EndOfFile
  #camc-sw-repo
  camc-sw-repo:
    image: $DOCKER_REGISTRY_PATH/camc-sw-repo:$SOFTWARE_REPO_VERSION
    restart: always
    container_name: camc-sw-repo
    hostname: $SOFTWARE_REPO_FQDN
    volumes:
      - /opt/ibm/docker/software-repo/etc/nginx/auth:/etc/nginx/auth
      - /var/log/ibm/docker/software-repo/var/log/nginx:/var/log/nginx
      - /opt/ibm/docker/software-repo/etc/fstab:/etc/fstab
      - /opt/ibm/docker/software-repo/var/swRepo/private:/var/swRepo/private
      - /opt/ibm/docker/software-repo/var/swRepo/yumRepo:/var/swRepo/yumRepo
      - /opt/ibm/docker/software-repo/etc/nginx/server-certs:/etc/nginx/ssl
    environment:
      - SOFTWARE_REPO_FQDN=$SOFTWARE_REPO_FQDN
    ports:
      - "8888:8888"
      - "9999:9999"
    privileged: true
EndOfFile
    destination = "./advanced-content-runtime/camc-sw-repo.tmpl"
  }

  provisioner "file" {
    content     = <<EndOfFile
#
# Copyright : IBM Corporation 2016, 2016
#
###########################################################################
# Docker Compose file for deploying repo-server, chef-server and pattern-manager
###########################################################################
version: '2'
services:

EndOfFile
    destination = "./advanced-content-runtime/infra-docker-compose.tmpl"
  }

  provisioner "file" {
    content     = <<EndOfFile
#!/bin/bash
#
# Copyright : IBM Corporation 2017. All rights reserved.
#
set -o errexit
set -o nounset
set -o pipefail

if [ $# -ne 2 ] ; then
  echo "Usage: image-upgrade <service> <version>"
  exit 1
fi

toolpath=`dirname $0`

if ! grep -xq ".*image:.*$1:.*" $toolpath/docker-compose.yml ; then
  echo "ERROR: Unable to find image definition for '$1' in docker-compose.yml."
  exit 1
fi

# Backup docker-compose.yml to docker-compose.yml.orig-<date_timestamp>
# Find / replace image line for <service> and update with new <version>
datetime=`date +"%Y-%m-%d_%H_%M_%S"`
sed --in-place=".orig-$datetime" -E "/\s*image:/s/($1:)(.*)/\1$2/" $toolpath/docker-compose.yml

set +e # disable checks
if ! sudo docker-compose -f $toolpath/docker-compose.yml pull; then
  echo "ERROR: Docker pull failed, restoring original config..."
  badconf="$toolpath/docker-docker-compose.yml.BAD-$datetime"
  mv $toolpath/docker-compose.yml $badconf
  mv "$toolpath/docker-compose.yml.orig-$datetime" $toolpath/docker-compose.yml
  echo "ERROR: Bad configuration saved in: $badconf"
  exit 1
fi
set -e # re-enable checks

echo "Pull done, restarting containers..."
sudo docker-compose -f $toolpath/docker-compose.yml stop
sudo docker-compose -f $toolpath/docker-compose.yml up -d

# Archive the output into the parameter file 
imagename=`grep -q ".*image:.*$1:.*" $toolpath/docker-compose.yml | rev |cut -f2 -d: | cut -f1 -d/ | rev`
sed -i "s/\(--$imagename\_version=\)\(.*\)/\1$2/" `find $toolpath -name .launch-docker-compose.sh`

echo "Done."
EndOfFile
    destination = "./advanced-content-runtime/image-upgrade.sh"
  }

  provisioner "file" {
    content     = <<EndOfFile
# Properties file used to create the directory structure on the location disk
# All path are relative to ROOT : /opt/ibm/docker/software-repo/var/swRepo/private
apache/httpd/v2.4.25/rhel7
apache/tomcat/v70/base
apache/tomcat/v80/base
db2/v105/base
db2/v105/maint
db2/v111/base
db2/v111/maint
im/v1x/base
IMRepo
oracle/mysql/v5.7.17/base
wmq/v8.0/base
wmq/v8.0/maint
wmq/v9.0/base
wmq/v9.0/maint
EndOfFile
    destination = "./advanced-content-runtime/mkdir.properties"
  }

  provisioner "file" {
    content     = <<EndOfFile
LayoutPolicyVersion=0.0.0.1
LayoutPolicy=Composite 
#repository.url.was=./WAS9
#repository.url.liberty=./Liberty
#repository.url.jdk8=./jdk8
EndOfFile
    destination = "./advanced-content-runtime/repository.config"
  }

  provisioner "file" {
    content     = <<EndOfFile
#
# Copyright : IBM Corporation 2016, 2016
#
######################################################################################
# Script to install docker-engine, docker-compose and launch the containers as per infra-docker-compose.tmpl
######################################################################################
#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

TEMPLATE_TIMESTAMP=""

function setup_aws_private() { # This is for PRIVATE network
  # AWS images do not have standard settings for IP and Hostname on the image.
	# The information in stored in metadata, which is accessable using the curl and IP address below
	# The IP is a virual address on top of the VM, and the request does not leave the machine
	# In turn the information is set back onto the VM to allow Chef and other packages to get information
	# about the configuration as they expect in a standard machine
  IPADDR=`curl http://169.254.169.254/latest/meta-data/local-ipv4` # ~ip_checker
  HOSTNAME=`curl http://169.254.169.254/latest/meta-data/local-hostname| cut -f1 -d'.' ` # ~ip_checker
  # Depending on the region there are different domains
  metadata=169.254.169.254 # ~ip_checker
  [[ "curl http://$metadata/latest/dynamic/instance-identity/document | egrep 'region.*us-east-1'" ]] && DOMAIN=ec2.internal || DOMAIN=`curl http://$metadata/latest/dynamic/instance-identity/document | cut -f4 -d'"'`.compute.internal # ~ip_checker
  # For chef local configuration, we need to fix up the host name on aws
  sudo hostname $HOSTNAME.$DOMAIN
  echo $IPADDR $HOSTNAME.$DOMAIN | sudo tee -a /etc/hosts
}

function setup_aws_public() { # This is for the PUBLIC network
  # AWS images do not have standard settings for IP and Hostname on the image.
  # The information in stored in metadata, which is accessable using the curl and IP address below
  # The IP is a virual address on top of the VM, and the request does not leave the machine
  # In turn the information is set back onto the VM to allow Chef and other packages to get information
  # about the configuration as they expect in a standard machine
  IPADDR=`curl http://169.254.169.254/latest/meta-data/public-ipv4` # ~ip_checker
  DOMAIN=`curl http://169.254.169.254/latest/meta-data/public-hostname| cut -f2- -d'.' ` # ~ip_checker
  HOSTNAME=`curl http://169.254.169.254/latest/meta-data/public-hostname| cut -f1 -d'.' ` # ~ip_checker
  # For chef local configuration, we need to fix up the host name on aws
  sudo hostname `curl http://169.254.169.254/latest/meta-data/public-hostname` # ~ip_checker
}

function setup_other_private() {
  # this is used to get the domain name of the docker host, and pass to the rest of the infrastructure, based on the docker node
	IPADDR=`ip addr | tr -s ' ' | egrep 'inet ' | sed -e 's/inet //' -e 's/addr://' -e 's/ Bcast.*//' -e 's/ netmask.*//' -e 's/ brd.*//'  -e 's/^ 127\..*//' -e 's/^ 172\...\.0\.1.*//' | cut -f1 -d'/'| xargs echo`
	DOMAIN=`hostname -d`
	HOSTNAME=`hostname | cut -f1 -d.`
}

function setup_other_public() {
  # this is used to get the domain name of the docker host, and pass to the rest of the infrastructure, based on the docker node
  IPADDR=`ip addr | tr -s ' ' | egrep 'inet ' | sed -e 's/inet //' -e 's/addr://' -e 's/ Bcast.*//' -e 's/ netmask.*//' -e 's/ brd.*//'  -e 's/^ 127\..*//' -e 's/^ 172\...\.0\.1.*//' -e 's/^ 10\..*//' -e 's/^ 192.168\..*//' | cut -f1 -d'/'| xargs echo`
  DOMAIN=`hostname -d`
  HOSTNAME=`hostname | cut -f1 -d.`
}

function setup_static_public() {
  # This is the case that we have the IP address
  DOMAIN=`hostname -d`
  HOSTNAME=`hostname | cut -f1 -d.`
}

function find_disk()
{
  # Will return an unallocated disk, it will take a sorting order from largest to smallest, allowing a the caller to indicate which disk
  [[ -z "$1" ]] && whichdisk=1 || whichdisk=$1
  diskcount=`sudo parted -l 2>&1 | egrep -c -i 'ERROR: '`
  if [ "$diskcount" -lt "$whichdisk" ] ; then
        echo ""
  else
        # Find the disk name
        greplist=`sudo parted -l 2>&1 | egrep -i "ERROR:" |cut -f2 -d: | xargs -i echo "Disk.{}:|" | xargs echo | tr -d ' ' | rev | cut -c2- | rev`
        echo `sudo fdisk -l  | egrep "$greplist"  | sort -k5nr | head -n $whichdisk | tail -n1 | cut -f1 -d: | cut -f2 -d' '`
  fi
}

function allocate_software_disk()
{
  DISK_NAME=$(find_disk 1) # find the largest disk for formatting
  if [ ! -z "$DISK_NAME" ] ; then
     echo "Obtained disk name: $DISK_NAME"
     ONE=1
     DISK_ONE="$DISK_NAME$ONE"
     (echo n; echo p; echo " "; echo " "; echo " "; echo w;) | sudo fdisk $DISK_NAME
     sudo mkfs.ext4 $DISK_ONE
     echo "Formatting $DISK_ONE"
     sudo mkdir -p $MOUNT_POINT
     echo "Mounting formatted disk to $MOUNT_POINT"
     echo $DISK_ONE  $MOUNT_POINT   ext4    defaults    0 0 | sudo tee -a $FSTAB_FILE
     sudo mount $DISK_ONE $MOUNT_POINT
     sudo mkdir -p $REPO_DIR
  fi
  # We shall just use local storage here in place of software
  [[ -e $runtimepath/mkdir.properties ]] && cat $runtimepath/mkdir.properties | egrep -v '#' | xargs -i sudo mkdir -p $REPO_DIR/{}
  [[ -e $runtimepath/repository.config ]] && sudo cp $runtimepath/repository.config $REPO_DIR/IMRepo/
}

function docker_disk()
{
  DISK_NAME=$(find_disk 1) # find the largest disk for formatting
  sudo mkdir -p /etc/docker/
  # Ubuntu 14.04 fails to mount the disk because of a downlevel API, do not process the disk if present
  if [[ ! -z "$DISK_NAME" ]] && [[ `sudo lvcreate --help | egrep wipesignatures` ]] ; then
     echo "Obtained disk name: $DISK_NAME"
     ONE=1
     DOCKER_DISK_NAME=$DISK_NAME$ONE
     (echo n; echo p; echo " "; echo " "; echo " "; echo t; echo 8e; echo w;) | sudo fdisk $DISK_NAME
     sudo pvcreate $DOCKER_DISK_NAME
     echo -e "{ \n\"storage-driver\": \"devicemapper\",\n\t\"storage-opts\": [\n\t\"dm.directlvm_device=$DOCKER_DISK_NAME\",\n\t\"dm.directlvm_device_force=true\"\n\t] \n}" | sudo tee /etc/docker/daemon.json
     sudo mkdir -p /etc/lvm/profile/
     echo -e "activation{\nthin_pool_autoextend_threshold=80\nthin_pool_autoextend_percent=20\n}\n" | sudo tee /etc/lvm/profile/docker-thinpool.profile
     sudo mv /var/lib/docker /var/lib/docker.origin || true
  else
     echo -e "{\n\"storage-driver\": \"devicemapper\"\n}" | sudo tee /etc/docker/daemon.json
  fi
}

function begin_message() {
  # Function is used to log the start of some configuration function
	config_name=$1
  string="============== Configure : $config_name : $TEMPLATE_TIMESTAMP =============="
  echo "`echo $string | sed 's/./=/g'`"
  echo "$string"
  echo -e "`echo $string | sed 's/[^=]/ /g'`\n"
}

function end_message() {
	string="============== Completed : $config_name, Status: $1 =============="
	echo -e "\n`echo $string | sed 's/[^=]/ /g'`"
	echo "$string"
	echo -e "`echo $string | sed 's/./=/g'`\n\n"
	config_name="unknown"
}

# In the case of retry, the script is reenterant, and can be invokes using the last set of parameters.
begin_message "Parameter File"
[[ `dirname $0 | cut -c1` == '/' ]] && runtimepath=`dirname $0/` || runtimepath=`pwd`/`dirname $0`
parmdir=$runtimepath/.advanced-runtime-config/
mkdir -p $parmdir

parmfile=$parmdir/.`basename $0`

if [[ $# -gt 0 ]] ; then
     if [[ -e $parmfile ]] ; then mv $parmfile $parmfile.`date | tr ' ' '_' | tr ':' '-'`; fi
     while [ $# -gt 0 ]
     do
         printf "%s\n" "$1" >> $parmfile
         shift
     done
fi

# Set the defaults of the script
DOCKER_REGISTRY="orpheus-local-docker.artifactory.swg-devops.com"
DOCKER_IMAGE_PATH="opencontent"

CHEF_ADMIN="chef-admin"
CHEF_IPADDR=""
CHEF_PEM=""
CHEF_HOST=""
CHEF_HOST_FQDN=""
CHEF_ORG="opencontent"
CHEF_VERSION=12.1.1
CHEF_URL="https://packages.chef.io/files/stable/chef-server/12.11.1/ubuntu/14.04/chef-server-core_12.11.1-1_amd64.deb"
CHEF_ADMIN_PASSWORD=''
CHEF_SSL_CERT_COUNTRY=''
CHEF_SSL_CERT_STATE=''
CHEF_SSL_CERT_CITY=''

NFS_SERVER_IP_ADDR="format"
DOCKER_REGISTRY_USER=""
DOCKER_REGISTRY_TOKEN=""
CONFIGURATION="single-node"

SOFTWARE_REPO_IP=""
SOFTWARE_REPO_PORT="8888"
SOFTWARE_REPO=""
SOFTWARE_REPO_FQDN=""
SOFTWARE_REPO_PASS=""
SOFTWARE_REPO_USER="repouser"
SOFTWARE_REPO_VERSION=latest
IM_REPO_PASS=""
IM_REPO_USER="repouser"

PATTERN_MGR=""
PATTERN_MGR_FQDN=""
PATTERN_MGR_VERSION=latest
PATTERN_MGR_ADMIN_TOKEN=""
PATTERN_MGR_ACCESS_TOKEN=""

CAMHUB_ACCESS_TOKEN=""
CAMHUB_HOST="github.ibm.com"
CAMHUB_ORG="CAMHub-Test"
CAMHUB_OPEN_ORG=""

CAM_PRIVATE_KEY_ENC=""
CAM_PUBLIC_KEY=""
CAM_PUBLIC_KEY_NAME=""
USER_PUBLIC_KEY=""

help=false
debug=false

PRIVATE_NETWORK=`head -n1 $parmfile` # pull off the first parameter indicating this is a private network

# Parse parameters from the command line, allow a parameter name, or parameter value, - options will only consume the first character
set +o errexit
while IFS='' read -r parameter || [[ -n "$parameter" ]]; do
        [[ $parameter =~ ^-cpu|--ibm_pm_public_ssh_key_name= ]] && { CAM_PUBLIC_KEY_NAME=`echo $parameter|cut -f2- -d'='`; continue;  }; # unused
        [[ $parameter =~ ^-cpr|--ibm_pm_private_ssh_key= ]] && { CAM_PRIVATE_KEY_ENC=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-cpp|--ibm_pm_public_ssh_key= ]] && { CAM_PUBLIC_KEY=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-up|--user_public_ssh_key= ]] && { USER_PUBLIC_KEY=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-dr|--docker_registry= ]] && { DOCKER_REGISTRY=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-dr|--docker_registry_path= ]] && { DOCKER_IMAGE_PATH=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-du|--docker_registry_user= ]] && { DOCKER_REGISTRY_USER=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-dt|--docker_registry_token= ]] && { DOCKER_REGISTRY_TOKEN=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-de|--docker_ee_repo= ]] && { DOCKER_EE_REPO=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-dc|--docker_configuration= ]] && { CONFIGURATION=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ca|--chef_admin= ]] && { CHEF_ADMIN=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ch|--chef_host= ]] && { CHEF_HOST=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-co|--chef_org= ]] && { CHEF_ORG=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-cw|--chef_admin_password= ]] && { CHEF_ADMIN_PASSWORD=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-co|--chef_ssl_cert_country= ]] && { CHEF_SSL_CERT_COUNTRY=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-cs|--chef_ssl_cert_state= ]] && { CHEF_SSL_CERT_STATE=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ct|--chef_ssl_cert_city= ]] && { CHEF_SSL_CERT_CITY=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-cv|--chef_version= ]] && { CHEF_VERSION=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-cu|--chef_url= ]] && { CHEF_URL=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ci|--chef_ip= ]] && { CHEF_IPADDR=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-cp|--chef_pem= ]] && { CHEF_PEM=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ht|--ibm_contenthub_git_access_token= ]] && { CAMHUB_ACCESS_TOKEN=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-hh|--ibm_contenthub_git_host= ]] && { CAMHUB_HOST=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ho|--ibm_contenthub_git_organization= ]] && { CAMHUB_ORG=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-hc|--ibm_openhub_git_organization= ]] && { CAMHUB_OPEN_ORG=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ip|--ip_address= ]] && { IPADDR=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-si|--software_repo_ip= ]] && { SOFTWARE_REPO_IP=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-sr|--software_repo= ]] && { SOFTWARE_REPO=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-sp|--software_repo_port= ]] && { SOFTWARE_REPO_PORT=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-su|--software_repo_user= ]] && { SOFTWARE_REPO_USER=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-sp|--software_repo_pass= ]] && { SOFTWARE_REPO_PASS=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ip|--im_repo_pass= ]] && { IM_REPO_PASS=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-ip|--im_repo_user= ]] && { IM_REPO_USER=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-sv|--camc-sw-repo_version= ]] && { SOFTWARE_REPO_VERSION=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-pm|--pattern_mgr= ]] && { PATTERN_MGR=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-pmd|--ibm_pm_admin_token= ]] && { PATTERN_MGR_ADMIN_TOKEN=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-pmc|--ibm_pm_access_token= ]] && { PATTERN_MGR_ACCESS_TOKEN=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-pv|--camc-pattern-manager_version= ]] && { PATTERN_MGR_VERSION=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-pn|--private_network= ]] && { PRIVATE_NETWORK=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-re|--prereq_strictness= ]] && { PREREQ_STRICTNESS=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-n|--nfs_mount_point= ]] && { NFS_SERVER_IP_ADDR=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-tt|--template_timestamp= ]] && { TEMPLATE_TIMESTAMP=`echo $parameter|cut -f2- -d'='`; continue;  };
        [[ $parameter =~ ^-d|--debug$ ]] && { debug=true;  };
        [[ $parameter =~ ^-h|--help$ ]] && { help=true;  };
        #shift
done < $parmfile
set -o errexit

if [ "$help" == true ] ; then
  help
  exit 0
fi

if [ "$debug" == true ] ; then
	set -x
	export DEBUG="true"
fi
echo "[*] Template Timestamp: $TEMPLATE_TIMESTAMP"
end_message "Successful"

begin_message "Requirements Checker"
# Check and install pre-requisites
chmod +x $runtimepath/prereq-check-install.sh
chmod +x $runtimepath/verify-installation.sh
$runtimepath/prereq-check-install.sh "$PREREQ_STRICTNESS" "$CHEF_VERSION" "$CAM_PUBLIC_KEY" "$CAM_PRIVATE_KEY_ENC" "$DOCKER_EE_REPO"
end_message "Successful"

begin_message "Disk"
FSTAB_FILE="/etc/fstab"

MOUNT_POINT="/opt/ibm/docker/software-repo"
REPO_DIR=$MOUNT_POINT/var/swRepo/private
if [[ ! -e $parmdir/mounts_setup.done ]] ; then
  case $NFS_SERVER_IP_ADDR in
    "format"|"local")
      # Allocate the software repo disk
      allocate_software_disk
      ;;
    "*")
      if [[ $platform == *"ubuntu"* ]]; then
        sudo apt-get -y install nfs-common # set the common mount point
      fi
      if [[ $platform == *"redhat"* ]] || [[ $platform == *"centos"* ]]; then
        sudo yum -y install nfs-utils
      fi
      echo  "$NFS_SERVER_IP_ADDR /nfsmnt nfs4 rsize=1048576,hard,timeo=600,retrans=2,ro 0 0"  | sudo tee -a $FSTAB_FILE
      # run the mount command here, to allow for the docker container to access
      sudo mkdir /nfsmnt
      sudo mount /nfsmnt
      # Sym-link the software repo
      [[ ! -e $MOUNT_POINT/var/ ]] &&  sudo mkdir -p $MOUNT_POINT/var/
      sudo ln -s /nfsmnt/software-repo/var/swRepo/ $MOUNT_POINT/var/swRepo
  esac
  touch $parmdir/mounts_setup.done
  sudo df -Th # debug
fi
end_message "Successful"

#Install docker engine
begin_message Docker
if [[ ! `sudo ls /etc/docker/daemon.json 2>/dev/null` ]]; then
        sudo groupadd docker || echo ""
        sudo usermod -aG docker $USER # even though we have added the user to the group, it will not take effect on this pid/process
        # Check to see if the docker service is running
        [[ `which systemctl` ]] && { sudo systemctl stop docker || true ; } || { sudo service docker stop || true ; }
        docker_disk
        [[ `which systemctl` ]] && sudo systemctl start docker || sudo service docker start
fi
end_message "Successful"

begin_message Environment
OFFLINE="false"
# Check for internet collection
[[ `ping -c 3 -w 10 www.ibm.com | egrep "0 received,"` ]] && OFFLINE="true" || OFFLINE="false"

# The main difference between aws and other is the network and getting some information
# This line will determine if the machine is in AWS, if so, it must curl the IPAddress. Otherwise the code will sed its way thru the ip addr return removing all local, and private IPs to find the public IP
[[  "`grep amazon /sys/devices/virtual/dmi/id/bios_version`" ]] && environment="aws" || environment="other"
[[ ! "$IPADDR" = "dynamic" ]] && environment="static"
setup_"$environment"_"$PRIVATE_NETWORK"
[[ `egrep static_ip_address $parmfile` ]] && sed -i "s/--static_ip_address.*/--static_ip_address=$IPADDR/" $parmfile || echo "--static_ip_address=$IPADDR" >> $parmfile

# set values which were not provided as parameters
[[ -z "$CHEF_IPADDR" ]] && CHEF_IPADDR=$IPADDR
[[ -z "$CHEF_HOST" ]] && CHEF_HOST="chef-server-"`echo $IPADDR | tr -d '.'`
[[ -z "$SOFTWARE_REPO_IP" ]] && SOFTWARE_REPO_IP=$IPADDR
[[ -z "$SOFTWARE_REPO" ]] && SOFTWARE_REPO="software-repo-"`echo $IPADDR | tr -d '.'`
[[ -z "$PATTERN_MGR" ]] && PATTERN_MGR="pattern-"`echo $IPADDR | tr -d '.'`

if [[ "$CONFIGURATION" = "single-node" ]] ; then
     # If this is a local install of chef, we need to get the name of the machine from the VM, and not allow input
      CHEF_HOST=$HOSTNAME # Set the host name to the VM
fi

[[ -z "$DOMAIN" ]] && { CHEF_HOST_FQDN=$CHEF_HOST ; SOFTWARE_REPO_FQDN=$SOFTWARE_REPO ; PATTERN_MGR_FQDN=$PATTERN_MGR ; } || { CHEF_HOST_FQDN=$CHEF_HOST.$DOMAIN ; SOFTWARE_REPO_FQDN=$SOFTWARE_REPO.$DOMAIN ; PATTERN_MGR_FQDN=$PATTERN_MGR.$DOMAIN ; }

# Setup the path to images ... we support other repos
dockerhub="ibmcom"
otherhub="$DOCKER_REGISTRY/$DOCKER_IMAGE_PATH"
if [ $DOCKER_REGISTRY = "hub.docker.com" ] ; then # if the registry is docker
	DOCKER_REGISTRY_PATH="$dockerhub"
	DOCKER_REGISTRY_TOKEN="" # This line can be removed, it is a temp fix for a logging issue
else
	DOCKER_REGISTRY_PATH="$otherhub"
fi

platform=`cat /etc/*release 2>/dev/null| egrep "^ID=" | cut -d '=' -f 2- | tr -d '"'`
end_message "Successful"

begin_message Chef
# This is a chef installed locally, and that the setup has not been run already
if [[ "$CONFIGURATION" = "single-node" ]] && [[ ! -e $parmdir/chef_setup.done ]] ; then
  # Install chef local on VM
      export HOSTNAME=$HOSTNAME
      export ORG_NAME=$CHEF_ORG
      export ADMIN_NAME=$CHEF_ADMIN
      export ADMIN_MAIL=donotreply@ibm.com
      export CHEF_LOG=$parmdir/chef-install.log
      [[ -z "$CHEF_ADMIN_PASSWORD" ]] && export ADMIN_PASSWORD='' || export ADMIN_PASSWORD="$CHEF_ADMIN_PASSWORD"
      [[ -z "$CHEF_SSL_CERT_COUNTRY" ]] && export SSL_CERT_COUNTRY='' || export SSL_CERT_COUNTRY="$CHEF_SSL_CERT_COUNTRY"
      [[ -z "$CHEF_SSL_CERT_STATE" ]] && export  SSL_CERT_STATE='' || export SSL_CERT_STATE="$CHEF_SSL_CERT_STATE"
      [[ -z "$CHEF_SSL_CERT_CITY" ]] && export  SSL_CERT_CITY='' || export SSL_CERT_CITY="$CHEF_SSL_CERT_CITY"
      chmod +x $runtimepath/setupchef.sh
      sudo cp $runtimepath/setupchef.sh /opt/
      sudo cp $runtimepath/chef-server.rb /opt/
      sudo -E /opt/setupchef.sh
      touch $parmdir/chef_setup.done
fi

end_message "Successful"

begin_message Certs
CERTS_PATH="/opt/ibm/docker/pattern-manager/certs"
if [ ! -d $CERTS_PATH ] || [ ! "$(ls -A $CERTS_PATH)" ]; then
    echo "creating certs directory"
    sudo mkdir -p $CERTS_PATH
else
    echo "certs already exists in the path"
fi
end_message "Successful"

begin_message "Pattern Manager"
#Create SSH-Keys for Patter-Manager
CHEF_PEM_LOC="/etc/opscode/$CHEF_ADMIN.pem"
CONFIG_PATH="/opt/ibm/docker/pattern-manager/config"
if [ ! -d $CONFIG_PATH ] || [ ! -e "$parmdir/pm_config.done" ]; then
    echo "Creating Config Directory"
    sudo mkdir -p $CONFIG_PATH

    #Create the Private/Public Keys for Pattenr-Manager
    echo $CAM_PRIVATE_KEY_ENC | sudo tee $CONFIG_PATH/cam_runtime_key_`hostname`

    #Config File Creation Script
    chmod +x $runtimepath/crtconfig.py
    sudo python $runtimepath/crtconfig.py $PATTERN_MGR_ACCESS_TOKEN $PATTERN_MGR_ADMIN_TOKEN -c=encoded $CONFIG_PATH/cam_runtime_key_`hostname` $CHEF_PEM_LOC $CHEF_HOST_FQDN $CHEF_ORG $CHEF_IPADDR $CHEF_ADMIN $SOFTWARE_REPO_IP $SOFTWARE_REPO_PORT $CONFIG_PATH/config.json
    touch $parmdir/pm_config.done
else
    echo "Config File Already Exists in the Path"
fi

# Add the users key to the authorized keys on the system
[[ ! -e ~/.ssh ]] && { mkdir -p ~/.ssh/ ; chmod 700 ~/.ssh; }
echo $USER_PUBLIC_KEY >> ~/.ssh/authorized_keys
end_message "Successful"

begin_message "Software Repository"
AUTH_FILE_PATH="/opt/ibm/docker/software-repo/etc/nginx/auth"
if [[ ! -s $AUTH_FILE_PATH/.secure_softwarerepo ]];  then
    echo "creating Auth file directory and auth file"
    sudo mkdir -p $AUTH_FILE_PATH
    echo -n "$SOFTWARE_REPO_USER:" | sudo tee $AUTH_FILE_PATH/.secure_softwarerepo
    echo $SOFTWARE_REPO_PASS | openssl passwd -apr1 -stdin | sudo tee --append $AUTH_FILE_PATH/.secure_softwarerepo
else
    echo "Auth file already exists in the path"
fi

AUTH_CERT_PATH="/opt/ibm/docker/software-repo/etc/nginx/server-certs/"
if [[ ! -s $AUTH_CERT_PATH/secure_swrepo.key ]] ; then
   echo "create Cert file directory, and move the files"
   sudo mkdir -p $AUTH_CERT_PATH
else
  echo "Software Repository Certificates already exist."
fi
end_message "Successful"

begin_message "Docker images"
REPOSERVER_FSTAB_FILE="/opt/ibm/docker/software-repo/etc/fstab"
echo "# Empty FSTAB File as Mount IP Address as passed as N/A" | sudo tee $REPOSERVER_FSTAB_FILE

# Based on the CONFIGURATION Build the docker-compose file
if [ "$CONFIGURATION" = "single-node" ] ; then
  cp $runtimepath/infra-docker-compose.tmpl $runtimepath/docker-compose.yml
  cat $runtimepath/camc-sw-repo.tmpl >> $runtimepath/docker-compose.yml
  cat $runtimepath/camc-pattern-manager.tmpl >> $runtimepath/docker-compose.yml
else
  cp $runtimepath/infra-docker-compose.tmpl $runtimepath/docker-compose.yml
  cat $runtimepath/$CONFIGURATION.tmpl >> $runtimepath/docker-compose.yml
fi

sed -i.bak "s|\$CHEF_ADMIN|$CHEF_ADMIN|; \
    s|\$CHEF_ORG|$CHEF_ORG|; \
    s|\$CHEF_HOST_FQDN|$CHEF_HOST_FQDN|; \
    s|\$CHEF_IPADDR|$CHEF_IPADDR|; \
    s|\$CHEF_VERSION|$CHEF_VERSION|; \
    s|\$SOFTWARE_REPO_IP|$SOFTWARE_REPO_IP|; \
    s|\$SOFTWARE_REPO_FQDN|$SOFTWARE_REPO_FQDN|; \
    s|\$SOFTWARE_REPO_PORT|$SOFTWARE_REPO_PORT|; \
    s|\$SOFTWARE_REPO_VERSION|$SOFTWARE_REPO_VERSION|; \
    s|\$PATTERN_MGR_FQDN|$PATTERN_MGR_FQDN|; \
    s|\$PATTERN_MGR_VERSION|$PATTERN_MGR_VERSION|; \
    s|\$DOCKER_REGISTRY_PATH|$DOCKER_REGISTRY_PATH|; \
    s|\$DOCKER_REGISTRY|$DOCKER_REGISTRY|" \
    $runtimepath/docker-compose.yml

# Update the pattern manager to load the software repo
sed "s|\$CAMHUB_ACCESS_TOKEN|$CAMHUB_ACCESS_TOKEN|; \
     s|\$CAMHUB_HOST|$CAMHUB_HOST|; \
     s|\$CAMHUB_ORG|$CAMHUB_ORG|" $runtimepath/load.tmpl > $runtimepath/load.json

end_message "Successful"

begin_message "Docker Start"
docker_compose_CMD=$(echo `which docker-compose`)
if [ ! -z "$DOCKER_REGISTRY_TOKEN" ] ; then
  # A docker token was passed in on the call, generate the file
  dockerdir=`eval echo ~`/.docker
  [[ ! -e "$dockerdir" ]] && mkdir $dockerdir
  echo -e '{\n\t"auths": {\n\t\t"$DOCKER_REGISTRY": {\n\t\t\t"auth": "$DOCKER_REGISTRY_TOKEN"\n\t\t}\n\t}\n}' | sed "s|\"\$DOCKER_REGISTRY\"|\"$DOCKER_REGISTRY\"|; s|\"\$DOCKER_REGISTRY_TOKEN\"|\"$DOCKER_REGISTRY_TOKEN\"|" > ~/.docker/config.json
fi
# The sudo su $USER is to become the user which includes the inclusion in the docker group
sudo su $USER -c "$docker_compose_CMD -f $runtimepath/docker-compose.yml down" # shut down incase were are re-enterant

# Check if images exist locally, if not, download them
if [[ $OFFLINE == *"true"* ]] && [[ "$(sudo docker images -q $DOCKER_REGISTRY_PATH/camc-pattern-manager:$PATTERN_MGR_VERSION 2> /dev/null)" == "" ]] && [[ "$(sudo docker images -q $DOCKER_REGISTRY_PATH/camc-sw-repo:$SOFTWARE_REPO_VERSION 2> /dev/null)" == "" ]]; then
  echo "[*] Docker images found"
else
  sudo su $USER -c "$docker_compose_CMD -f $runtimepath/docker-compose.yml pull > /dev/null"
fi
sudo su $USER -c "$docker_compose_CMD -f $runtimepath/docker-compose.yml up -d"
end_message "Successful"

begin_message "Cookbooks"
# chef-user who is not defined at the OS level needs write access to the pattern folder.
sudo chmod o+rw /var/log/ibm/docker/pattern-manager/
if [[ $CONFIGURATION = "single-node" ]] ; then
	# For sure on the single-node, we want to wait for the docker chef to start, then restart the pattern-manager
	# for the other configruations, the restart is handled in the templated, waiting for the pem file to be written
	pemfile="/opt/ibm/docker/chef-server/etc/opscode/$CHEF_ADMIN.pem"
	count=0
	sleep 20 # The chef server needs a little time before servicing requests
	# Call to the pattern manager for the initialization of the cookbooks
	echo "Update the cookbooks on chef server"
	echo curl --write-out %{http_code} --output /dev/null --request POST -k -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization:Bearer $PATTERN_MGR_ACCESS_TOKEN" https://localhost:5443/v1/upload/chef/git_hub --data @$runtimepath/load.json
	response=`curl --write-out %{http_code} --output /dev/null --request POST -k -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization:Bearer $PATTERN_MGR_ACCESS_TOKEN" https://localhost:5443/v1/upload/chef/git_hub --data @$runtimepath/load.json`
	echo "Return from the curl command : $response"
	curl -k -H "Authorization:Bearer $PATTERN_MGR_ACCESS_TOKEN" -X GET https://localhost:5443/v1/info/chef
fi
end_message "Successful"

begin_message "Docker Containers"
sudo docker ps -a
end_message "Successful"

begin_message "Verify Installation"
$runtimepath/verify-installation.sh
end_message "Successful"
EndOfFile
    destination = "./advanced-content-runtime/launch-docker-compose.sh"
  }

  provisioner "remote-exec" {
    inline = [
        "chmod 775 ./advanced-content-runtime/launch-docker-compose.sh",
        "chmod 775 ./advanced-content-runtime/image-upgrade.sh",
        "bash -c \"./advanced-content-runtime/launch-docker-compose.sh ${var.network_visibility} --docker_registry_token='${var.docker_registry_token}'  --nfs_mount_point='${var.nfs_mount}' --software_repo_user='${var.ibm_sw_repo_user}' --software_repo_pass='${var.ibm_sw_repo_password}' --im_repo_user='${var.ibm_im_repo_user_hidden}' --im_repo_pass='${var.ibm_im_repo_password_hidden}'  --chef_host=chef-server --software_repo=software-repo --pattern_mgr=pattern --ibm_contenthub_git_access_token='${var.ibm_contenthub_git_access_token}' --ibm_contenthub_git_host='${var.ibm_contenthub_git_host}' --ibm_contenthub_git_organization='${var.ibm_contenthub_git_organization}' --ibm_openhub_git_organization='${var.ibm_openhub_git_organization}' --chef_org='${var.chef_org}' --chef_admin='${var.chef_admin}' --docker_registry='${var.docker_registry}' --chef_version=${var.chef_version} --ibm_pm_access_token='${var.ibm_pm_access_token}' --ibm_pm_admin_token='${var.ibm_pm_admin_token}' --camc-sw-repo_version='${var.docker_registry_camc_sw_repo_version}' --docker_ee_repo='${var.docker_ee_repo}' --camc-pattern-manager_version='${var.docker_registry_camc_pattern_manager_version}' --docker_configuration=single-node --ibm_pm_public_ssh_key_name='${var.ibm_pm_public_ssh_key_name}' --ibm_pm_private_ssh_key='${var.ibm_pm_private_ssh_key}' --ibm_pm_public_ssh_key='${var.ibm_pm_public_ssh_key}' --user_public_ssh_key='${var.user_public_ssh_key}' --prereq_strictness='${var.prereq_strictness}' --ip_address='${var.ipv4_address}' --template_timestamp='${var.template_timestamp_hidden}'\""
      ]
   }
}

### VMware output variables
  output "ip_address" {
  value = "${var.ipv4_address}" }
  output "ibm_sw_repo" {
  value = "https://${var.ipv4_address}:9999" }
  output "ibm_im_repo" {
  value = "https://${var.ipv4_address}:9999/IMRepo" }
  output "ibm_pm_service" {
  value = "https://${var.ipv4_address}:5443" }
  output "ibm_im_repo_user" {
  value = "${var.ibm_sw_repo_user}" }
  output "ibm_im_repo_password" {
  value = "${var.ibm_sw_repo_password}" }
  output "template_timestamp" {
  value = "2017-10-09 18:53:59" }
### End VMware output variables

output "runtime_hostname" { value = "${var.runtime_hostname}"}
output "docker_registry_token" { value = "${var.docker_registry_token}"}
output "docker_registry" { value = "${var.docker_registry}"}
output "docker_registry_camc_pattern_manager_version" { value = "${var.docker_registry_camc_pattern_manager_version}"}
output "docker_registry_camc_sw_repo_version" { value = "${var.docker_registry_camc_sw_repo_version}"}
output "chef_version" { value = "${var.chef_version}"}
output "ibm_sw_repo_user" { value = "${var.ibm_sw_repo_user}"}
output "ibm_sw_repo_password" { value = "${var.ibm_sw_repo_password}"}
output "ibm_im_repo_user_hidden" { value = "${var.ibm_im_repo_user_hidden}"}
output "ibm_im_repo_password_hidden" { value = "${var.ibm_im_repo_password_hidden}"}
output "ibm_contenthub_git_access_token" { value = "${var.ibm_contenthub_git_access_token}"}
output "ibm_contenthub_git_host" { value = "${var.ibm_contenthub_git_host}"}
output "ibm_contenthub_git_organization" { value = "${var.ibm_contenthub_git_organization}"}
output "ibm_openhub_git_organization" { value = "${var.ibm_openhub_git_organization}"}
output "chef_org" { value = "${var.chef_org}"}
output "chef_admin" { value = "${var.chef_admin}"}
output "ibm_pm_access_token" { value = "${var.ibm_pm_access_token}"}
output "ibm_pm_admin_token" { value = "${var.ibm_pm_admin_token}"}
output "network_visibility" { value = "${var.network_visibility}"}
output "ibm_pm_public_ssh_key_name" { value = "${var.ibm_pm_public_ssh_key_name}"}
output "ibm_pm_private_ssh_key" { value = "${var.ibm_pm_private_ssh_key}"}
output "ibm_pm_public_ssh_key" { value = "${var.ibm_pm_public_ssh_key}"}
output "user_public_ssh_key" { value = "${var.user_public_ssh_key}"}
output "docker_ee_repo" { value = "${var.docker_ee_repo}"}
output "template_timestamp_hidden" { value = "${var.template_timestamp_hidden}"}
output "vsphere_datacenter" { value = "${var.vsphere_datacenter}"}
output "vsphere_cluster" { value = "${var.vsphere_cluster}"}
output "vsphere_folder" { value = "${var.vsphere_folder}"}
output "vsphere_datastore" { value = "${var.vsphere_datastore}"}
output "runtime_domain" { value = "${var.runtime_domain}"}
output "cores" { value = "${var.cores}"}
output "memory" { value = "${var.memory}"}
output "nfs_mount" { value = "${var.nfs_mount}"}
output "vsphere_dns" { value = "${var.vsphere_dns}"}
output "disk1_template" { value = "${var.disk1_template}"}
output "disk2_name" { value = "${var.disk2_name}"}
output "disk2_size" { value = "${var.disk2_size}"}
output "network_label" { value = "${var.network_label}"}
output "ipv4_address" { value = "${var.ipv4_address}"}
output "ipv4_gateway" { value = "${var.ipv4_gateway}"}
output "ipv4_prefix_length" { value = "${var.ipv4_prefix_length}"}
output "vmware_image_ssh_user" { value = "${var.vmware_image_ssh_user}"}
output "vmware_image_ssh_password" { value = "${var.vmware_image_ssh_password}"}
output "vmware_image_ssh_private_key" { value = "${var.vmware_image_ssh_private_key}"}
output "prereq_strictness" { value = "${var.prereq_strictness}"}
