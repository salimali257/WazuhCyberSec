{\rtf1\ansi\ansicpg1252\cocoartf1504\cocoasubrtf830
{\fonttbl\f0\fnil\fcharset0 Menlo-Regular;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;}
{\*\expandedcolortbl;;\csgray\c0;}
\margl1440\margr1440\vieww10800\viewh8400\viewkind0
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardirnatural\partightenfactor0

\f0\fs22 \cf2 \cb1 \CocoaLigature0 #!/bin/bash\
# Script for automatic installation of Wazuh agent\
\
MANAGER_IP=$1\
AUTHD_PORT="1515"\
GROUP="ces"\
\
# Confirm that Wazuh is not installed\
\
if [ -d /var/ossec ]\
then\
    echo "Directory /var/ossec already exists. Exiting."\
    exit\
fi\
\
# Detect release type\
\
if [ -f /etc/redhat-release ]\
then\
    RELEASE="/etc/redhat-release"\
\
    # Confirm that package is not installed\
\
    if rpm -qa | grep -q 'wazuh-agent'\
    then\
        echo "Package wazuh-agent already installed. Exiting."\
        exit\
    elif grep -q "CentOS" $RELEASE\
    then\
        cat > /etc/yum.repos.d/wazuh.repo <<\\EOF\
[wazuh_repo]\
gpgcheck=1\
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\
enabled=1\
name=CentOS-$releasever - Wazuh\
baseurl=https://packages.wazuh.com/3.x/yum-dev/el/$releasever/$basearch\
protect=1\
EOF\
    elif grep -q "Fedora" $RELEASE\
    then\
        cat > /etc/yum.repos.d/wazuh.repo <<\\EOF\
[wazuh_repo]\
gpgcheck=1\
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\
name=Fedora-$releasever - Wazuh\
enabled=1\
baseurl=https://packages.wazuh.com/3.x/yum-dev/fc/$releasever/$basearch\
protect=1\
EOF\
    else\
        cat > /etc/yum.repos.d/wazuh.repo <<\\EOF\
[wazuh_repo]\
gpgcheck=1\
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\
enabled=1\
name=RHEL-$releasever - Wazuh\
baseurl=https://packages.wazuh.com/3.x/yum-dev/rhel/$releasever/$basearch\
protect=1\
EOF\
    fi\
\
    yum -y install wazuh-agent\
\
    if [ "$?" != "0" ]\
    then\
        exit 1\
    fi\
elif ( [ -f /etc/os-release ] && grep -q "debian" /etc/os-release ) || [ -f /etc/debian_version ]\
then\
    echo "Debian OS detected. Not installing."\
    exit 1\
fi\
\
# Registering agent\
/var/ossec/bin/agent-auth -m $\{MANAGER_IP\} -p $\{AUTHD_PORT\}\
\
# Get Agent ID\
AGENT_ID=`cat /var/ossec/etc/client.keys | cut -f1 -d' '`\
\
# Configuring agent - Server IP\
sed -i "s/<address>MANAGER_IP<\\/address>/<address>$\{MANAGER_IP\}<\\/address>/" \\\
/var/ossec/etc/ossec.conf\
\
# Configuring agent - Internal options\
sed -i "s/syscheck.sleep=2/syscheck.sleep=0/" \\\
/var/ossec/etc/internal_options.conf\
\
sed -i "s/logcollector.remote_commands=0/logcollector.remote_commands=1/" \\\
/var/ossec/etc/internal_options.conf\
\
# Load quarantine.sh script for Active Response\
cp /home/centos/quarantine.sh /var/ossec/active-response/bin/\
chown root:ossec /var/ossec/active-response/bin/quarantine.sh\
\
# Auto assign group\
curl -XPUT https://$\{MANAGER_IP\}:55000/agents/$\{AGENT_ID\}/group/$\{GROUP\} -k -u wazuh:wazuh\
\
# Starting agent\
/var/ossec/bin/ossec-control start\
\
# Checking connection\
sleep 3\
if grep "Connected to the server" /var/ossec/logs/ossec.log > /dev/null; then\
  echo "Agent successfully installed, registered, and connected to the manager."\
else\
  echo "Agent didn't get to connect to the manager. Please check installation and configuration."\
fi}