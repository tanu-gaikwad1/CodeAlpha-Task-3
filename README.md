# CodeAlpha-Task-3
Network Intrusion Detection system :Develop a network based intrusion detection system using suricata. 
Step 1: Install Suricata on Kali Linux
Update Kali Linux:
Before installing Suricata, update your Kali Linux system to ensure all packages are up-to-date:
sudo apt update
sudo apt upgrade -y

Install Suricata:
Suricata can be installed directly from the Kali repositories. Use the following command to install it:
sudo apt install suricata -y

Verify Installation:
After installation, verify Suricata is installed correctly by checking its version:
suricata --version
This should return the version of Suricata installed on your system.

Step 2: Configure Suricata
Configure Network Interface:
Suricata needs to know which network interface to monitor. You can find the name of your network interface (e.g., eth0, wlan0) using the following command:
ip a

Edit Suricata Configuration:
Suricata’s configuration file is located at /etc/suricata/suricata.yaml.

Open it for editing:
sudo nano /etc/suricata/suricata.yaml
af-packet:
  - interface: eth0
Replace eth0 with the name of your network interface.

Set the HOME_NET Variable:

The HOME_NET variable defines the range of IP addresses that Suricata is monitoring. Set HOME_NET to your local network or IP address (e.g., 192.168.0.0/24):
home-net:
  - 192.168.53.232/24
Enable EVE JSON Output:

Suricata can output event logs in JSON format for easy integration with other tools or visualizations. To enable JSON output, find the eve.json section in the suricata.yaml file and make sure it’s uncommented and configured:
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
This will log alerts and network events in JSON format to /var/log/suricata/eve.json.

Step 3: Set Up Suricata Rules
Suricata comes with default rule sets, but you may want to update them to get the latest detection rules:
sudo suricata-update
This will download the latest rules from the Emerging Threats or other sources specified in the configuration.

Create Custom Rules:
You can also add your custom detection rules. Suricata rules are typically stored in /etc/suricata/rules/. Create a custom rules file (e.g., local.rules):
sudo nano /etc/suricata/rules/local.rules
Add custom rules to detect specific suspicious activities, for example:

Detect ICMP Echo Request (Ping):

text
Copy code
alert icmp any any -> $HOME_NET any (msg:"ICMP Echo Request"; itype:8; sid:1000001;)
Detect HTTP SQL Injection Attempt:

alert http $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"' OR 1=1 --"; http_uri; sid:1000002;)
Update Suricata Configuration to Include Local Rules:

Ensure that your custom rules are loaded by adding the following line to the suricata.yaml file in the default-rule-path section:
rule-files:
  - /etc/suricata/rules/local.rules
Step 4: Start Suricata to Monitor Traffic
Start Suricata in IDS Mode:

After configuring Suricata, you can start it in IDS mode (monitoring the traffic without dropping any packets):

sudo suricata -c /etc/suricata/suricata.yaml -i eth0
Replace eth0 with your network interface. Suricata will start monitoring traffic and generate alerts based on your rules.

Check the Suricata Logs:
cat /var/log/suricata/eve.json


