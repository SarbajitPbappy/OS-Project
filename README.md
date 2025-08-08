DHCP Client-Server Communication Project

📌 Overview
This project implements a custom DHCP (Dynamic Host Configuration Protocol) client-server communication system using Bash scripts. It simulates a DHCP client requesting and obtaining an IP address from a DHCP server, enabling dynamic network configuration. The system also includes a basic messaging mechanism using MAC addresses for device identification.
Developed as a group project for our Operating Systems course.

👥 Group Members



Name
ID



Sarbajit Paul Bappy
222-15-6155


Rittik Chandra Das Turjy
222-15-6289


Maruf Rahman
222-15-6212


Most. Jannatul Firdousi Zoti
222-15-6145


Istiak Ahmed Shanto
222-15-6225



✨ Features

Sends DHCPDISCOVER and receives DHCPOFFER
Assigns IP address via DHCPREQUEST and confirms with DHCPACK
Retrieves hardware (MAC) address
Sends messages to devices using MAC address
Modular Bash scripts for ease of use
Compatible with Linux-based systems (tested on Ubuntu & VirtualBox)


📂 Project Structure
OSProject Using bash/
├── bash_scripts/
│   ├── dhcp_client_request.sh   # DHCP client implementation
│   ├── get_mac_address.sh       # Fetch MAC address
│   ├── send_message.sh          # Send a message to a given MAC address
│   ├── helpers.sh               # Common functions and utilities
├── README.md                    # Project documentation


🛠️ Requirements

Linux-based OS (Ubuntu recommended)
bash shell
dhclient (for DHCP functionality)
ip or ifconfig command
Network interface in bridged or NAT mode (for VMs)


🚀 Setup and Usage
1️⃣ Clone the Repository
git clone https://github.com/your-username/dhcp-client-server.git
cd dhcp-client-server/bash_scripts

2️⃣ Run the DHCP Client Script
chmod +x dhcp_client_request.sh
./dhcp_client_request.sh

Expected Output:
DHCPDISCOVER on enp0s3 to 255.255.255.255 port 67
DHCPOFFER of 192.168.x.x from 192.168.x.x
DHCPREQUEST for 192.168.x.x
DHCPACK of 192.168.x.x
bound to 192.168.x.x -- renewal in XXXX seconds

3️⃣ Get Your MAC Address
chmod +x get_mac_address.sh
./get_mac_address.sh

4️⃣ Send a Message to Another Device
chmod +x send_message.sh
./send_message.sh

Follow the prompts to:

Enter the recipient's MAC address
Input your message
Send the message over the network


📊 Workflow Diagram

sequenceDiagram
    participant Client
    participant Server
    Client->>Server: DHCPDISCOVER
    Server->>Client: DHCPOFFER
    Client->>Server: DHCPREQUEST
    Server->>Client: DHCPACK


⚠️ Notes

The interface name (enp0s3) may vary. Use ip link to identify the correct interface.
If you see No active DHCP lease found, verify:
Network connectivity
DHCP server is running
Correct interface name in scripts




📜 License
This project is for educational purposes only under the guidelines of our Operating Systems course.

🔮 Future Improvements

Develop a full server-side Bash script
Support multiple simultaneous clients
Enhance error handling for network issues
Create a GUI for visualizing DHCP messages


🙌 Acknowledgments

Thanks to our Operating Systems course instructor for guidance
Built with ❤️ by the team
