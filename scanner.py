import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<----------------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n""")
print("You have selected option: ", resp)

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    if scanner[ip_addr].state() == 'up':
        print(scanner[ip_addr].all_protocols())
        if 'tcp' in scanner[ip_addr]:
            print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
        else:
            print("No open TCP ports found.")
    else:
        print("The IP is down or unreachable.")
elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    if scanner[ip_addr].state() == 'up':
        print(scanner[ip_addr].all_protocols())
        if 'udp' in scanner[ip_addr]:
            print("Open Ports: ", scanner[ip_addr]['udp'].keys())
        else:
            print("No open UDP ports found.")
    else:
        print("The IP is down or unreachable.")
elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    if scanner[ip_addr].state() == 'up':
        print(scanner[ip_addr].all_protocols())
        if 'tcp' in scanner[ip_addr]:
            print("Open TCP Ports: ", scanner[ip_addr]['tcp'].keys())
        else:
            print("No open TCP ports found.")
        if 'udp' in scanner[ip_addr]:
            print("Open UDP Ports: ", scanner[ip_addr]['udp'].keys())
        else:
            print("No open UDP ports found.")
    else:
        print("The IP is down or unreachable.")
elif resp >= '4':
    print("Please enter a valid option")
