import socket
import re
import threading as t
import time
import requests as r
import os
from PyEnhance import Stamps, Loading, Counter

Stamp = Stamps.Stamp
Loading = Loading.Loading
Counter = Counter.Counter

Input = Stamp.Input
Output = Stamp.Output
Error = Stamp.Error
Info = Stamp.Info






def main():
    global CommonPortsDict
    class ListsAndDicts:
        global OpenPortsList, CommonPortsDict, CommonPortOutputList, UnknownPortOutputList
        global OpenPortsListFilteredAndDone, Replace
        CommonPortOutputList = []
        UnknownPortOutputList = []
        OpenPortsList = []
        OpenPortsListFilteredAndDone = []
        Replace = ["[", "]", "'", ",", "(", ")"]

        CommonPortsDict = {
            1: 'TCPMUX', 5: 'RJE', 7: 'ECHO', 9: 'DISCARD',
            11: 'SYSTAT', 13: 'DAYTIME', 17: 'QOTD', 18: 'MSP',
            19: 'CHARGEN', 20: 'FTP_DATA', 21: 'FTP_CONTROL', 22: 'SSH',
            23: 'TELNET', 25: 'SMTP', 37: 'TIME', 42: 'NAMESERVER',
            43: 'WHOIS', 49: 'TACACS', 53: 'DNS', 67: 'DHCP_CLIENT',
            68: 'DHCP_SERVER', 69: 'TFTP', 70: 'Gopher', 79: 'Finger',
            80: 'HTTP', 88: 'Kerberos', 102: 'MS Exchange', 110: 'POP3',
            113: 'IDENT', 119: 'NNTP', 123: 'NTP', 135: 'RPC',
            137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN', 143: 'IMAP',
            161: 'SNMP', 179: 'BGP', 194: 'IRC', 201: 'AppleTalk',
            220: 'IMAP3', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
            464: 'Kerberos Change/Set password', 465: 'SMTPS', 500: 'ISAKMP', 514: 'Syslog',
            520: 'RIP', 530: 'RPC', 543: 'Kerberos (klogin)', 544: 'Kerberos (kshell)',
            546: 'DHCPv6 Client', 547: 'DHCPv6 Server', 554: 'RTSP', 587: 'SMTP (Message Submission)',
            631: 'Internet Printing Protocol (IPP)', 636: 'LDAPS', 873: 'rsync', 902: 'VMware Server Console',
            989: 'FTPS (data)', 990: 'FTPS (control)', 993: 'IMAPS', 995: 'POP3S',
            1025: 'Microsoft RPC', 1433: 'Microsoft SQL Server', 1434: 'Microsoft SQL Monitor',
            1521: 'Oracle database default listener',
            1723: 'PPTP', 1724: 'PPTP', 2049: 'NFS', 2082: 'cPanel',
            2083: 'cPanel', 2181: 'ZooKeeper', 2222: 'DirectAdmin', 3306: 'MySQL',
            3389: 'RDP', 3690: 'SVN', 4333: 'mSQL', 4444: 'Metasploit',
            5060: 'SIP', 5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB',
            6379: 'Redis', 6667: 'IRC', 6881: 'BitTorrent', 8000: 'HTTP alternate',
            8080: 'HTTP alternate', 8443: 'HTTPS alternate', 8888: 'HTTP alternate', 9000: 'SonarQube',
            9090: 'Openfire Administration Console', 9200: 'Elasticsearch', 9300: 'Elasticsearch', 9418: 'Git',
            27017: 'MongoDB', 27018: 'MongoDB', 27019: 'MongoDB', 50000: 'SAP',
            50070: 'Hadoop NameNode', 50075: 'Hadoop DataNode', 50090: 'Hadoop Secondary NameNode', 5601: 'Kibana',
            5985: 'WinRM (Windows Remote Management)', 7077: 'Apache Spark', 9091: 'Transmission (BitTorrent client)',
            10000: 'Webmin (Web-based interface for system administration)',
            11211: 'Memcached', 28017: 'MongoDB Web Status Page', 3260: 'iSCSI',
            51413: 'Transmission (BitTorrent client)',
            64738: 'Mumble (Voice chat protocol)'
        }


    URLorIP = input(f'{Input} Please Enter URL Or IP To Scan: ')

    print('\n')

    print(f"""Please Choose Scan Type:

    [1] Common Scan
    [2] Full Scan
    [3] Custom Range (0 to 65535)""")

    print('\n')

    ScanTypeChoice = input(f'{Input} Please Choose Scan Type: ')
    def ScanTypeInputs():
        global URLorUP
        global Redo


        if ScanTypeChoice == '1':
            global CommonRange

            CommonRange = True

        if ScanTypeChoice == '2':
            CommonRange = False
            global PortRangeInt
            PortRangeInt = 65535

        if ScanTypeChoice == '3':
            CommonRange = False
            PortRangeInt = input(f'{Input} Please Enter Max Range: ')
            if not PortRangeInt.isdigit():
                print(f'{Error} Port number must be a single number for example if you set 100 as the max range this program will scan ports 0 through 100')
                ScanTypeInputs()


    ScanTypeInputs()

    def Scan(port=int):
        def HostToScan():
            global host
            host = URLorIP

            def HostInputChecks():
                pass
            HostInputChecks()

        HostToScan()

        def ScanPorts(port):
            global OpenPortsList  # tell Python we're using the global list
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                s.connect((host, port))
                OpenPortsList.append(port)

            except:
                pass

            finally:
                s.close()

        threads = []

        if CommonRange is True:
            for port in CommonPortsDict.keys():
                thread = t.Thread(target=ScanPorts, args=(port,))
                thread.start()
                threads.append(thread)
        else:
            for port in range(0, int(PortRangeInt)):
                thread = t.Thread(target=ScanPorts, args=(port,))
                thread.start()
                threads.append(thread)

        for thread in threads:
            thread.join()


        def Outputs():

            def PortsCheck():
                for port in OpenPortsList:
                    if port in CommonPortsDict.keys():
                        CommonPortOutput = (
                            f"port {port} is open this port is used for {CommonPortsDict.get(port)}")
                        CommonPortOutputList.append(CommonPortOutput)
                    else:
                        UnknownPortOutput = (f"port {port} is open its use can not be identified by this program")
                        UnknownPortOutputList.append(UnknownPortOutput)

            def ConsoleOutput():
                global CommonPortOutputFiltered
                global CommonPortOutputFilteredDone
                for i in (CommonPortOutputList):
                    CommonPortOutputFiltered = f"{i}"


                    for i in Replace:
                        CommonPortOutputFilteredDone = (CommonPortOutputFiltered.replace(i, ""))

                    print(f'\n{Output} {CommonPortOutputFilteredDone}')

                for i in (UnknownPortOutputList):
                    UnknownPortOutputFiltered = f"{i}"

                    for i in Replace:
                        UnknownPortOutputFilteredDone = (UnknownPortOutputFiltered.replace(i, ""))

                    print(f'\n{Output} {UnknownPortOutputFilteredDone}')

            PortsCheck()
            ConsoleOutput()
            def TxtOutput():
                if os.path.exists(f'{host}.txt'):
                    pass

                else:
                    with open(f'{host}.txt', 'x'):
                        pass

                with open(f'{host}.txt', 'w') as file:

                    for CommonPortOutput in CommonPortOutputList:

                        for i in Replace:
                            FilteredOutput = str(CommonPortOutput).replace(i, "")

                        file.write(f"{FilteredOutput}\n")

                    for UnknownPortOutput in UnknownPortOutputList:

                        for i in Replace:
                            FilteredOutputU = str(UnknownPortOutput).replace(i, "")
                        file.write(f"{FilteredOutputU}\n")

            TxtOutput()
        Outputs()
    Scan()




main()

# BirdScan 1.0.4
# A simple Python port scanner

# Not A Bird
# CEO of Bird Inc.
