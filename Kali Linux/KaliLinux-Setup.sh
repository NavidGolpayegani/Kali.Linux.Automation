#!/bin/bash

# Effortlessly Install Applications on Kali Linux using a Custom Shell Script
# (C) 2023, by: Navid Golpayegani
# Karaj, Alborz - Iran


# Ncat is a powerful networking utility used to read and write data across networks using TCP or UDP protocols. It can be used for debugging, testing, and other networking tasks.
sudo apt-get install -y ncat

# Ndiff is a tool used to compare two Nmap scan results and identify differences between them, such as changes in open ports or services. It can be helpful for identifying potential security issues or changes in network configurations.
sudo apt-get install -y ndiff

# Nmap is a powerful network exploration and security auditing tool. It's used to discover hosts and services on a network, as well as to identify vulnerabilities and perform security scans. It's a very popular tool for network administrators and security professionals.
sudo apt-get install -y nmap

# nmap-common is a set of common files and data used by the Nmap suite of tools, including Nmap itself, as well as other tools such as Zenmap and Nping. It includes things like documentation, scripts, and data files that are necessary for the proper functioning of the tools.
sudo apt-get install -y nmap-common

# Hydra is a powerful tool for brute-forcing authentication credentials, such as passwords or usernames. It supports a wide range of protocols and services, and can be used for both legitimate purposes (such as testing the strength of passwords) and malicious purposes (such as trying to gain unauthorized access to systems). It's important to note that using Hydra for unauthorized access is illegal and unethical.
sudo apt-get install -y hydra

# Hydra-gtk is a graphical user interface (GUI) front-end for the Hydra tool. It provides a more user-friendly way to configure and launch Hydra brute-force attacks, making it easier for users who are not comfortable with command-line interfaces to use the tool.
sudo apt-get install -y hydra-gtk

# Metasploit Framework is a powerful and widely used open-source penetration testing tool that allows security professionals to identify and exploit vulnerabilities in networks, servers, and applications. It includes a comprehensive set of the modules and exploits that can be used to test the security of target systems. It also provides a command-line interface as well as a web-based user interface for ease of use.
sudo apt-get install -y metasploit-framework

# SQLmap is an open-source penetration testing tool used to detect and exploit SQL injection vulnerabilities in web applications. It automates the process of detecting and exploiting SQL injection flaws, making it easier and more efficient for security professionals to test the web applications for potential vulnerabilities. It can also be used for other tasks such as fingerprinting the database server and executing arbitrary SQL statements.
sudo apt-get install -y sqlmap

# Gobuster is a popular open-source tool used for directory and file brute-forcing on web servers. It is commonly used for discovering hidden files and directories, subdomains, and other web server resources that are not intended for public access. It can also be used for security testing and identifying potential vulnerabilities in web applications.
sudo apt-get install -y gobuster

# libwireshark-data is a package of data files used by the Wireshark network protocol analyzer, which allows users to capture and analyze network traffic in real-time. The package includes protocol definition files, display filter files, and other data files that are necessary for Wireshark to function properly.
sudo apt-get install -y libwireshark-data

# libwireshark-dev is a development package for the Wireshark network protocol analyzer. It includes header files, libraries, and other resources that developers can use to build applications that interact with Wireshark or extend its functionality. It is intended for use by developers who want to create custom dissectors or plugins for Wireshark.
sudo apt-get install -y libwireshark-dev

# libwireshark16 is a library package for the Wireshark network protocol analyzer. It provides shared libraries that are used by Wireshark and other applications that rely on the Wireshark library. It allows these applications to decode and analyze network traffic captured in various formats.
sudo apt-get install -y libwireshark16

# libwiretap-dev is a development package for the Wiretap library, which is a library used by the Wireshark network protocol analyzer to read and write various file formats. It includes header files, libraries, and other resources that developers can use to build applications that read or write network capture files in a variety of formats. It is intended for use by developers who want to create applications that can read or write packet capture files.
sudo apt-get install -y libwiretap-dev

# libwiretap13 is a library package for the Wiretap library, which is a library used by the Wireshark network protocol analyzer to read and write various file formats. It provides shared libraries that are used by Wireshark and other applications that rely on the Wiretap library to read and write packet capture files in various formats.
sudo apt-get install -y libwiretap13

# libwsutil-dev is a development package for the Wsutil library, which is a library used by the Wireshark network protocol analyzer to perform protocol analysis and packet dissection. It includes header files, libraries, and other resources that developers can use to build applications that analyze network traffic and dissect network protocols. It is intended for use by developers who want to create custom protocol dissectors or extend the functionality of the Wsutil library.
sudo apt-get install -y libwsutil-dev

# libwsutil14 is a library package for the Wsutil library, which is a library used by the Wireshark network protocol analyzer to perform protocol analysis and packet dissection. It provides shared libraries that are used by Wireshark and other applications that rely on the WsUtil library to analyze and dissect network protocols.
sudo apt-get install -y libwsutil14

# Tshark is a command-line network protocol analyzer that is part of the Wireshark network protocol analyzer suite. It allows users to capture and analyze network traffic in real-time or read network capture files and analyze them offline. Tshark is designed to be used in terminal-based environments and is particularly useful for scripting and automating network analysis tasks.
sudo apt-get install -y tshark

# Wireshark is a widely-used network protocol analyzer that allows users to capture, analyze, and interpret network traffic in real-time. It provides a graphical user interface (GUI) that displays detailed information about network packets, protocols, and conversations. Wireshark is often used by network administrators, security professionals, and developers to troubleshoot network issues, identify security vulnerabilities, and develop and test network applications.
sudo apt-get install -y wireshark

# Wireshark-common is a package that provides common files used by the Wireshark network protocol analyzer. It includes configuration files, icons, and other resources that are shared by all Wireshark components. The package is typically installed alongside the main Wireshark package and is required for the proper functioning of the Wireshark application.
sudo apt-get install -y wireshark-common

# Wireshark-dev is a development package for the Wireshark network protocol analyzer. It includes header files, libraries, and other resources that developers can use to build applications that interact with Wireshark or extend its functionality. It is intended for use by developers who want to create custom dissectors or plugins for Wireshark or build applications that capture and analyze network traffic.
sudo apt-get install -y wireshark-dev

# Wireshark-doc is a package that provides documentation and user guides for the Wireshark network protocol analyzer. It includes manuals, tutorials, and other resources that help users understand how to use Wireshark to capture, analyze, and interpret network traffic. The package is typically installed alongside the main Wireshark application and is useful for both new and experienced users.
sudo apt-get install -y wireshark-doc

# Wireshark-gtk is a package that provides a graphical user interface (GUI) for the Wireshark network protocol analyzer. It is designed for use in desktop environments that use the GTK+ toolkit, such as GNOME and Xfce. The package includes the same features and functionality as the main Wireshark application, but with a different interface that is optimized for use in a graphical environment.
sudo apt-get install -y wireshark-gtk

# Wireshark-qt is a package that provides a graphical user interface (GUI) for the Wireshark network protocol analyzer. It is designed for use in desktop environments that use the Qt toolkit, such as KDE and LXQt. The package includes the same features and functionality as the main Wireshark application, but with a different interface that is optimized for use in a graphical environment based on the Qt framework.
sudo apt-get install -y wireshark-qt

# Sherlock is a tool used for finding usernames across a variety of social media platforms. It is designed to help penetration testers and security professionals quickly and easily enumerate social media accounts associated with a particular person or organization. Sherlock works by automating the process of searching various social media platforms for account usernames, and it provides a report of the accounts it finds.
sudo apt-get install -y sherlock

# Cewl (pronounced "cool") is a tool used to generate custom wordlists by spidering a target website or document and extracting unique words and phrases. It can be used by security professionals to create custom password lists based on a target's known interests, such as hobbies or job-related terminology, which can then be used in password cracking or phishing attacks. Cewl can also be used for other purposes, such as data mining and content analysis.
sudo apt-get install -y cewl

# Aircrack-ng is a set of tools used to test the security of Wi-Fi networks by performing various types of attacks, such as packet sniffing, password cracking, and session hijacking. It includes tools for capturing and analyzing network traffic, as well as tools for testing the security of wireless networks by exploiting vulnerabilities in the Wi-Fi protocols. Aircrack-ng can be used by security professionals to evaluate the security of wireless networks and identify weaknesses that can be exploited by attackers.
sudo apt-get install -y aircrack-ng

# Airgraph-ng is a tool used to visualize wireless networks their characteristics based on data collected by tools such as Airodump-ng and tcpdump. It provides graphs and charts that help security professionals analyze and interpret network traffic data, including signal strength, channel utilization, and traffic patterns. Airgraph-ng can be used to identify potential network issues, detect suspicious activity, and optimize wireless network performance.
sudo apt-get install -y airgraph-ng

# WPScan is a tool used for scanning and detecting vulnerabilities in WordPress websites. It can be used by security professionals to identify security weaknesses in WordPress installations, including vulnerabilities in themes, plugins, and configurations. WPScan performs a wide range of tests, such as brute-forcing WordPress login credentials, enumerating user accounts, and detecting vulnerable plugins and themes. It can also be used to gather information about a target WordPress site, including its version, installed plugins, and active themes. WPScan is a popular tool among security researches and penetration testers who want to assess the security of WordPress sites.
sudo apt-get install -y wpscan

# DirBuster is a tool used for discovering hidden directories and files on web servers. It works by performing brute-force attacks on a target website to identify directories that are not linked from the site's main pages or sitemap. DisBuster uses a dictionary of common directory and file names, and it also allows users to create custom dictionaries to improve the accuracy of the search. DirBuster can be used by security professionals to identify hidden content on a website that may be used for malicious purposes, such as storing sensitive data or hosting malware.
sudo apt-get install -y dirbuster

# Wifite is a tool used for automated wireless network auditing. It can be used to perform various types of attacks against Wi-Fi networks, including capturing and analyzing network traffic, deauthenticating clients, cracking passwords, and conducting rogue access point attacks. Wifite automates the process of scanning for available wireless networks and selecting the appropriate attack for each network based on its security settings. It can be used by security professionals to test the security of wireless networks and identify vulnerabilities that can be exploited by attackers.
sudo apt-get install -y wifite

# Dirb is a tool used for discovering hidden directories and files on web servers. It works by performing brute-force attacks on a target website to identify directories that are not linked from the site's main pages or sitemap. Dirb uses a dictionary of common directory and file names, and it also allows users to create custom dictionaries to improve the accuracy of the search. Dirb is a simple and fast tool that can be used by security professionals to identify hidden content on a website that may be used for malicious purposes, such as storing sensitive data or hosting malware.
sudo apt-get install -y dirb

# Maltego is a powerful tool used for open-source intelligence (OSINT) and forensics. It allows users to gather and analyze information from various sources, such as social media, public records, and online communities, and the virtualize the relationships between the data using graphs and charts. Maltego has a user-friendly interface and offers a wide range of data-mining and visualization features, including link analysis, entity extraction, and geospatial mapping. It can be used by security professionals, law enforcement agencies, and intelligence analysts to investigate and solve various types of crimes and security incidents.
sudo apt-get install -y maltego

# Wordlists are collections of words and phrases used in password cracking and other security-related activities. They are often used in conjunction with brute-force attacks, where the attacker tries every possible combination of words, numbers, and symbols until the correct password is discovered. Wordlists can be created manually or generate automatically using tools that scrape websites, social media, and other online sources for commonly used passwords and phrases. They can also be customized to include specific words, languages, or other criteria. Wordlists are an essential tool for security professionals and penetration testers who need to test the strength of passwords and identify vulnerabilities in systems and applications.
sudo apt-get install -y wordlists

# Ettercap is a comprehensive suite for man-in-the-middle attacks (MiTM) that allows security professionals to monitor and manipulate network traffic. The Ettercap suite includes various modules and plugins, such as sniffers, filters, and injectors, that can be used to perform a wide range of attacks, including password sniffing, session hijacking, and protocol analysis. Ettercap-common is a package that includes the common files and libraries used by the Ettercap suite. It provides a set of tools that can be used by security professionals to test the security of networks and applications, and identify vulnerabilities that can be exploited by attackers.
sudo apt-get install -y ettercap-common

# Ettercap-graphical is a graphical user interface (GUI) for the Ettercap suite, which is a comprehensive suite for man-in-the-middle (MiTM) attacks that allows security professionals to monitor and manipulate network traffic. The GUI provides a user-friendly interface for configuring and launching various modules and plugins, such as sniffers, filters, and injectors, that can be used to perform a wide range of attacks, including password sniffing, session hijacking, and protocol analysis. Ettercap-graphical is an excellent tool for security professionals who prefer a visual interface to manage and monitor their network attacks.
sudo apt-get install -y ettercap-graphical

# Ettercap-text-only is a command-line interface (CLI) for the Ettercap suite, which is a comprehensive suite for man-in-the-middle (MiTM) attacks that allows security professionals to monitor and manipulate network traffic. The CLI provides a text-based interface for configuring and launching various modules and plugins, such as sniffers, filters, and injectors, the can be used to perform a wide range of attacks, including password sniffing, session hijacking, and protocol analysis. Ettercap-text-only is an excellent tool for security professionals who prefer a non-graphical interface to manage and monitor their network attacks.
sudo apt-get install -y ettercap-text-only

# BeEF (Browse Exploitation Framework) is a penetration testing tool that allows security professionals to test the security of web browsers and web applications by using various types of browser-based attacks. It is a client-server application that runs on Kali Linux and is used to exploit and control web browsers using various modules and plugins. BeEF-xss is an extension for the BeEF framework that adds cross-site scripting (XSS) capabilities, allowing security professionals to test the security of web applications that are vulnerable to XSS attacks. With BeEF-xss, security professionals can automate and execute various types of XSS attacks and analyze the results to identify and exploit vulnerabilities.
sudo apt-get install -y beef-xss

# Tcpdump is a command-line packet analyzer tool that is used for capturing and analyzing network traffic in real-time. It is a powerful tool that can be used to capture packets transmitted over the network and save them to a file for later analysis. Tcpdump is used by network administrators and security professionals to troubleshoot network issues, detect network intrusions, and monitor network activity. It can capture packets at the protocol level and provide detailed information about the contents of the packets, including the source and destination IP addresses, ports, and protocol information. Tcpdump is an essential tool for network analysis and troubleshooting.
sudo apt-get install -y tcpdump

# Subfinder is an open-source tool used for discovering subdomains of a given domain. It uses various techniques, such as search engines, DNS queries, and certificate transparency logs, to identify and enumerate subdomains. Subfinder is designed to be fast and efficient, and it can be used in conjunction with other tools, such as nmap and masscan, to gather information about the target domain. It can be especially useful for performing reconnaissance and identifying potential attack vectors during penetration testing or bug bounty hunting.
sudo apt-get install -y subfinder

# Crunch is a wordlist generator tool that can create custom wordlists for use in password cracking, WPA/WPA2 handshake cracking, and other security testing scenarios. It can generate wordlists of different sizes and combinations based on user-defined criteria such as character sets, length, and patterns. Crunch is a powerful tool that can save time in the wordlist generation process and increase the effectiveness of password cracking attacks.
sudo apt-get install -y crunch

# Hashcat is a popular password cracking tool that can be used to recover lost or forgotten passwords from various types of encrypted files and hashes. It uses a technique called brute force attack, which involves trying all possible combinations of characters until the correct password is found. Hashcat supports a wide range of hash types, including MD5, SHA1, SHA256, bcrypt, and others. It is a command-line tool that is highly optimized for multi-core processors and GPUs, making it one of the fastest password cracking tools available. Hashcat is often used by security professionals to test the strength of passwords and to recover passwords for forensic and legal purpose.
sudo apt-get install -y hashcat

# Hashcat-data is a package that contains the rules, masks, and dictionaries used by the Hashcat password cracking tool. These files are used to generate wordlists and perform attacks on encrypted files and hashes. The package includes a variety of wordlists, including common passwords, usernames, and other combinations that can be used in password cracking attacks. The rules and masks are used to modify the wordlists and generate more complex combinations, such as adding numbers, symbols, and capital letters. Hashcat-data is an essential package for anyone using Hashcat for password cracking or security testing purpose.
sudo apt-get install -y hashcat-data

# Netcat-traditional is a command-line utility that provides TCP/IP networking capabilities. It allows users to establish and manage connections between computers, as well as send and receive data over a network. Netcat-traditional is often used by system administrators and security professionals for network testing and debugging, as well as for transferring files and data between computers. It is a versatile tool that can be used in a variety of scenarios, such as port scanning, banner grabbing, and remote shell access. Netcat-traditional is one of the most widely used networking utilities in the Unix/Linux world and is available on a variety of platforms.
sudo apt-get install -y netcat-traditional

# Nikto is an open-source web server scanner that performs comprehensive tests against web servers for known vulnerabilities, misconfigurations, and other security issues. It is designed to quickly identify potential security weaknesses in web servers and web applications, and provide detailed reports of its findings. Nikto is capable of detecting over 6700 potentially dangerous files and programs, as well as outdated software versions, weak passwords, and other common vulnerabilities. It can be used for both manual and automated testing, making it a valuable tool for security professionals, system administrators, and web developers alike. Nikto is available for Linux, Windows, and other operating systems.
sudo apt-get install -y nikto

# Armitage is a graphical cyber attack management tool for the Metasploit Framework. It provides a user-friendly interface that allows security professionals and hackers to visualize their attack strategies and manage their exploits, payloads, and sessions within the Metasploit Framework. With Armitage, users can launch pre-configured attacks against target networks, analyze their results, and create custom scripts and plugins to extend its functionality. Armitage is particularly useful for conducting penetration testing, vulnerability assessments, and network reconnaissance. It is available for Linux, Windows, and Mac OS X platforms.
sudo apt-get install -y armitage

# TestDisk is a powerful open-source data recovery software that is designed to recover lost or damaged partitions, fix partition table errors, and repair boot sectors. It supports a wide range of file systems, including FAT, NTFS, EXT, and HFS, and can be used to recover data from hard drives, USB drives, memory cards, and other storage media. TestDisk can also be used to undelete files that have been accidentally deleted, copy files from deleted partitions, and rebuild boot sectors. It runs on various operating systems, including Linux, Windows, and Mac OS X, and is available in both command-line and graphical user interface versions.
sudo apt-get install -y testdisk

# hping3 is a popular network security tool that allows users to generate and send custom packets to target hosts, and then listen for and analyze the responses. It can be used for various network security tasks, such as port scanning, firewall testing, network troubleshooting, and remote operating system fingerprinting. hping3 supports TCP/IP, UDP/IP, ICMP/IP protocols, and can be used to craft packets with various options, such as TTL, window size, and fragmentation. It runs on various operating systems, including Linux, Windows, and Mac OS X, and is available as a command-line tool.
sudo apt-get install -y hping3

# GoldenEye is a network stress testing tool that can be used to test the resilience and performance of network infrastructures and web servers. It works by generating a large volume of HTTP/HTTPS requests to a target server, which can cause the server to become overloaded and unresponsive. GoldenEye can be configured to simulate various types of attacks, such as HTTP GET/POST requests, cookie stealing, and user agent spoofing. It can also be used to test the effectiveness of DDoS mitigation techniques and network security measures. GoldenEye is available as a command-line tool and can run on various operating systems, including Linux, Windows, and Mac OS X.
sudo apt-get install -y goldeneye

# PowerShell is a command-line shell and scripting language developed by Microsoft for Windows operating systems. It provides a powerful and flexible way to automate various system administration tasks and manage Windows-based environments. PowerShell has a rich set of commands, known as cmdlets, that can used to interact with various system components, such as the file system, registry, network, and Active Directory. It supports various programming constructs, such as loops, conditionals, functions, and error handling, and can be used to build complex scripts and modules. PowerShell is also extensible, and third-party modules can be added to enhance its functionality.
sudo apt-get install -y powershell

# John the Ripper, also known as John, is a popular cracking tool that is used to audit and test the strength of passwords. It is primarily designed to brute-force crack password hashes, including those encrypted with popular algorithms such as MD5 and SHA1. John uses various techniques to crack passwords, including dictionary attacks, brute-force attacks, and rainbow table attacks. It supports multiple platforms, including Unix, Linux, Windows, and MacOS, and can be used with various input file formats, such as password hash files, password-protected ZIP files, and encrypted PDF files. John can also be extended with third-party modules to support additional hash types and algorithms.
sudo apt-get install -y john

# John the Ripper has a companion packaged called "john-data" witch contains wordlists, rules, and other data files used by John to crack passwords. These files include commonly used password dictionaries, character sets, and other tools that can help improve the efficiency and accuracy of password cracking attempts. The "john-data" package is typically installed alongside John the Ripper and is necessary of the program to function properly.
sudo apt-get install -y john-data

# TheHarvester is a tool for gathering information on a target domain or email account, including email addresses, subdomains, and hosts associated with the target. It uses various public sources such as search engines, social media platforms, and DNS records to build a comprehensive profile of the target's online presence. This tool can be useful for security researches, penetration testers, and anyone who want to learn more about a particular organization or individual.
sudo apt-get install -y theharvester

# TraceRoute is a network diagnostic tool used to tace the path taken by an Internet Protocol (IP) packet from the sender to the destination device or server. It sends packets with gradually increasing TTL (Time To Live) values to each route in the path to the destination, and records the time it takes for each packet to be acknowledged. This information can be used to identify network issues and troubleshoot connectivity problems.
sudo apt-get install -y traceroute

# Whois is a command-line tool that allows users to look up information about domain names, including the domain registrar, domain expiration date, and contact information for the domain owner. The tool can also be used to verify domain ownership and check for domain availability. Whois queries can be performed using various tools or websites, or by using the command-line tool provided by many operating systems.
sudo apt-get install -y whois

# fcrackzip is a command-line tool used to recover the password of password-protected ZIP files. It works by performing a brute-force attack, systematically trying all possible combinations of characters until the correct password is found. The tool supports various types of password attacks, including dictionary attacks, brute-force attacks, and hybrid attacks, and can be used to recover passwords of both encrypted and uncompressed ZIP files.
sudo apt-get install -y fcrackzip

# Burp Suite is a platform used for performing security testing of web applications. It is a graphical tool that consists of several modules designed to perform various tasks related to web application security testing, including scanning of vulnerabilities, intercepting and modifying HTTP requests and responses, and fuzzing input parameters to identify potential vulnerabilities. It is widely used by security professionals and penetration testers to assess the security posture of web applications.
sudo apt-get install -y burpsuite

# Steghide is a command-line tool used for concealing data inside digital images or audio files. It uses steganography to hide messages or files inside another file without affecting the original file's functionality or appearance. It can be used for various purposes, such as transmitting confidential information, hiding malware, or covert communication. Steghide supports encryption of hidden data with a passphrase and is commonly used by security professionals and digital forensics investigators.
sudo apt-get install -y steghide

# steghide-doc is the documentation package for Steghide. It contains the user manual and usage examples for the Steghide tool, explaining its functionality, command-line options, and various use cases for steganography. It provides guidance on how to use Steghide effectively for concealing data, and how to decode and recover hidden information from images or audio files. This package is useful for those who want to learn more about Steghide or are new to steganography.
sudo apt-get install -y steghide-doc

# Responder is a tool for performing LLMNR, NBT-NS, and MDNS poisoning attacks on a network, allowing an attacker to intercept and capture user credentials.
sudo apt-get install -y responder

# Recon-ng is a reconnaissance framework that helps in the process of gathering information about target web applications, networks, and people using open source intelligence.
sudo apt-get install -y recon-ng

# Ffuf is a fast web fuzzer written in GO, used for quickly brute-force directories and files in web applications.
sudo apt-get install -y ffuf

# Autopsy is a digital forensics platform that provides a graphical interface to The Sleuth Kit suite of tools, allowing users to analyze disk images and recover file from them.
sudo apt-get install -y autopsy

# Bettercap is a network tool that allows users to perform various network attacks such as ARP spoofing, DNS spoofing, and man-in-the-middle attacks. It also allows network discovery, packet interception and analysis, and session hijacking.
sudo apt-get install -y bettercap

# Metagoofil is a tool used to extract metadata and other information from public documents such as PDF and Word documents.
sudo apt-get install -y metagoofil

# Mimikatz is an open-source post-exploitation tool written in C++ and used for obtaining user credentials from the Windows Operating system. It is commonly used by penetration testers and attackers to extract sensitive data such as passwords, tokens, and hashes from Windows systems. Mimikatz has the capability to manipulate Windows authentication protocols and allows an attacker to perform pass-the-hash attacks, bypassing the need for the actual plaintext password. The tool was created by Benjamin Delpy and has been actively maintained and updated by him and the Mimikatz community. However, it's important to note that the use of Mimikatz for malicious purposes is illegal and can result in serious legal consequences.
sudo apt-get install -y mimikatz

# 'wfuzz' is a command-line tool used for brute-forcing and fuzzing web applications. It can be used to test a website for various vulnerabilities like SQL injection, file inclusion, and more. 'wfuzz' supports a variety of features like multiple injection points, custom headers, cookies, and authentication. It can also be used for discovering hidden files and directories on a website. 'wfuzz' is written in Python and is available for Linux, macOS, and Windows operating systems.
sudo apt-get install -y wfuzz

# Reaver is an open-source tool that is used for brute-forcing the Wi-Fi Protected Setup (WPS) protocol. It allows security researches and penetration tasters to test the security of wireless networks by exploiting a vulnerability in the WPS protocol. The tool uses a brute force attack to guess the WPS PIN, and once it finds the PIN, it can be used to gain access to the network. The tool is used to assess the security of wireless networks and to identify vulnerabilities that can be exploited by attackers to gain unauthorized access to the network.
sudo apt-get install -y reaver

# Lynis is a security auditing tool for Unix-based systems, developed by CISOfy. It performs a thorough scan of a system's configuration and provides suggestions for improving the security posture of the system. It checks for known security issues, misconfigurations, and common vulnerabilities in various areas such as file permissions, user accounts, system logging, network configuration, and more. Lynis generates a report the summarizes its findings and provides recommendations for remediation. The tool is available for free and can be run on demand or scheduled to run regularly as part of security monitoring program.
sudo apt-get install -y lynis

# Amass is an open-source network mapping and information gathering tool that can be used for both offensive and defensive purposes. It is designed to help security professionals map and identify potential attack surfaces by discovering and enumerating subdomains, IP addresses, and other network assets associated with a given domain or target. Amass leverages a variety of data sources and techniques, including brute-forcing, scraping, and OSINT gathering, to build comprehensive maps of target networks that can be used for vulnerability assessment, reconnaissance, and other security testing activities. The tool is particularly useful for conducting large-scale reconnaissance operations against complex or distributed network architectures, and can be integrated with other security tools and workflows to support more effective and efficient security testing.
sudo apt-get install -y amass

# Amass is a reconnaissance tool that helps information security professionals perform network mapping of attack surfaces and external asset discovery using open-source information gathering and active reconnaissance techniques. The 'amass-common' package in Kali Linux contains the common files shared by other Amass tools, such as the Amass DNS Enumeration Tool ('amass' package). These common files include configuration files, data files, and documentation.
sudo apt-get install -y amass-common

# Arpwatch is a network monitoring tool used to detect and log ARP (Address Resolution Protocol) activity on a network. ARP is used to map a network address (such as an IP address) to a physical address (such as a MAC address). Arpwatch listens to all network traffic on a network segment and records the source and destination MAC addresses and IP addresses in a database. It can then generate email alerts or log messages when it detects changes in the MAC address-to-IP address mapping. This can be useful for detecting unauthorized changes to a network or identifying potential security threats.
sudo apt-get install -y arpwatch

# Sublist3r is a python-based tool that is used to enumerate subdomains of websites using various search engines such as Google, Yahoo, Bing, and others. It can also perform brute force and reverse DNS lookups to find subdomains. It is helpful for reconnaissance and information gathering during penetration testing or bug bounty hunting. Sublist3r is pre-installed on Kali Linux and can be used from the command line interface.
sudo apt-get install -y sublist3r

# Skipfish is a web application security scanner that is used to identify vulnerabilities in web applications. It is an open-source tool that uses a combination of active and passive scans to identify potential security issues such as SQL injection, cross-site scripting (XSS), and file inclusion vulnerabilities. Skipfish works by sending a large number of requests to the target website, analyzing the responses, and attempting to identify potential vulnerabilities. It can be used by security professionals and penetration testers to assess the security of web applications and identify potential weaknesses that could be exploited by attackers.
sudo apt-get install -y skipfish

# Netdiscover is a network address discovery tool that is used for network exploration, network scanning and security auditing. It is an active reconnaissance tool that sends packets to the network and analyses their responses to identify live hosts and associated information, such as IP address, MAC address, hostname and operating system. It can also be used to perform man-in-the-middle attacks, identify open ports and services, and detect rouge DHCP servers. Netdiscover is included in Kali Linux and can be used from the command line interface.
sudo apt-get install -y netdiscover

# Mdk3 is a powerful wireless attack tool used for testing and auditing wireless networks. It is a suite of tools that allows users to probe, scan, and attack wireless networks. Some of the features of mdk3 include the ability to perform various types of wireless attacks such as deauthentication attacks, beacon flooding, and fake access point creation. Mdk3 can also be used to perform traffic analysis and to inject packets into a wireless network. It is a command-line tool that runs on Linux and is included in Kali Linux, a popular penetration testing and hacking operating system.
sudo apt-get install -y mdk3

# Kismet is a wireless network detector, sniffer, and intrusion detection system for 802.11 wireless LANs. It is an open-source project and is included in Kali Linux by default. Kismet can detect hidden networks, record network activity, and monitor network performance. It also provides real-time and historical wireless network information, including network names, signal strengths, and encryption settings. Kismet can be run on various platforms, including Linux, Mac OS X, and Windows.
sudo apt-get install -y kismet

# The 'kismet-capture-common' package is a dependency of 'kismet', a wireless network detector, sniffer, and intrusion detection system. It contains the common files needed by various kismet capture tools. These tools are used to capture wireless network traffic and feed it to Kismet for analysis and monitoring. The 'kismet-capture-common' package includes shared configuration files, scripts, and documentation needed by the capture tools.
sudo apt-get install -y kismet-capture-common

# 'kismet-capture-linuxbluetooth' is a plugin for the Kismet wireless network detector, sniffer, and intrusion detection system. It allows Kismet to capture Bluetooth packets on Linux systems that support the BlueZ Bluetooth stack. The plugin is used to monitor and analyze Bluetooth devices and their activity on the network. It can be installed on Linux systems that support BlueZ, such as Ubuntu, Debian, and Kali Linux.
sudo apt-get install -y kismet-capture-linux-bluetooth

# 'kismet-capture-linux-wifi' is a package in Kali Linux that provides the Linux wireless capture support for the Kismet wireless network analyzer. This package is used to capture wireless traffic in monitor mode on Linux operating systems using compatible wireless network adapters. It allows Kismet to scan for and collect data on wireless networks, including SSIDs, MAC addresses, signal strength, and data rates. The collected data can then be used for various purposes, such as network troubleshooting, security auditing, and performance optimization.
sudo apt-get install -y kismet-capture-linux-wifi

# 'kismet-capture-nrf51822' is a package in Kali Linux that provides support for capturing Bluetooth Low Energy (BLE) traffic using nRF51822-based USB dongles in Kismet. nRF51822 is a microcontroller chip used in many BLE devices. This package allows Kismet to use nRF51822-based dongles for BLE packet capture.
sudo apt-get install -y kismet-capture-nrf-51822

# 'kismet-capture-nrf51840' is a plugin for the Kismet wireless network sniffer that allows capturing and decoding wireless traffic from devices using the Nordic nRF51840 chipset. This chipset is commonly used in Bluetooth Low Energy (BLE) devices such as smart watches, fitness trackers, and other loT devices. The plugin allows users to capture and analyze the traffic generated by these devices, which can be useful for security testing and troubleshooting.
sudo apt-get install -y kismet-capture-nrf-51840

# 'kismet-capture-nrf-mouse-jack' is a capture module for Kismet that enables the monitoring of MouseJack attacks using NRF24LU1+ based dongles. MouseJack is a vulnerability in wireless mice and keyboards that allows an attacker to send keystrokes or mouse movements to a victim's computer from up to 100 meters away. The module works by listening for MouseJack packets on the NRF24L01+ radio and then forwarding them to the Kismet server for analysis.
sudo apt-get install -y kismet-capture-nrf-mousejack

# 'kismet-capture-xnp-kw41z' (or 'kismet-capture-nxpkw41z') is a plugin for the Kismet wireless network detector and sniffer that enables capturing traffic from the NXP KW41Z chipset. This chipset is used in some Bluetooth Low Energy (BLE) and IEEE 802.15.4 (Zigbee) devices. The plugin is useful for analyzing and monitoring traffic from devices that use the chipset.
sudo apt-get install -y kismet-capture-nxp-kw41z

# 'kismet-capture-rzkillerbee' is a plugin for Kismet that enables packet capture and analysis for networks that use the KillerBee wireless attack toolkit. This plugin allows Kismet to capture and analyze wireless packets on networks using ZigBee and other protocols that are supported by the KillerBee toolkit. With this plugin, users can perform security assessments and penetration testing of ZigBee networks, as well as other wireless networks that use KillerBee-compatible devices.
sudo apt-get install -y kismet-capture-rz-killerbee

# 'kismet-capture-ti-cc-2531' is a plugin for the Kismet wireless network sniffer that allows capturing and decoding of wireless packets using the Texas Instruments CC2531 USB dongle. This dongle can be used as a sniffer to capture and analyze ZigBee wireless network traffic. The plugin allows Kismet to control the dongle and capture ZigBee packets for analysis.
sudo apt-get install -y kismet-capture-ti-cc-2531

# 'kismet-capture-ti-cc-2540' is a package in Kali Linux that provides support for capturing wireless traffic using the Texas Instruments CC2540 chipset. This chipset is commonly used in Bluetooth Low Energy (BLE) devices, and this package enables Kismet to capture BLE traffic from devices using this chipset.
sudo apt-get install -y kismet-capture-ti-cc-2540

# The 'kismet-capture-ubertooth-one' package provides support for capturing Bluetooth Low Energy (BLE) traffic using the Ubertooth One hardware device. The Ubertooth One is an open source Bluetooth test tool developed and maintained by the Open Source Bluetooth Analysis and Testing (OSBAT) project. The 'kismet-capture-ubertooth-one' package contains the necessary components to interface with the Ubertooth One device and capture BLE traffic for analysis in the Kismet wireless network detector, sniffer, and intrusion detection system.
sudo apt-get install -y kismet-capture-ubertooth-one

# Kismet-core is the core backend of the Kismet wireless network detector, sniffer, and intrusion detection system. It includes the core processing engine that does packet analysis, intrusion detection, and sensor management. The Kismet core can be used with multiple front-ends and user interfaces, such as the command-line interface, web interface, or mobile application.
sudo apt-get install -y kismet-core

# Kismet-logtools is a set of tools that are used to process and analyze log files generated by the Kismet wireless network detector, sniffer, and intrusion detection system. These tools allow you to to parse and filter Kismet log files, generate reports, and extract valuable information from the data collected by Kismet. Some of the tools included in kismet-logtools are kismet_to_gpx, which coverts Kismet log files to GPS exchange format files, and kismet_csv, which converts Kismet log files to CSV format.
sudo apt-get install -y kismet-logtools

# 'kismet-plugins' is a package in Kali Linux that includes additional plugins for the Kismet wireless network detector, sniffer, and intrusion detection system. These plugins extend the functionality of Kismet to support additional protocols, devices, and data sources, such as Bluetooth Low Energy (BLE), Zigbee, and GPS.
# Some examples of plugins included in 'kismet-plugins' are:
#       'kismet-plugin-bluetooth': Adds support for Bluetooth Classic and Bluetooth Low Energy (BLE) devices.
#       'kismet-plugin-gpsmap': Plots the location of detected wireless networks on a map using GPS coordinates.
#       'kismet-plugin-ieee80211n': Adds support for 802.11n wireless networks.
#       'kismet-plugin-ubertooth': Adds support for the Ubertooth One Bluetooth sniffer.
#       'kismet-plugin-zigbee': Adds support for Zigbee wireless networks.
# Overall, 'kismet-plugins' provides a wide range of additional features and capabilities to Kismet, making it a powerful tool for wireless network analysis and security testing.
sudo apt-get install -y kismet-plugins

# 'python3-kismet-capture-bt-geiger' is a Python3 module for Kismet that allows for capturing Bluetooth Low Energy (BLE) advertisements from a BT Geiger device. The BT Geiger is a small, low-cost BLE device that is designed to detect radiation and send notifications when it is detected. The module can be used to capture BLE advertisements from the device and log the radiation levels along with the advertisement data.
sudo apt-get install -y python3-kismetcapturebtgeiger

# 'python3-kismet-capture-freak-labs-zigbee' is a Python library for Kismet wireless network detector, sniffer, and intrusion detection system. It allows Kismet to capture and decode data packets from Freaklabs Zigbee devices. This library can be used to capture data packets from Zigbee devices and analyze the network traffic for security and debugging purposes.
sudo apt-get install -y python3-kismetcapturefreaklabszigbee

# 'python3-kismet-capture-rtl433' is a Python3 module that enables Kismet to use an RTL-SDR dongle as a capture source for wireless devices using the 433MHz ISM band, such as weather sensors, home automation devices, and other wireless devices. It allows Kismet to decode and display information from these devices, which can be useful for analyzing and monitoring wireless traffic in these frequency ranges.
sudo apt-get install -y python3-kismetcapturertl433

# 'python3-kismet-capture-rtl-adsb' is a Python3 library for Kismet that allows capturing ADS-B data using RTL-SDR devices. It is used for capturing and decoding Automatic Dependent Surveillance-Broadcast (ADS-B) messages transmitted by aircraft. The library utilizes the 'rtl_adsb' program to capture the ADS-B messages and provides a Python interface to interact with the captured data.
sudo apt-get install -y python3-kismetcapturertladsb

# 'python3-kismet-capture-rtlamr' is a plugin for Kismet that allows capturing and decoding of Automatic Meter Reading (AMR) transmissions using the RTL-SDR dongle. This plugin enables Kismet to recognize and analyze AMR packets transmitted by smart meters. The decoded data can then be used for various purposes, such as monitoring and analyzing energy consumption patterns in a smart grid network.
sudo apt-get install -y python3-kismetcapturertlamr

# 'impacket-scripts' is a collection of Python scripts that use the Impacket library to perform network-related tasks such as SMB authentication, MSRPC, and DCE-RPC. These scripts can be used for various network penetration testing activities such as password cracking, port scanning, and exploiting Windows vulnerabilities. Some of the popular scripts included in the package are smbclient.py, rpcdump.py, wmiquery.py, and lookupsid.py.
sudo apt-get install -y impacket-scripts

# Dmitry is an open-source information gathering tool used for gathering intelligence about a target domain or IP addresses. It can perform tasks such as port scanning, banner grabbing, and OS fingerprinting, among others. The tool is designed to be used in penetration testing and vulnerability assessment tasks or identify potential weaknesses and security issues. Dmitry is included in Kali Linux and can be installed on other Linux distributions as well. It is written in C and is licensed under the GPL.
sudo apt-get install -y dmitry

# Airgeddon is a multi-use bash script for Linux systems to audit wireless networks. It is designed to provide a comprehensive suite of tools and functions for conducting wireless penetration testing and security assessments. Airgeddon is capable of performing a variety of attacks, including deauthentication attacks, fake access point (AP) attacks, handshake captures, and various other network scanning and analysis tasks. It supports a wide range of wireless network interfaces and is compatible with a variety of Linux distributions, including Kali Linux.
sudo apt-get install -y airgeddon

# The 'apt-get update' command is used in Kali Linux to update the local package index from the repositories. It downloads the package lists from the configured repositories and updates the local package index to reflect any changes that may have occurred. This command should be run before installing or updating any packages on the system to ensure that you have the latest package information.
sudo apt-get update

# 'python3-scapy' is a Python module for crafting and manipulating network packets. it allows you to send, sniff and dissect network packets, as well as create custom packets for testing purposes. It is often used in network penetration testing and other security-related applications. In Kali Linux, 'python3-scapy' is often pre-installed, but if it's not, you can install it.
sudo apt-get install -y python3-scapy

# Legion is a multi-purpose tool for conducting offensive security assessments. It is a Python-based framework that can be used for reconnaissance, vulnerability assessment, and exploitation. It provides a collection of modules that can be used to automate various tasks in the assessment process, such as information gathering, port scanning, and exploitation. It also supports multiple protocols, including HTTP, SMB, and SMTP. Legion is often used by penetration testers and security professionals to test the security of networks and applications.
sudo apt-get install -y legion

# 'python3-impacket' is a Python library that provides a set of classes to work with network protocols. It includes a set of tools for network packet manipulation, such as sending and receiving packets, crafting and decoding packets, and sniffing network traffic. it is often used for penetration testing and network analysis tasks.
sudo apt-get install -y python3-impacket

# Hash-Identifier is a tool used for identifying the different types of hashes used to encrypt data. It is a Python-based tool that can detect the hash type of a given string, file or hash dump. It analyzes the input data and generates a possible match to the hash type from its database of known hash types. This tool can be useful in cases where a user has obtained a hash and wants to determine what type of hash it is to aid in cracking the hash.
sudo apt-get install -y hash-identifier

# dsniff is a network security tool that allows you to analyze and intercept network traffic in real-time. It includes various modules for network sniffing, password sniffing, and session hijacking. With dsniff, you can monitor network traffic and capture usernames and passwords, as well as other sensitive information, from various network protocols. It can also be used for testing network security and detecting vulnerabilities. Dsniff is included in Kali Linux by default.
sudo apt-get install -y dsniff

# 'dnsmap' is a command-line tool used for subdomain enumeration through DNS. It can perform brute-force guessing of subdomains, reverse lookup of IP addresses to find associated domain names, and dictionary-based guessing of subdomains. It can output the results in various formats, including plain text and XML. It can be useful for reconnaissance and information-gathering during penetration testing and security assessments. 'dnsmap' is available in Kali Linux as a pre-installed tool.
sudo apt-get install -y dnsmap

# BloodHound is an open-source, Windows-based application developed by the BloodHound team at SpecterOps. It is a tool used to identify and map relationships between Active Directory (AD) objects in an enterprise network. By analyzing the relationships between AD objects, BloodHound can help identify potential attack paths and privilege escalation opportunities that might exist within an organization's AD environment. BloodHound uses graph theory to visualize the complex relationships between AD objects and can help security analysts quickly identify and mitigate potential security risks.
sudo apt-get install -y bloodhound

# Binwalk is an open-source tool used for analyzing, reverse engineering, and extracting firmware images and binary files. It is particularly useful in the field of embedded systems security and loT device security. Binwalk can identify the type of files contained within a firmware image or binary file and extract them, including file systems, bootloaders, and other binary blobs. It also has the capability to perform signature scanning, entropy analysis, and file system analysis, which can help in identifying vulnerabilities and security issues in firmware images.
sudo apt-get install -y binwalk

# 'binwalk' is a firmware analysis tool that is capable of searching binary files for embedded files and executable code. It can be used for reverse engineering, malware analysis, and extracting firmware images. 'python3-binwalk' is a Python3 library that allows for integration of 'binwalk' into Python scripts for automated analysis. It provides a simple and easy-to-use interface for parsing the results of 'binwalk' and can be used to extract and manipulate the embedded files found by 'binwalk'.
sudo apt-get install -y python3-binwalk

# Wifiphisher is a wireless security tool used to conduct automated phishing attacks against WiFi networks. It is a social engineering attack that targets clients of a wireless network by performing a Man-in-the-Middle (MiTM) attack between the client and the access point (AP). The tool aims to trick the users into entering their WiFi credentials or other sensitive information by displaying a convincing login page that looks like a legitimate AP login page. Once the user enters their credentials, the tool logs them and allows the attacker to access the network. Wifiphisher is available as a package in Kali Linux.
sudo apt-get install -y wifiphisher

# SSLstrip is a tool used for performing a man-in-the-middle attack on HTTPS connections. It was developed by Moxie Marlinspike and allows an attacker to intercept and modify HTTPS traffic by downgrading the connection to HTTP. The tool is designed to be used for testing and educational purposes only and should not be used for illegal activities. SSLstrip is available on Kali Linux and can be installed using the package manager.
sudo apt-get install -y sslstrip

# 'slowhttptest' is a security testing tool used to test HTTP server vulnerabilities related to Slowloris, Show Read and Slow POST attacks. It sends HTTP traffic to a server in slow but regular intervals to check how the server handles the requests. Slowhttptest can detect resource exhaustion and denial of service vulnerabilities in an HTTP server.
sudo apt-get install -y slowhttptest

# rkhunter stands for Rootkit Hunter, a tool designed to detect rootkits and other forms of malware that my have infected a Linux-based system. It scans the system for suspicious files, directories, and other signs of potential compromise, and generates reports of its findings. Rkhunter can be run on-demand or scheduled to run periodically as part of a security maintenance routine.
sudo apt-get install -y rkhunter

# Medusa is a command-line tool that can be used for password cracking. It is capable of performing brute force attacks and dictionary attacks against a wide range of protocols, including HTTP, FTP, SSH, Telnet, and more. It supports parallelism and can run on multiple machines to speed up the cracking process. Medusa is included in Kali Linux and other security-focused Linux distributions.
sudo apt-get install -y medusa

# Fierce is a DNS reconnaissance tool that helps in discovering non-contiguous IP space, DNS servers and various DNS information such as mail servers and MX records. It can also perform subdomain bruteforcing, zone transfer tests and reverse lookups. Fierce is useful for penetration testing and security assessments.
sudo apt-get install -y fierce

# CrackMapExec (CME) is a post-exploitation tool used to gather information about a target network and to perform various types of security assessments. It allows security professionals and ethical hackers to perform various tasks, such as password cracking, port scanning, and service enumeration, among others. The tool is written in Python and runs on both Linux and Windows operating systems. CME is often used in penetration testing and red teaming exercises to simulate real-world attacks and test security posture of organization.
sudo apt-get install -y crackmapexec

# Commix is a command injection and exploitation tool that can be used to test web applications' security against various command injection attacks. It allows users to test web applications that rely on various programming languages, such as Python, Perl, Ruby, PHP, and others, for vulnerabilities. Commix automates the process of identifying and exploiting command injection vulnerabilities in a web application. It also provides a variety of features such as parameter brute-forcing, cookie support, and HTTP proxy support.
sudo apt-get install -y commix

# Chntpw is a tool used in Kali Linux to reset or recover lost Windows passwords. It can be used to edit the Windows registry, enable or disable account flags, and promote or demote user accounts. It works with Windows NT, 2000, XP, Vista, 7, 8, and 10.
sudo apt-get install -y chntpw

# arp-scan is a command-line utility that allows users to discover hosts on a network by sending ARP requests and analyzing the responses. It can be used to identify IP and MAC addresses, vendor information, and open ports. It is commonly used for network troubleshooting and security audits.
sudo apt-get install -y arp-scan

# Xsser is a penetration testing tool used for detecting and exploiting Cross-Site Scripting (XSS) vulnerabilities in web applications. The tool is designed to simulate real-world attacks and can be used to test the security of web applications by injecting malicious code into web pages. The tool can be used by security professionals, ethical hackers, and web developers to identify and fix vulnerabilities in their applications. Xsser is available in Kali Linux as a command-line tool and can be installed using the package manager or by downloading it from the official website.
sudo apt-get install -y xsser

# SpiderFoot is an open-source intelligence (OSINT) automation tool that collects information about a given target through a variety of sources such as search engines, websites, and social media platforms. The tool can be used for both defensive and offensive purposes, such as reconnaissance for vulnerability assessments and penetration testing or investigating online threats and attacks. SpiderFoot has a modular design that allows users to customize their searches and integrate their own tools and APIs. It also provides a user-friendly interface and reports that simplify the analysis and virtualization of the collected data. SpiderFoot is written in Python and can be installed on Linux, Windows, and MacOS systems.
sudo apt-get install -y spiderfoot

# Parsero is a tool used for finding hidden information on web applications. It is a free, open-source tool that can identify directories, subdomains, and other sensitive information on websites. It does so by analyzing the website's robots.txt file and the sitemap.xml file, and by performing brute force attacks to find hidden directories and files. The tool is mainly used for reconnaissance purposes and is often used by penetration testers and ethical hackers.
sudo apt-get install -y parsero

# Nuclei is an open-source project, and a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use. The templates are easy to write and share, making it easier for teams to collaborate on improving detection capabilities. Nuclei has an intuitive syntax and a simple but powerful templating engine for detecting known and unknown vulnerabilities. It also supports various output formats to make is easier for security teams to consume the results.
sudo apt-get install -y nuclei

# Ghidra is a free and open-source software reverse engineering tool developed by the National Security Agency (NSA). It provides users with the ability to analyze binary files to understand their functionality and behavior. Ghidra supports a wide range of processor architectures and file formats, and includes features such as disassembly, decompilation, scripting, and debugging. It is widely used in the security research and software development communities for tasks such as malware analysis, vulnerability research, and firmware analysis.
sudo apt-get install -y ghidra

# Foremost is a data recovery tool that is used to recover files based on their headers, footers, and internal data structures. It is typically used to recover files that have been deleted or lost due to file system corruption, disk failure, or other similar issues. Foremost can recover files or various types including images, documents, and multimedia files from various file systems such as FAT, NTFS, and ext3/4. It is a command-line tools and comes pre-installed in Kali Linux.
sudo apt-get install -y foremost

# Dnsrecon is an open-source DNS reconnaissance tool for information gathering about DNS servers, domain names, and IP addresses. It can be used to zone transfers, brute-forcing, and various other DNS-related tasks. The tool is written in Python and comes with various features, such as the ability to perform dictionary-based attacks and use different types of queries to retrieve information. It can also be used for network mapping and scanning purposes.
sudo apt-get install -y dnsrecon

# Dirsearch is an open-source web path scanner used for finding directories and files on web servers. It is written in Python and can be used to discover web content that is not properly linked or hidden. It has support for multiple scanning modes and can be used for both white-box and black-box testing. Dirsearch is commonly used by security professionals and penetration testers to identify possible attack vectors on a web application.
sudo apt-get install -y dirsearch

# Capstone is a lightweight multi-platform, multi-architecture disassembly framework. It provides a simple and powerful interface for disassembly binary code into human-readable assembly instructions. It supports a variety of architectures including ARM, MIPS, PowerPC, x86, and more. Capstone is used to variety of tools such as reverse engineering, malware analysis, and binary code analysis.
sudo apt-get install -y capstone-tool

# 'libcapstone-dev' is a development library for Capstone disassembly framework. It provides header files and other resources necessary for developing applications that use Capstone's disassembly capabilities. Capstone is lightweight multi-platform, multi-architecture disassembly framework that supports several hardware platforms including ARM, MIPS, PowerPC, and x86. It can be used for static analysis of binaries, binary instrumentation, and just-in-time code generation. The 'libcapstone-dev' package allows developers to write code that uses Capstone and take advantage of its disassembly capabilities.
sudo apt-get install -y libcapstone-dev

# 'libcapstone4' is a system library that provides an open-source disassembly framework that supports multiple architectures including x86, ARM, PowerPC, and MIPS. It is used by various applications such as debuggers, compilers, static code analyzers, and other security tools to disassemble binary code and extract information such as function names, operands, and control flow structures. The library is designed to be lightweight, portable, and easy to use.
sudo apt-get install -y libcapstone4

# 'python3-capstone' is a Python binding for the Capstone disassembly framework. It allows Python developers to use the Capstone library to disassemble binary files and obtain information about the code inside them. Capstone supports a wide range of hardware architectures and binary file formats, making it a popular tool for reverse engineering and malware analysis.
sudo apt-get install -y python3-capstone

# BED (Binary Editor) is a library for binary file manipulation on multiple platforms. It was designed to be lightweight, fast, and portable. BED provides a simple and intuitive API, allowing the user to read, modify, and write binary files with ease. The library also includes functionality for searching and replacing bytes, inserting and deleting data, and more advanced features such as pattern recognition and data analysis. BED can be used in a variety of applications, including reverse engineering, file format conversion, and data analysis.
sudo apt-get install -y bed

# WhatWeb is a web application scanner that identifies what websites are built with, including technologies, frameworks, and content management systems. It does this by analyzing web page headers, HTML code, and other characteristics. WhatWeb can be used to gather intelligence about a website and its underlying technologies, as well as to identify potential security vulnerabilities. It is often used as part of larger security testing toolkit for web applications.
sudo apt-get install -y whatweb

# The command 'sudo dpkg --add-architecture i386' is sued in Debian-based Linux distributions (including Kali Linux) to enable multiarch support, which allows a system to install and run packages from multiple architectures (such as i386 and amd64) on the same system. The command adds the i386 architecture to the list of architectures the system can use. This is particularly useful when trying to run and install 32-bit applications on a 64-bit operating system.
sudo dpkg --add-architecture i386

# Running 'sudo apt update' will refresh the package lists and update them to the latest available version.
sudo apt update

# 'wine32' is a package in Linux systems that provides the ability to run 32-bit Windows applications on a 64-bit Linux operating system. It installs the 32-bit version of Wine, which is a compatibility layer that allows Windows applications to run on Linux. The 'wine32' package provides support for 32-bit Windows applications, while the 'win64' package provides support for 64-bit Windows applications.
sudo apt-get install -y wine32

# Shellter is a dynamic shellcode injection tool, and a dynamic PE infector that be used to bypass modern Antivirus solutions. It supports both Windows 32 and 64-bit systems, and it compatible with the Metasploit Framework, as it can generate Metasploit payloads on the fly.
sudo apt-get install -y shellter

# RainbowCrack is a password cracking tool that utilizes precomputed rainbow tables to crack password hashes. It can be used to crack a wide variety of password hashes, including LM, NTLM, MD5, SHA-1, and others. RainbowCrack is known for its speed and efficiency, as it can crack even complex passwords in a matter of seconds. It is often used by security professionals and penetration testers or test the strength of passwords and to identify weak passwords that may be susceptible to cracking.
sudo apt-get install -y rainbowcrack

# Maryam is written in Python programming language and it's designed to provide a powerful environment to harvest data from open sources and search engines and collect data quickly and thoroughly.
sudo apt-get install -y maryam

# Macchanger is a Linux utility tool that allows users to modify their MAC address. The MAC address is a unique identifier assigned to network interfaces, and it is used to identify devices on a network. Macchanger allows users to change their MAC address to a random address or a specific address, which can help improve anonymity and security while using a network.
sudo apt-get install -y macchanger

# JSQL-Injection is a tool for finding SQL injection vulnerabilities in web applications. It is written in Java and works by sending specially crafted SQL queries to the target application and analyzing the responses to determine if a vulnerability exists. JQL-Injection can also be used to perform automated exploitation of SQL injection vulnerabilities by running SQL commands against the vulnerable database. The tool is designed to be simple to use and requires minimal configuration.
sudo apt-get install -y jsql-injection

# Hakrawler is an open-source web crawler for discovering hidden files and directories on a target website. It is written in GO programming language and is designed to be fast, efficient, and easy to use. Hakrawler supports various options, including recursive crawling, custom headers, filtering by status code and more. It is commonly used in web application security testing to identify potential vulnerabilities for sensitive information that may be exposed on a website.
sudo apt-get install -y hakrawler

# DNSenum is a tool used for gather information about DNS servers and perform zone transfers. It can be used to enumerate subdomains, gather DNS record types, and identify common vulnerabilities in DNS configurations. DNSenum is typically used in penetration testing and network reconnaissance.
sudo apt-get install -y dnsenum

# Chisel is a command-line tool that creates a TCP tunnel between two computers, allowing communication between them over an encrypted an authenticated channel. It can be used to bypass firewalls or to establish secure connections between systems on different networks. Chisel is written in Golang and is available for Linux, Windows, and MacOS.
sudo apt-get install -y chisel

# Arjun is a command-line tool written in Python for finding parameters and testing vulnerabilities in web applications. It works by analyzing HTTP requests and responses to identify potential vulnerabilities, such as SQL injection, Cross-Site Scripting (XSS), and more. It can also brute-force parameters to discover hidden APIs and endpoints. Arjun is designed to be lightweight and easy to use, making it a popular choice for web application security testing.
sudo apt-get install -y arjun

# Amap (short for Application Mapper) is an open-source network scanner that allows users to identify and fingerprint the services and applications running on a target network. Amap is designed to be fast and accurate, and it can detect and identify more than 500 different application protocols. The tool uses several techniques to identify the services and applications running on a network, including active and passive fingerprinting, banner grabbing, and more. Amap can be used for security audits, penetration testing, and network mapping.
sudo apt-get install -y amap

# Wafw00f is a web application firewall (WAF) detection tool written in Python. It allows security professionals and researchers to easily identify and fingerprint different types of WAFs that may be used by a target web application. It works by sending a set of HTTP requests to the target application, analyzing the responses, and attempting to identify any WAF-specific patterns or behaviors. This can be useful in both offensive and defensive security operations, as it can help identify potential vulnerabilities or attack surfaces that may be protected by a WAF.
sudo apt-get install -y wafw00f

# Veil is a tool used for creating payloads that bypass antivirus software. It works by generating a customized executable file that is unique to the target system, making it more difficult for antivirus software to detect. Veil uses various methods to achieve this, such as encryption, obfuscation, and polymorphism. The tool can be used for penetration testing and red teaming purposes to test the effectiveness of an organization's antivirus software. Veil is written in Python and is available on various platforms including Linux, Windows and MacOS.
sudo apt-get install -y veil

# Veil-Catapult is a payload delivery and evasion tool that allows you to generate various types of payloads using Veil-Evasion and deploy them over a network using various methods such as DNS and SMB. It can be used for penetration testing and ethical hacking activities.
sudo apt-get install -y veil-catapult

# Veil-Evasion is a tool designed for penetration testing that creates custom bypassing antivirus payloads to avoid detection. It generates payloads in various formats, including executable files, DLLs, Python scripts, and others, and provides a simple interface to configure the payload's behavior and output format. The tool uses a combination of several methods to avoid detection, including code obfuscation, custom encoding, and Metasploit payloads. Veil-Evasion is a popular tool among security researches and penetration testers due to its ease of use and effectiveness.
sudo apt-get install -y veil-evasion

# SSlyze is a Python tool that analyzes SSL/TLS configurations of servers. It can be used to scan servers for various SSL/TLS issues such as weak ciphers, certificate issues, and protocol vulnerabilities. SSlyze can also perform tests such as checking for the support of TLS 1.3 and the presence of HTTP Strict Transport Security (HSTS) headers. The tool has a command-line interface as well as a graphical user interface (GUI) and can be used for both manual and automated testing of SSL/TLS servers.
sudo apt-get install -y sslyze

# 'sslscan' is a command-line tool used to scan and identify SSL/TLS protocol and cipher suite support on target servers. It can identify insecure cipher suites and highlight weak SSL configurations. It is a useful tool for checking SSL configurations and verifying whether SSL is properly implemented on a target server.
sudo apt-get install -y sslscan

# SET (Social-Engineer Toolkit) is an open-source framework designed to automate social engineering attacks, including phishing and spear-phishing. It is written in Python and is available on Linux, Windows, and MacOS. SET provides various modules that allow an attacker to create a tailored attack, such as credential harvester, SMS spoofing, and website cloning. These modules can be customized to meet the attacker's needs. SET also includes the ability to generate malicious payloads that can be used to exploit vulnerabilities in systems. These payloads can encoded to evade detection by anti-virus software and can be delivered via various channels, such as email, USB drives, or phishing websites. SET has been widely used by security professionals to simulate real-world social engineering attacks and to identify vulnerabilities in their organizations's security. However, it should be noted that the use of SET for any malicious purpose is illegal and can result in severe legal consequences.
sudo apt-get install -y set

# Fern Wifi Cracker is a wireless security auditing and attack tool written in Python. It uses a combination of various tools such as Aircrack-ng, Reaver, Pixiewps, and Wash to perform the attack. It is used to test the security of wireless networks by attempting to crack the encryption key. It supports a wide range of attacks such as WEP, WPA, and WPA2-PSK. The tool has a graphical user interface (GUI) and is easy to use for both beginners and experienced users.
sudo apt-get install -y fern-wifi-cracker

# 'software-properties-common' is a package in Ubuntu and Debian-based systems that provides an abstraction for repositories' management. This package allows you to easily add, remove or enable/disable repositories through a graphical or command-line interface. It is also required for some software installation procedures as it provides the 'add-apt-repository' command which enables you to add external PPAs (Personal Package Archives) and other repositories to your system.
sudo apt-get install -y software-properties-common

# The 'network-manager-l2tp-gnome' package provides a plugin for NetworkManager to support L2TP and L2TP/IPsec VPNs. It also includes a GNOME applet to configure VPN connections. Note that this package requires 'network-manager' and 'network-manager-l2tp' to be installed as well.
sudo apt-get install -y network-manager-l2tp-gnome

# 'zlib1g-dev' is a package for Ubuntu and Debian Linux distributions that provides the development files necessary for compiling software that requires zlib, a popular data compression library. The 'zlib1g-dev' package contains the header files and static library required for developing software that uses zlib.
sudo apt-get install -y zlib1g-dev

# The command 'sudo apt update' is used to update the package lists and information of available software packages in the repositories configured in the system. It is an important step to ensure that the system has the latest information about available software packages before installing or upgrading any packages. The 'sudo' prefix is used to execute the command with administrative privileges.
sudo apt update

# The 'sudo apt upgrade -y --fix-missing' command is used to upgrade all installed packages on a system. The '-y' option is used to automatically answer "yes" to any prompts that appear during the upgrade process, and the '--fix-missing' option is used to fix any missing dependencies that may be encountered during the upgrade process. The 'sudo' command is used to run the upgrade command with administrative privileges. It is important to regularly run 'apt update' to ensure that all software packages on a system are up-to-date with the latest security patches and bug fixes.
sudo apt upgrade -y --fix-missing

# 'default-jdk' is a meta-package in Ubuntu and Debian-based Linux distributions that installs a default JAVA Development Kit (JDK) package. It is a convenient way to install the recommended Java development environment on your system. When installed, 'default-jdk' installs the default Java Runtime Environment (JRE) and the default Java Development Kit (JDK). The package ensures that the system has a java compiler, Java Virtual Machine (JVM), and other essential Java tools.
sudo apt-get install -y default-jdk

# 'openjdk-17-dbg' is a package for OpenJDK 17 that provides debugging symbols that can be used to debug programs written in Java. The package contains the debug symbols for OpenJDK 17 and is typically used by developers who are building and debugging Java applications on Ubuntu or other Linux-based operating systems.
sudo apt-get install -y openjdk-17-dbg

# 'openjdk-17-doc' is the package that contains the documentation for the OpenJDK 17. OpenJDK is a free and open-source implementation of the Java Platform, Standard Edition (JAVA SE). It includes a Java Virtual Machine (JVM), a set of libraries, and development tools. The 'openjdk-17-doc' package includes the API documentation, examples, and guides for the OpenJDK 17. It can be useful for developers who want to write Java applications using OpenJDK 17.
sudo apt-get install -y openjdk-17-doc

# 'openjdk-17-demo' is a package containing demo programs and examples for OpenJDK 17. It can be used to demonstrate the capabilities and features of OpenJDK, as well as to help developers learn how to use the APIs and tools provided by OpenJDK. The package includes a variety of demo programs, such as graphical user interface (GUI) demos, network demos, and security demos. It also includes sample code and documentation to help developers get started with OpenJDK.
sudo apt-get install -y openjdk-17-demo

# 'openjdk-17-jdk' is the package that contains the Java Development Kit (JDK) for OpenJDK 17, which is an open-source implementation of the Java Platform, Standard Edition (JAVA SE) specification. The JDK includes tools such as 'javac', 'java', 'jar', and others that are needed for developing and running Java applications.
sudo apt-get install -y openjdk-17-jdk

# 'openjdk-17-jdk-headless' is a package in the Ubuntu operating system that provides the OpenJDK 17 JDK (Java Development Kit) without the graphical user interface components. This package contains the tools necessary for developing, compiling, and running Java programs from the command line, including the Java compiler ('javac'), the Java Virtual Machine ('java'), and other command-line utilities. It is useful for systems without a GUI or headless servers where a GUI is not needed.
sudo apt-get install -y openjdk-17-jdk-headless

# The 'openjdk-17-jre' package provides the OpenJDK Runtime Environment, which allows users to run Java applications on their systems without needing to develop Java applications themselves. The OpenJDK Runtime Environment is required to run Java applications and applets on the system.
sudo apt-get install -y openjdk-17-jre

# 'openjdk-17-jre-headless' is the headless version of the Java Runtime Environment (JRE) based on OpenJDK 17. This package provides the libraries and the Java Virtual Machine (JVM) necessary to run Java-based software on a system without a graphical user interface. It is suitable for running Java applications in server environments where a GUI is not needed.
sudo apt-get install -y openjdk-17-jre-headless

# The 'openjdk-17-jre-zero' package provides an alternative JRE implementation that does not include a Just-In-Time (JIT) compiler, which can be useful in certain scenarios where the overhead of JIT compilation is not desirable, such as running on resource-constrained systems.
sudo apt-get install -y openjdk-17-jre-zero

# The 'openjdk-17-source' package contains the source code for the OpenJDK 17 implementation, which is an open-source implementation of the JAVA SE Platform Edition. It allows developers to browse and explore the source code of the JDK to better understand how it works and how to use it effectively. The package is typically used by developers who want to contribute to the OpenJDK project or want to debug issues in the JDK.
sudo apt-get install -y openjdk-17-source

# The 'auto-remove' command is used in Ubuntu and other Debian-based Linux distributions to remove packages that were automatically installed as dependencies and are no longer needed by any other installed package. This command helps to free up disk space by removing unnecessary packages. The full command to use this feature is 'sudo apt autoremove'.
sudo apt auto-remove -y

# 'The 'auto-clean' command in Linux is used to clean up the local repository of retrieved package files that can no longer be downloaded, and are largely useless. This command is similar to 'clean', but instead of removing all downloaded package files, it only removes package files that can no longer be downloaded and are not currently installed. It helps to free up disk space by removing unnecessary packages from the system.
sudo apt auto-clean -y

# The package 'python3.11-venv' provides a built-in tool in Python 3.11 for creating virtual environments. Virtual environments allow you to have multiple isolated instances of Python with their own installed packages, without interfering with the global Python installation or other virtual environments.
# You can use the 'python3.11-venv' package to create a new virtual environment in Python 3.11 by running the command 'python3.11 -m venv <path_to_env>'. This will create a new directory at the specified path with the virtual environment files. You can activate the virtual environment by running the command 'source <path_to_env>/bin/activate' on Linux/macOS or '<path_to_env>\Scripts\activate.bat' on Windows. Once activated, any packages installed via pip will be installed only in the virtual environment.
sudo apt-get install -y python3.11-venv

# The command 'python3.11 -m venv --help' is used to display the help message for the 'venv' module in Python 3.11. The 'venv' module is used to create virtual environments in Python, which are isolated environments that can have their own set of installed packages and Python interpreter. The '--help' option displays a list of available options and their usage examples.
python3.11 -m venv --help

