from PySide6.QtWidgets import (QApplication,
                               QWidget,
                               QPushButton,
                               QHBoxLayout,
                               QVBoxLayout,
                               QGridLayout,
                               QLabel,
                               QLineEdit,
                               QSizePolicy,
                               QTextEdit,
                               QComboBox,
                               QScrollArea,
                               QListWidget,
                               QListWidgetItem,
                               QMessageBox,
                               QDialog,
                               QFormLayout,
                               QTabWidget,
                               QTreeWidget,
                               QTreeWidgetItem,
                               QHeaderView)
from PySide6.QtCore import QThread, Signal, QTimer, QObject, Qt
from PySide6.QtGui import QFont, QIcon, QColor
import pyqtgraph as pg
from scapy.all import *
from scapy.layers.l2 import Ether, ARP, arping
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
# from scapy.layers.tls.all import TLS
from scapy.layers.dhcp import DHCP
import ipaddress
import psutil
import socket
from mac_vendor_lookup import MacLookup
from collections import namedtuple
from dataclasses import dataclass
from datetime import (datetime, timedelta)
from plyer import notification
import os.path
import sqlite3
import threading
import time
import sys

# Importing database...
NETMON_DEVICES = r"./NetMon-Devices.db"

# DB Helper Class
class DeviceDB:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)  # Connect to the db
        self.lock = threading.Lock()  # Safety
        self.device = {}  # Device dict
        self._load_device()  # Automatically create dict

    def _load_device(self):  # Create device dict for all devices (performance)
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT Mac_Address, Device_Name FROM NetMon_Devices")
            self.device = {mac: name for mac, name in cur.fetchall()}

    def get_name(self, mac):
        return self.device.get(mac, None)

    def save_name(self, mac, name):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO NetMon_Devices (Mac_Address, Device_Name)
                VALUES (?, ?)
                ON CONFLICT(Mac_Address) DO UPDATE SET Device_Name=excluded.Device_Name
            """, (mac, name))
            self.conn.commit()
            self.device[mac] = name  # Update device dict

    def close(self):
        with self.lock:
            self.conn.close()


# Capture Packets
class PacketCapture(QThread):
    packet_capture_signal = Signal(str, object)

    def __init__(self, iface, network_id, mac, subnet):
        super().__init__()
        self.iface = iface
        self.network_id = ipaddress.ip_network(network_id, strict=False)
        self.mac = mac
        self.subnet = subnet
        self.is_capturing_active = True

        pcap_file_temp = ""
        for file_num in range(1, 1000):
            if os.path.isfile(f'./Pocket-NetMon/NetMon {file_num}.pcap'):
                continue
            else:
                pcap_file_temp = open(f'./Pocket-NetMon/NetMon {file_num}.pcap', "x")
                break
        self.pcap_file = pcap_file_temp.name

        # ARP SCAN DETECTION
        self.arp_scan_check_tracker = {}

        match int(self.subnet):
            case 8 | 16 | 17 | 18 | 19 | 20 | 21:
                self.arp_scan_check_threshold = 2000
                self.arp_scan_check_duration = 18
            case 22:
                self.arp_scan_check_threshold = 669
                self.arp_scan_check_duration = 12
            case 23:
                self.arp_scan_check_threshold = 489
                self.arp_scan_check_duration = 10
            case 24:
                self.arp_scan_check_threshold = 239
                self.arp_scan_check_duration = 8
            case 25:
                self.arp_scan_check_threshold = 118
                self.arp_scan_check_duration = 4
            case 26:
                self.arp_scan_check_threshold = 59
                self.arp_scan_check_duration = 3
            case 27:
                self.arp_scan_check_threshold = 24
                self.arp_scan_check_duration = 3
            case 28:
                self.arp_scan_check_threshold = 13
                self.arp_scan_check_duration = 2
            case 29:
                self.arp_scan_check_threshold = 4
                self.arp_scan_check_duration = 2
            case 30:
                self.arp_scan_check_threshold = 2
                self.arp_scan_check_duration = 1

        # PORT SCAN DETECTION
        self.port_scan_check_tracker = {}
        self.port_scan_check_threshold = 30
        self.port_scan_check_duration = 5
        self.port_scan_check_alert_cooldown = 5

    def run(self):
        sniff(iface=self.iface, prn=self.process_captured_packet, store=False, stop_filter=self.should_stop_capturing)

    def process_captured_packet(self, packet):
        packet_summary = PacketUtils.packet_title(packet, self.network_id)
        self.packet_capture_signal.emit(packet_summary, packet)

        wrpcap(self.pcap_file, packet, append='True')

        if DHCP in packet:
            self.new_device_check(packet)
        elif ARP in packet and packet[ARP].op == 1:
            self.arp_scan_check(packet)
        elif TCP in packet and packet[TCP].flags == "S" and IP in packet:
            self.tcp_syn_scan_check(packet)

        self.port_scan_alert()

    def should_stop_capturing(self, packet):
        return not self.is_capturing_active

    def stop_packet_capture(self):
        self.is_capturing_active = False

    def new_device_check(self, packet):
        dora = {"1": "discover", "discover": "1", "2": "offer", "offer": "2",
                "3": "request", "request": "3", "5": "ack", "ack": "5"}

        dhcp_options = packet[DHCP].options
        dhcp_type = None

        # For each option, get the DHCP type
        for option in dhcp_options:
            if not isinstance(option, tuple):  # If option is not a tuple data type
                continue
            if isinstance(option, tuple) and (option[0] == "message-type" or option[0] == 53):
                dhcp_type = str(option[1]).lower()  # DORA or 1-4
                break

        # Check if DHCP DORA (new device wants to join the network)
        if dhcp_type in ('request', '3'):  # Should be 1/3/5 D/R/A, but read WORD

            src_mac = packet[Ether].src.upper()  # Device/Client MAC
            src_name = device_db.get_name(src_mac)  # Check device in DB

            try:
                src_vendor = MacLookup().lookup(src_mac)
            except Exception:
                src_vendor = None

            offered_ip = None
            dhcp_leasetime = None
            dhcp_hostname = None

            if packet.haslayer('BOOTP'):
                offered_ip = packet['BOOTP'].yiaddr  # Offered IP addr to client

            for option in dhcp_options:
                if not isinstance(option, tuple):  # If option is not a tuple data type
                    continue
                if (isinstance(option, tuple) and (option[0] == "requested_addr" or option[0] == 50) and
                        offered_ip == "0.0.0.0"):
                    offered_ip = option[1]  # Requested IP addr to client
                    continue
                if isinstance(option, tuple) and (option[0] == "lease_time" or option[0] == 51):
                    dhcp_leasetime = timedelta(seconds=option[1]).days  # Lease Time
                    continue
                if isinstance(option, tuple) and (option[0] == "hostname" or option[0] == 12):
                    dhcp_hostname = option[1]  # Host Name
                    continue

            dhcp_type = f"{dhcp_type} ({dora.get(dhcp_type)})"

            if src_name is None:  # If device doesn't exists in db / If new device
                a = Alert(datetime.now(),  # Time
                          "INFO",          # Severity
                          "New Device",    # Category
                          f"{src_mac} ({src_vendor or "Unknown Vendor"}) just joined the network. "
                          f"The offered IP address is {offered_ip or "Unknown"} [DHCP {dhcp_type}]. "
                          f"This device can use this IP address for {dhcp_leasetime or "Unknown"} days.",  # Message
                          f"{src_mac} ({src_vendor or "Unknown Vendor"}) just joined the network.\n"
                          f"The offered IP address is {offered_ip or "Unknown"}.",  # Noti
                          f"If you recognize the device, add it to the device list. "
                          f"If not, disconnect it or change your Wi-Fi password.",  # Suggestion
                          {"mac": src_mac,
                           "ip": offered_ip or "Unknown",
                           "vendor": src_vendor or "Unknown",
                           "hostname": dhcp_hostname or "Unknown",
                           "leasetime": dhcp_leasetime or "Unknown",
                           "type": dhcp_type})  # Evidence
                alert_manager.add_alert(a)

            else:
                a = Alert(datetime.now(),           # Time
                          "INFO",                   # Severity
                          f"{src_name} Connected",  # Category
                          f"{src_name} just joined the network. "
                          f"The offered IP address is {offered_ip or "Unknown"} [DHCP {dhcp_type}]. "
                          f"This device can use this IP address for {dhcp_leasetime or "Unknown"} days.",  # Message
                          f"{src_name} just joined the network.\n"
                          f"The offered IP address is {offered_ip or "Unknown"}.",  # Noti
                          f"If you weren't expecting this device to connect, "
                          f"consider disconnecting it or verifying the user.",      # Suggestion
                          {"mac": src_mac,
                           "ip": offered_ip or "Unknown",
                           "vendor": src_vendor or "Unknown",
                           "hostname": src_name,
                           "leasetime": dhcp_leasetime or "Unknown",
                           "type": dhcp_type})  # Evidence
                alert_manager.add_alert(a)

    def arp_scan_check(self, packet):
        now = time.time()
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc.upper()
        target_ip = packet[ARP].pdst

        if src_mac == self.mac:
            return

        tracker = self.arp_scan_check_tracker.get(src_mac)
        if tracker is None:
            self.arp_scan_check_tracker[src_mac] = [(now, target_ip)]
        else:
            tracker.append((now, target_ip))

            cutoff = now - self.arp_scan_check_duration
            self.arp_scan_check_tracker[src_mac] = [(t, ip) for (t, ip) in tracker if t > cutoff]

            total_targets = len(set(ip for (t, ip) in self.arp_scan_check_tracker[src_mac]))

            if total_targets > self.arp_scan_check_threshold:
                src_name = device_db.get_name(src_mac)  # Check device in DB
                try:
                    src_vendor = MacLookup().lookup(src_mac)
                except Exception:
                    src_vendor = None

                a = Alert(datetime.now(),   # Time
                          "WARNING",        # Severity
                          f"Host Scan",     # Category
                          f"{src_name or src_ip} scanned for {total_targets}+ hosts in less than "
                          f"{self.arp_scan_check_duration} seconds.",  # Message
                          f"Possible Host Scan Detected from {src_name or src_ip}.",    # Noti
                          f"If unknown, disconnect the device from the network.",       # Suggestion
                          {"hostname": src_name or "Unknown",
                           "ip": src_ip,
                           "mac": src_mac,
                           "vendor": src_vendor or "Unknown",
                           "total_hosts_scanned": total_targets})  # Evidence
                alert_manager.add_alert(a)

                self.arp_scan_check_tracker[src_mac].clear()

    def tcp_syn_scan_check(self, packet):
        now = time.time()
        src_ip = packet[IP].src
        src_mac = packet[Ether].src.upper()
        target_ip = packet[IP].dst
        target_port = packet[TCP].dport

        if src_mac == self.mac:
            return

        tracker = self.port_scan_check_tracker.get(src_mac)
        if tracker is None:
            self.port_scan_check_tracker[src_mac] = {
                "src_ip": src_ip,
                "ports": {target_port},
                "targets": {target_ip},
                "start_time": now,
                "last_seen": now,
                "alerted": False
            }
            return

        tracker["ports"].add(target_port)
        tracker["targets"].add(target_ip)
        tracker["last_seen"] = now

        if now - tracker["start_time"] > self.port_scan_check_duration:
            tracker["ports"].clear()
            tracker["targets"].clear()
            tracker["start_time"] = now
            tracker["alerted"] = False
            return

    def port_scan_alert(self):
        now = time.time()

        for src_mac, tracker in list(self.port_scan_check_tracker.items()):
            if tracker["alerted"]:
                continue

            if now - tracker["last_seen"] < self.port_scan_check_alert_cooldown:
                continue

            total_ports = len(tracker["ports"])

            if total_ports >= self.port_scan_check_threshold:
                src_name = device_db.get_name(src_mac)
                duration = round(tracker["last_seen"] - tracker["start_time"], 2)

                a = Alert(
                    datetime.now(),
                    "WARNING",      # Severity
                    "Port Scan",    # Category
                    f"{src_name or tracker["src_ip"]} scanned for {total_ports} ports in {duration} seconds.",  # Message
                    f"Possible Port Scan Detected from {src_name or tracker["src_ip"]}.",  # Noti
                    "If unknown, disconnect the device from the network.",
                    {
                        "hostname": src_name or "Unknown",
                        "ip": tracker["src_ip"],
                        "mac": src_mac,
                        "targets": list(tracker["targets"]),
                        "ports": sorted(tracker["ports"]),
                        "total_ports": total_ports,
                        "duration": duration
                    }
                )
                alert_manager.add_alert(a)

                tracker["alerted"] = True


# Window for packet details
class PacketDetailsPopup(QDialog):
    def __init__(self, item, parent=None):
        super().__init__(parent)

        packet = item["packet"]
        packet_summary = item["packet_summary"]

        self.setWindowTitle(packet_summary)
        self.setWindowIcon(QIcon('./NetMon-img/NetMon-Logo-Alt-TP.png'))
        self.resize(480, 340)

        packet_details_layout = QVBoxLayout(self)

        packet_details_summary = QLabel(f"<b>Summary:</b> {packet.summary()}")
        packet_details_summary.setWordWrap(True)

        packet_details_details = QTreeWidget()
        packet_details_details.setHeaderLabels(["Field", "Value"])
        packet_details_details.setHeaderHidden(True)
        #packet_details_details.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        packet_details_details.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        packet_details_details.header().setSectionResizeMode(1, QHeaderView.Stretch)

        layer = packet
        while layer:
            packet_details_details_item = QTreeWidgetItem([layer.name])
            packet_details_details.addTopLevelItem(packet_details_details_item)
            for field_name, field_value in layer.fields.items():
                value = str(field_value)
                packet_details_details_item_child = QTreeWidgetItem([field_name, value])
                packet_details_details_item.addChild(packet_details_details_item_child)
            layer = layer.payload

        packet_details_details.setStyleSheet("""
                    QTreeWidget {
                        outline: none;
                    }
                    QTreeWidget::item {
                        padding: 4px 6px;
                    }
                    QTreeWidget::item:selected {
                        background-color: #e70e06;
                    }
                """)

        packet_details_layout.addWidget(packet_details_summary)
        packet_details_layout.addWidget(packet_details_details)


# Scan host
class HostDiscover(QThread):
    host_discovered_signal = Signal(str, object, str)

    def __init__(self, iface, ip, mac, subnet):
        super().__init__()
        self.iface = iface
        self.mac_address = mac
        self.ip_address = ip
        self.ip_subnet = subnet
        self.network_id = ipaddress.ip_network(f"{self.ip_address}/{self.ip_subnet}", strict=False)

        self.mac_ip = {}

    def run(self):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.network_id)), iface=self.iface, timeout=2)
        total_host = f"({len(ans)} Active Devices)"

        for packet in ans:
            host_data = PacketUtils.host_info(packet, self.mac_address)

            if host_data.host_mac not in self.mac_ip:
                self.mac_ip[host_data.host_mac] = {
                    "name": host_data.host_name,
                    "ip": []
                }
            if host_data.host_ip not in self.mac_ip[host_data.host_mac]["ip"]:
                self.mac_ip[host_data.host_mac]["ip"].append(host_data.host_ip)

            if host_data.host_name == "Unknown" and host_data.host_vendor != "Unknown":
                host_name = f"{host_data.host_name} ({host_data.host_vendor})"
            else:
                host_name = host_data.host_name

            discovered_host = f"{host_name}\n{host_data.host_ip}\n{host_data.host_mac}"
            self.host_discovered_signal.emit(discovered_host, packet, total_host)

        self.duplicate_mac_check(self.mac_ip)

    def duplicate_mac_check(self, mac_ip):
        for mac, name_ips in mac_ip.items():
            hostname = name_ips["name"]
            ip_total = len(name_ips["ip"])
            ips = name_ips["ip"]

            if ip_total > 1:
                a = Alert(datetime.now(),
                          "WARNING",        # Severity
                          "MAC Spoofing",   # Category
                          f"MAC address of {hostname} ({mac}) is being used by {ip_total} different IPs "
                          f"({", ".join(ips)}). ",  # Message
                          f"MAC spoofing detected: {hostname} ({mac}) appeared from multiple IPs.",  # Noti
                          f"Check which device is supposed to use this MAC address. "
                          f"If an unknown device appears, disconnect it.",  # Suggestion
                          {"hostname": hostname,
                           "mac": mac,
                           "total_ip": ip_total,
                           "ips": ips}
                          )
                alert_manager.add_alert(a)


# Window for host details
class HostDetailsPopup(QDialog):
    def __init__(self, host, mac, parent=None):
        super().__init__(parent)
        self.mac_address = mac

        self.setWindowIcon(QIcon('./NetMon-img/NetMon-Logo-Alt-TP.png'))
        self.resize(288, 250)

        self.host_data = PacketUtils.host_info(host, self.mac_address)

        if self.host_data.host_name == "Unknown" and self.host_data.host_vendor != "Unknown":
            host_title = f"{self.host_data.host_name} ({self.host_data.host_vendor})"
        elif self.host_data.host_name == "Unknown" and self.host_data.host_vendor == "Unknown":
            host_title = f"{self.host_data.host_name} ({self.host_data.host_ip})"
        else:
            host_title = f"{self.host_data.host_name}"

        self.setWindowTitle(host_title)

        host_details = (f"IP\t: {self.host_data.host_ip}\nMAC\t: {self.host_data.host_mac}\nVendor\t: "
                        f"{self.host_data.host_vendor}")

        host_details_security_tab = QTabWidget()

        host_details_tab = QWidget()
        self.host_details_label = QLabel(host_details)
        host_details_tab_layout = QVBoxLayout(host_details_tab)
        host_details_tab_layout.setAlignment(Qt.AlignCenter)
        host_details_tab_layout.addWidget(self.host_details_label)
        host_details_security_tab.addTab(host_details_tab, "Overview")

        host_security_tab = QWidget()
        self.host_security_results = QLabel("No security check run yet.")
        host_security_tab_layout = QVBoxLayout(host_security_tab)
        host_security_tab_layout.setAlignment(Qt.AlignCenter)
        host_security_tab_layout.addWidget(self.host_security_results)
        host_details_security_tab.addTab(host_security_tab, "Security Report")

        host_details_security_tab.setStyleSheet("""
                    QTabWidget::pane{
                        background-color: #2d2d2d;                        
                        border-bottom-left-radius: 6px;
                        border-bottom-right-radius: 6px;
                        border-top-right-radius: 6px;
                    }
                    QTabBar::tab{
                        background-color: #242424;
                        padding: 3px 15px;
                        margin-right: 2px;
                        border-top-left-radius: 5px;
                        border-top-right-radius: 5px;
                    }
                    QTabBar::tab:selected{
                        background-color: #2d2d2d;
                        font-weight: bold;
                    }
                    QTabBar::tab:!selected{
                        margin-top: 2px;
                    }
                    QTabBar::tab:hover{
                        background-color: #2d2d2d;
                        margin-top: 0;
                    }
                """)

        self.host_add_change_in = QLineEdit()
        self.host_add_change_in.setPlaceholderText("Name")
        self.host_add_change_in.setStyleSheet("""
                    QLineEdit{
                        border:none;
                        border-bottom:1px solid rgba(231, 14, 6, 0.5);
                        background-color:transparent;
                        padding: 0 4px 0 4px;
                    }
                    QLineEdit:focus{
                        border-bottom:1px solid #e70e06;
                        background-color:transparent;
                    }
                """)

        self.host_add_change_btn = QPushButton()
        if device_db.get_name(self.host_data.host_mac) is not None:
            self.host_add_change_btn.setText("Change name")
        else:
            self.host_add_change_btn.setText("Add device")
        self.host_add_change_btn.setStyleSheet("""
                    QPushButton{
                        border:1px solid #e70e06;
                        border-radius:4px;
                    }
                    QPushButton:hover{
                        background-color:#e70e06;
                        color:black;
                    }
                """)

        self.host_details_check = QPushButton("Security Check")
        self.host_details_check.setStyleSheet("""
                    QPushButton:disabled{
                        border:1px solid rgba(231, 14, 6, 0.5);
                        border-radius:4px;
                    }
                    QPushButton:enabled{
                        border:1px solid #e70e06;
                        border-radius:4px;
                    }
                    QPushButton:hover{
                        background-color:#e70e06;
                        color:black;
                    }
                """)

        self.host_details_dc = QPushButton("Disconnect")
        self.host_details_dc.setStyleSheet("""
                    QPushButton{
                        border:1px solid #e70e06;
                        border-radius:4px;
                    }
                    QPushButton:hover{
                        background-color:#e70e06;
                        color:black;
                    }
                """)

        host_details_layout_main = QVBoxLayout(self)
        host_details_layout_db = QHBoxLayout()
        host_details_layout_bot = QHBoxLayout()

        host_details_layout_main.addWidget(host_details_security_tab)
        host_details_layout_db.addWidget(self.host_add_change_in, 1)
        host_details_layout_db.addWidget(self.host_add_change_btn, 1)
        host_details_layout_main.addLayout(host_details_layout_db)
        host_details_layout_bot.addWidget(self.host_details_check)
        host_details_layout_bot.addWidget(self.host_details_dc)
        host_details_layout_main.addLayout(host_details_layout_bot)
        host_details_layout_main.setSpacing(10)

        self.host_details_check.clicked.connect(self.security_check)
        self.host_add_change_btn.clicked.connect(self.add_change_host_db)
        self.host_details_dc.clicked.connect(self.dc_host_netw)

    def add_change_host_db(self):
        host_name = self.host_add_change_in.text().strip()
        if not host_name:
            QMessageBox.warning(self, "Error", "Please enter a name.")
            return

        host_mac = self.host_data.host_mac
        device_db.save_name(host_mac, host_name)

        if device_db.get_name(host_mac) == host_name:
            QMessageBox.information(self, "Saved", f"Host '{host_name}' has been saved/updated!"
                                    f"\nRescan to see the changes!")

        self.close()

    def dc_host_netw(self):
        return

    def security_check(self):
        self.host_details_check.setDisabled(True)
        QTimer.singleShot(1000, lambda: self.host_details_check.setEnabled(True))

        self.host_security_results.clear()
        self.check = HostSecurityCheck(self.host_data.host_ip)
        self.check.security_result_signal.connect(self.security_check_results)
        self.check.start()

    def security_check_results(self, port, status):
        old_result = self.host_security_results.text()
        new_result = f"{port}\t: {status}"

        if old_result:
            self.host_security_results.setText(old_result + "\n" + new_result)
        else:
            self.host_security_results.setText(new_result)


class HostSecurityCheck(QThread):
    security_result_signal = Signal(int, str)

    def __init__(self, host_ip):
        super().__init__()
        self.host_ip = host_ip
        self.ports = [20, 22, 53, 80, 139, 443]

    def run(self):
        pkt = IP(dst=self.host_ip)/TCP(flags="S", dport=self.ports)
        ans, unans = sr(pkt, timeout=2, retry=0, verbose=0)

        for sent, received in ans:
            if received.haslayer(TCP):

                if received[TCP].flags & 0x12 == 0x12:
                    port = received[TCP].sport if received[TCP].sport in self.ports else sent[TCP].dport
                    port_name = socket.getservbyport(port, "tcp")
                    status = f"OPEN ({port_name})"
                    self.security_result_signal.emit(port, status)

                elif received[TCP].flags & 0x14 == 0x14 or received[TCP].flags & 0x04 == 0x04:
                    port = received[TCP].sport if received[TCP].sport in self.ports else sent[TCP].dport
                    port_name = socket.getservbyport(port, "tcp")
                    status = f"CLOSED ({port_name})"
                    self.security_result_signal.emit(port, status)

            else:
                port = sent[TCP].dport
                port_name = socket.getservbyport(port, "tcp")
                status = f"FILTERED ({port_name})"
                self.security_result_signal.emit(port, status)


# Alert Dataclass
@dataclass
class Alert:
    timestamp: datetime
    severity: str       # INFO, WARNING, CRITICAL
    category: str       # New Device, DDoS, MitM
    message: str        # Details
    notification: str   # Noti Message
    suggestion: str     # Mitigation suggestion
    evidence: dict      # Dict - MAC, IP


# Alert
class AlertManager(QObject):
    alert_signal = Signal(object)

    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.alerts = []            # Alert history
        self.dedupe = {}            # De-duplication
        self.dedupe_seconds = 5     # De-duplication timer

    def _dedupe_key(self, alert: Alert):
        if alert.category == "New Device":
            return f"newdevice:{alert.evidence.get('src_mac')}"
        return f"{alert.category}:{str(alert.evidence)}"

    def add_alert(self, alert: Alert):
        with self.lock:
            self.alerts.append(alert)

        try:
            self.alert_signal.emit(alert)
        except Exception:
            pass

        notification.notify(  # Noti
            title=f"[{alert.severity}] {alert.category}",
            message=alert.notification,
            timeout=5,
            app_name="NetMon",
            app_icon='./NetMon-img/NetMon-Logo-Alt-TP.ico'
        )


# Window for alert details
class AlertDetailsPopup(QDialog):
    def __init__(self, alert, parent=None):
        super().__init__(parent)

        self.setFixedWidth(360)
        self.setWindowTitle(f"{alert.timestamp:%I:%M %p} [{alert.severity}] {alert.category}")
        self.setWindowIcon(QIcon('./NetMon-img/NetMon-Logo-Alt-TP.png'))

        alert_details_layout_v = QVBoxLayout(self)
        alert_details_layout_h = QHBoxLayout()
        alert_details_layout_v.setSpacing(10)

        alert_details_layout_v.addWidget(QLabel(f"<b>{alert.timestamp.strftime("%Y-%m-%d %I:%M:%S %p")}</b>"))

        message = QLabel(f"{alert.message}")
        suggestion = QLabel(f"{alert.suggestion}")
        message.setWordWrap(True)
        message.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        suggestion.setWordWrap(True)
        suggestion.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        if alert.category == "New Device":
            alert_details_layout_v.addWidget(message)
            alert_details_layout_v.addWidget(QLabel(f"MAC\t\t: {alert.evidence['mac']}\n"
                                                    f"Offered IP\t: {alert.evidence['ip']}\n"
                                                    f"Vendor\t\t: {alert.evidence['vendor']}\n"
                                                    f"Hostname\t: {alert.evidence['hostname']}\n"
                                                    f"Lease Time\t: {alert.evidence['leasetime']} days\n"
                                                    f"DHCP\t\t: {alert.evidence['type']}"))
            alert_details_layout_v.addWidget(suggestion)

            self.host_add_in = QLineEdit()
            self.host_add_in.setPlaceholderText("Name")
            self.host_add_btn = QPushButton("Add device")
            alert_details_layout_h.addWidget(self.host_add_in)
            alert_details_layout_h.addWidget(self.host_add_btn)
            alert_details_layout_v.addLayout(alert_details_layout_h)

            self.host_dc_btn = QPushButton(f"Disconnect {alert.evidence['mac']}")
            alert_details_layout_v.addWidget(self.host_dc_btn)

            self.host_add_in.setStyleSheet("""
                        QLineEdit{
                            border:none;
                            border-bottom:1px solid rgba(231, 14, 6, 0.5);
                            background-color:transparent;
                            padding: 0 4px 0 4px;
                        }
                        QLineEdit:focus{
                            border-bottom:1px solid #e70e06;
                            background-color:transparent;
                        }
                    """)
            self.host_add_btn.setStyleSheet("""
                        QPushButton{
                            border:1px solid #e70e06;
                            border-radius:4px;
                            width:108px;
                        }
                        QPushButton:hover{
                            background-color:#e70e06;
                            color:black;
                        }
                    """)
            self.host_dc_btn.setStyleSheet("""
                        QPushButton{
                            border:1px solid #e70e06;
                            border-radius:4px;
                        }
                        QPushButton:hover{
                            background-color:#e70e06;
                            color:black;
                        }
                    """)

            self.host_add_btn.clicked.connect(lambda: self.add_host_db(alert))
            self.host_dc_btn.clicked.connect(lambda: self.dc_host_netw(alert))

        elif "Connected" in alert.category:
            alert_details_layout_v.addWidget(message)
            alert_details_layout_v.addWidget(QLabel(f"MAC\t\t: {alert.evidence['mac']}\n"
                                                    f"Offered IP\t: {alert.evidence['ip']}\n"
                                                    f"Vendor\t\t: {alert.evidence['vendor']}\n"
                                                    f"Name\t\t: {alert.evidence['hostname']}\n"
                                                    f"Lease Time\t: {alert.evidence['leasetime']} days\n"
                                                    f"DHCP\t\t: {alert.evidence['type']}"))
            alert_details_layout_v.addWidget(suggestion)

            self.host_dc_btn = QPushButton(f"Disconnect {alert.evidence['hostname']}")
            alert_details_layout_v.addWidget(self.host_dc_btn)

            self.host_dc_btn.setStyleSheet("""
                                                QPushButton{
                                                    border:1px solid #e70e06;
                                                    border-radius:4px;
                                                }
                                                QPushButton:hover{
                                                    background-color:#e70e06;
                                                    color:black;
                                                }
                                            """)

            self.host_dc_btn.clicked.connect(lambda: self.dc_host_netw(alert))

        elif alert.category == "Traffic Spike":
            alert_details_layout_v.addWidget(message)
            alert_details_layout_v.addWidget(QLabel(f"Current No. of Packets\t: {alert.evidence['current_pkt_count']}\n"
                                                    f"Average No. of Packets\t: {alert.evidence['avg_pkt_count']}\n"
                                                    f"Time on Graph\t\t: {alert.evidence['graph_time']}"))
            alert_details_layout_v.addWidget(suggestion)

        elif alert.category == "Host Scan":
            alert_details_layout_v.addWidget(message)
            alert_details_layout_v.addWidget(QLabel(f"Hostname\t: {alert.evidence['hostname']}\n"
                                                    f"IP\t\t: {alert.evidence['ip']}\n"
                                                    f"MAC\t\t: {alert.evidence['mac']}\n"
                                                    f"Vendor\t\t: {alert.evidence['vendor']}"))
            alert_details_layout_v.addWidget(suggestion)

            self.host_dc_btn = QPushButton(f"Disconnect {alert.evidence['hostname'] if alert.evidence['hostname'] 
                                           != "Unknown" else alert.evidence['mac']}")
            alert_details_layout_v.addWidget(self.host_dc_btn)

            self.host_dc_btn.setStyleSheet("""
                                    QPushButton{
                                        border:1px solid #e70e06;
                                        border-radius:4px;
                                    }
                                    QPushButton:hover{
                                        background-color:#e70e06;
                                        color:black;
                                    }
                                """)

            self.host_dc_btn.clicked.connect(lambda: self.dc_host_netw(alert))

        elif alert.category == "MAC Spoofing":
            alert_details_layout_v.addWidget(message)
            alert_details_layout_v.addWidget(QLabel(f"Hostname\t: {alert.evidence['hostname']}\n"
                                                    f"MAC\t\t: {alert.evidence['mac']}\n"
                                                    f"Total IP\t: {alert.evidence['total_ip']}\n"
                                                    f"IPs\t\t: {", ".join(alert.evidence['ips'])}"))
            alert_details_layout_v.addWidget(suggestion)

            self.host_dc_ip = QComboBox()
            for ip in alert.evidence['ips']:
                self.host_dc_ip.addItem(ip)
            self.host_dc_btn = QPushButton(f"Disconnect")

            alert_details_layout_h.addWidget(self.host_dc_ip)
            alert_details_layout_h.addWidget(self.host_dc_btn)
            alert_details_layout_v.addLayout(alert_details_layout_h)

            self.host_dc_btn.setStyleSheet("""
                                    QPushButton{
                                        border:1px solid #e70e06;
                                        border-radius:4px;
                                    }
                                    QPushButton:hover{
                                        background-color:#e70e06;
                                        color:black;
                                    }
                                """)

            self.host_dc_btn.clicked.connect(lambda: self.dc_host_netw(alert))

        elif alert.category == "Port Scan":
            alert_details_layout_v.addWidget(message)
            alert_details_layout_v.addWidget(QLabel(f"Hostname\t: {alert.evidence['hostname']}\n"
                                                    f"IP\t\t: {alert.evidence['ip']}\n"
                                                    f"MAC\t\t: {alert.evidence['mac']}\n"
                                                    f"Target IP\t: {alert.evidence['targets']}\n"
                                                    f"Total Ports\t: {alert.evidence['total_ports']}\n"
                                                    f"Duration\t: {alert.evidence['duration']}s"))
            alert_details_layout_v.addWidget(suggestion)

    def add_host_db(self, alert):
        host_name = self.host_add_in.text().strip()

        if not host_name:
            QMessageBox.warning(self, "Error", "Please enter a name.")
            return

        host_mac = alert.evidence['mac']
        device_db.save_name(host_mac, host_name)

        if device_db.get_name(host_mac) == host_name:
            QMessageBox.information(self, "Saved", f"Host '{host_name}' has been saved!"
                                                   f"\nScan host to see the updated list!")

        self.close()

    def dc_host_netw(self, alert):
        return


# Packet Helper Class
class PacketUtils:
    @staticmethod
    def packet_title(packet, network_id):  # Packet Title for list
        src_name, dst_name = "", ""

        if IP in packet and Ether in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_mac = packet[Ether].src.upper()
            dst_mac = packet[Ether].dst.upper()

            # SOURCE
            if ipaddress.ip_address(src_ip) in network_id:  # If src in same network
                src_name = device_db.get_name(src_mac) or f"{src_ip} [INT]"
            else:  # If src not in the same network
                src_name = src_ip + " [EXT]"
                """
                try:
                    src_name = socket.gethostbyaddr(src_ip)[0]
                except:
                    src_name = src_ip
                """

            # DESTINATION
            if ipaddress.ip_address(dst_ip) in network_id:  # If dst in same network
                dst_name = device_db.get_name(dst_mac) or f"{dst_ip} [INT]"
            else:  # If dst not in the same network
                dst_name = dst_ip + " [EXT]"
                """
                try:
                    dst_name = socket.gethostbyaddr(dst_ip)[0]
                except:
                    dst_name = dst_ip
                """

        elif IP in packet and Ether not in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if ipaddress.ip_address(src_ip) in network_id:
                src_name = packet[IP].src + " [INT]"
            else:
                src_name = packet[IP].src + " [EXT]"

            if ipaddress.ip_address(dst_ip) in network_id:
                dst_name = packet[IP].dst + " [INT]"
            else:
                dst_name = packet[IP].dst + " [EXT]"

        elif IP not in packet and Ether in packet:
            src_mac = packet[Ether].src.upper()
            dst_mac = packet[Ether].dst.upper()
            src_name = device_db.get_name(src_mac) or src_mac
            dst_name = device_db.get_name(dst_mac) or dst_mac

        layer = packet
        prev_layer = None
        while layer.payload:
            prev_layer = layer
            layer = layer.payload

        last_layer = layer.name
        second_last_layer = prev_layer.name if prev_layer else None

        if second_last_layer:
            packet_layers = f"{second_last_layer}/{last_layer}"
        else:
            packet_layers = last_layer

        packet_summary = f"{src_name} → {dst_name} ({packet_layers})"
        return packet_summary

    @staticmethod
    def host_info(packet, my_mac):
        host_ip = packet[1][0][0].psrc
        host_mac = packet[1][0][0].hwsrc.upper()

        if host_mac != my_mac:
            host_name = device_db.get_name(host_mac) or "Unknown"
        else:
            host_name = f"{device_db.get_name(host_mac) or "Unknown"} (You)"

        try:
            host_vendor = MacLookup().lookup(host_mac)
        except Exception:
            host_vendor = "Unknown"

        HostInfo = namedtuple("HostInfo", ["host_ip", "host_mac", "host_name", "host_vendor"])
        host_data = HostInfo(host_ip, host_mac, host_name, host_vendor)

        return host_data


class NetworkUtils():
    @staticmethod
    def get_interfaces():
        interfaces_details = {}
        for iface_name, addrs in psutil.net_if_addrs().items():
            ip, mac, netmask, network, subnet = None, None, None, None, None
            for addr in addrs:
                if addr.family.name == "AF_INET":
                    ip = addr.address
                    netmask = addr.netmask
                if addr.family.name == "AF_LINK":
                    mac = addr.address

            if ip and netmask:
                try:
                    iface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
                    network = str(iface.network.network_address)
                    subnet = iface.network.prefixlen
                except Exception:
                    pass

            interfaces_details[iface_name] = {"ip": ip,
                                              "mac": mac,
                                              "netmask": netmask,
                                              "network": network,
                                              "subnet": subnet,
                                              "network_subnet": f"{network}/{subnet}" if network and subnet else None}

        return interfaces_details

    @staticmethod
    def map_interfaces():
        interfaces_details = NetworkUtils.get_interfaces()

        mac_to_name = {v["mac"]: k for k, v in interfaces_details.items() if v["mac"]}
        ip_to_name = {v["ip"]: k for k, v in interfaces_details.items() if v["ip"]}

        interfaces = {}
        for iface in get_if_list():
            try:
                mac = get_if_hwaddr(iface).upper()
                ip = get_if_addr(iface)

                if (not ip or ip == "0.0.0.0") and (not mac or mac == "00:00:00:00:00:00"):
                    continue

                iface_name = mac_to_name.get(mac) or ip_to_name.get(ip) or iface
                extra = interfaces_details.get(iface_name, {})
                interfaces[iface] = {"iface_name": iface_name,
                                     "ip": ip,
                                     "mac": mac,
                                     "netmask": extra.get("netmask"),
                                     "network": extra.get("network"),
                                     "subnet": extra.get("subnet"),
                                     "network_subnet": extra.get("network_subnet")}
            except Exception:
                continue
        return interfaces


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        # INTERFACE
        self.interfaces = NetworkUtils.map_interfaces()
        self.iface = None
        self.network_subnet = None
        self.ip = None
        self.mac = None
        self.subnet = None

        # UI
        self.initUI()
        self.is_capturing_active = False
        self.packet_capture_thread = None

        # GRAPH
        self.packet_count_y = []
        self.time_stamps_x = []
        self.graph_packet_count = 0
        self.graph_elapsed_time = 0
        self.graph_timer = QTimer()
        self.graph_timer.setInterval(1000)
        self.graph_timer.timeout.connect(self.update_graph)

    def initUI(self):

        # ----- GUI
        self.setWindowTitle("NetMon")

        # ----- Asking user to choose interface
        iface_label = QLabel("Interface: ")
        iface_label.setStyleSheet("font-weight:bold")
        self.iface_list = QComboBox()
        for iface_npf, iface_info in self.interfaces.items():
            interface = f"{iface_info['iface_name']}"
            if interface == "Wi-Fi":
                self.iface_list.insertItem(0, "Wi-Fi")
                self.iface_list.setCurrentIndex(0)
                continue
            self.iface_list.addItem(interface)

        subnet_label = QLabel("Network Size: ")
        subnet_label.setStyleSheet("font-weight:bold")
        self.subnet_list = QComboBox()

        # ----- Start capture button
        self.start_btn = QPushButton("Start")
        self.start_btn.setStyleSheet("""
                    QPushButton:enabled{
                        border:1px solid #e70e06;
                        border-radius:4px;
                    }
                    QPushButton:hover{
                        background-color:#e70e06;
                        color:black;
                    }
                    QPushButton:disabled{
                        border:1px solid rgba(231, 14, 6, 0.5);
                        border-radius:4px;
                    }
                """)
        self.start_btn.clicked.connect(self.capture)

        # Extra
        self.network_id_display = QLabel()
        self.network_id_display.setStyleSheet("""
                    QLabel{
                        color: #666666;
                    }
                """)
        self.network_id_display.setAlignment(Qt.AlignCenter)

        self.subnet_list_items()
        self.iface_list.currentIndexChanged.connect(self.subnet_list_items)

        # ----- Capture Section
        capture_section_label = QLabel("Capture")
        capture_section_label.setStyleSheet("font-weight:bold")
        self.captured_packet = QListWidget()
        self.captured_packet.setFixedWidth(380)
        self.captured_packet.setStyleSheet("""
                    QListWidget{
                        show-decoration-selected:1;
                    }
                    QListWidget::item{
                        border-radius:0;
                        margin:0 3px 0 3px;
                    }
                    QListWidget::item:hover{
                        background-color:#393939;
                        border-radius:0;
                        border-left:2px solid rgba(231, 14, 6, 0.5);
                    }
                    QListWidget::item:selected {
                        background-color:#393939;
                        border-left:2px solid #e70e06;
                    }
                """)
        self.captured_packet.setFocusPolicy(Qt.NoFocus)
        self.captured_packet.itemClicked.connect(self.packet_details)  # When user click on a (one) list item

        # ----- Host Section
        host_section_label = QLabel("Host")
        host_section_label.setStyleSheet("font-weight:bold")
        self.host_total = QLabel("")
        self.host_scan_btn = QPushButton("Scan")
        self.host_scan_btn.setStyleSheet("""
                    QPushButton:disabled{
                        border:1px solid rgba(231, 14, 6, 0.5);
                        border-radius:4px;
                    }
                    QPushButton:enabled{
                        border:1px solid #e70e06;
                        border-radius:4px;
                    }
                    QPushButton:hover{
                        background-color:#e70e06;
                        color:black;
                    }
                """)
        self.host_scan_btn.setFixedWidth(100)
        self.host_scan_btn.setEnabled(False)
        self.host_scan_btn.clicked.connect(self.host)

        self.host_container = QListWidget()
        self.host_container.setStyleSheet("""
                    QListWidget{
                        show-decoration-selected:1;
                    }
                    QListWidget::item{
                        border-radius:0;
                    }
                    QListWidget::item:hover{
                        background-color:#393939;
                        border-radius:0;
                        border-left:2px solid rgba(231, 14, 6, 0.5);
                    }
                    QListWidget::item:selected {
                        background-color:#393939;
                        border-left:2px solid #e70e06;
                    }
                """)
        self.host_container.setFocusPolicy(Qt.NoFocus)
        self.host_container.setSpacing(7)
        self.host_container.itemClicked.connect(self.host_details)

        # ----- Alert Section
        alert_section_label = QLabel("Alert")
        alert_section_label.setStyleSheet("font-weight:bold")
        self.alert_container = QListWidget()
        self.alert_container.setStyleSheet("""
                    QListWidget{
                        show-decoration-selected:1;
                    }
                    QListWidget::item{
                        border-radius:0;
                    }
                    QListWidget::item:hover{
                        background-color:#393939;
                        border-radius:0;
                        border-left:2px solid rgba(231, 14, 6, 0.5);
                    }
                    QListWidget::item:selected {
                        background-color:#393939;
                        border-left:2px solid #e70e06;
                    }
                """)
        self.alert_container.setFocusPolicy(Qt.NoFocus)
        self.alert_container.setSpacing(3)
        self.alert_container.itemClicked.connect(self.alert_details)
        alert_manager.alert_signal.connect(self.update_alert)

        # ----- Graph
        self.graph_container = pg.PlotWidget()
        self.graph_container.setLabel("left", "Packets")
        self.graph_container.setLabel("bottom", "Time (s)")
        self.graph_container.setFixedHeight(235)
        self.graph_container.setBackground((45, 45, 45))  # Color
        self.graph_container.setMouseEnabled(x=False, y=False)
        self.graph_container.hideButtons()
        self.graph_container.getAxis("left").setStyle(tickFont=QFont("Arial", 8))
        self.graph_container.getAxis("bottom").setStyle(tickFont=QFont("Arial", 8))
        self.graph_container.setXRange(0, 30, padding=0)
        self.graph_line = self.graph_container.plot(pen=pg.mkPen("w", width=1))  # Line on graph

        # --- Layout
        # --- --- Top Layout
        iface_layout = QHBoxLayout()
        iface_layout.addWidget(iface_label)
        iface_layout.addWidget(self.iface_list, stretch=1)

        subnet_layout = QHBoxLayout()
        subnet_layout.addWidget(subnet_label)
        subnet_layout.addWidget(self.subnet_list, stretch=1)

        start_btn_layout = QVBoxLayout()
        start_btn_layout.addLayout(iface_layout)
        start_btn_layout.addLayout(subnet_layout)
        start_btn_layout.addWidget(self.start_btn)
        start_btn_layout.setContentsMargins(0, 0, 0, 10)

        # --- --- Capture Layout
        capture_layout = QVBoxLayout()
        capture_layout.addWidget(capture_section_label)
        capture_layout.addWidget(self.captured_packet)

        # --- --- HOST LAYOUT
        host_scan_layout = QHBoxLayout()
        host_scan_layout.addWidget(host_section_label)
        host_scan_layout.addWidget(self.host_total)
        host_scan_layout.addWidget(self.host_scan_btn)

        host_layout = QVBoxLayout()
        host_layout.addLayout(host_scan_layout)
        host_layout.addWidget(self.host_container)

        # --- --- --- Alert Layout
        alert_layout = QVBoxLayout()
        alert_layout.addWidget(alert_section_label)
        alert_layout.addWidget(self.alert_container)

        # --- --- --- Graph Layout
        graph_layout = QVBoxLayout()
        graph_layout.addWidget(self.graph_container)

        # --- --- --- Main Layout
        main_layout = QGridLayout()
        main_layout.addLayout(start_btn_layout, 1, 2)
        main_layout.addLayout(host_layout, 2, 1)
        main_layout.addLayout(capture_layout, 2, 2)
        main_layout.addLayout(alert_layout, 2, 3)
        main_layout.addLayout(graph_layout, 3, 1, 3, 3)
        main_layout.addWidget(self.network_id_display, 1, 3)

        self.setLayout(main_layout)

    def subnet_list_items(self):
        subnet, network_subnet = None, None
        selected_iface_temp = self.iface_list.currentText()
        for iface_npf, iface_info in self.interfaces.items():
            if iface_info['iface_name'] in selected_iface_temp:
                subnet = iface_info['subnet']
                network_subnet = iface_info['network_subnet']
                break

        self.subnet_list.clear()

        perma_subnets = [subnet, 8, 16, 18, 22, 24, 26, 28]
        final_perma_subnets = sorted(set(x for x in perma_subnets if subnet <= x <= 28))  # , reverse=True)
        for i in final_perma_subnets:
            subnet_item = f"{i} (Full scan)" if i == subnet else i
            self.subnet_list.addItem(f"/{subnet_item}")

        self.network_id_display.clear()
        self.network_id_display.setText(f"Network ID\n{network_subnet}")

    def capture(self):

        if not self.is_capturing_active:

            self.iface_list.setEnabled(False)
            selected_iface_temp = self.iface_list.currentText()
            for iface_npf, iface_info in self.interfaces.items():
                if iface_info['iface_name'] in selected_iface_temp:
                    self.iface = iface_npf
                    self.network_subnet = iface_info['network_subnet']
                    self.ip = iface_info['ip']
                    self.mac = iface_info['mac']
                    self.subnet = iface_info['subnet']
                    break

            self.subnet_list.setEnabled(False)

            self.host_scan_btn.setEnabled(True)

            self.start_btn.setDisabled(True)
            QTimer.singleShot(2000, lambda: self.start_btn.setEnabled(True))  # Prevent spam
            self.start_btn.setText("Stop")

            self.captured_packet.clear()
            self.host_container.clear()
            self.host_total.clear()
            self.alert_container.clear()

            self.is_capturing_active = True

            # Creating thread for PacketCapture
            self.packet_capture_thread = PacketCapture(self.iface, self.network_subnet, self.mac, self.subnet)
            self.packet_capture_thread.packet_capture_signal.connect(self.update_capture)  # Connecting thread with UI
            self.packet_capture_thread.start()

            # GRAPH
            self.reset_graph()
            self.graph_timer.start()

        else:
            self.iface_list.setEnabled(True)
            self.subnet_list.setEnabled(True)

            self.host_scan_btn.setEnabled(False)

            self.start_btn.setDisabled(True)
            QTimer.singleShot(1000, lambda: self.start_btn.setEnabled(True))  # Prevent spam
            self.start_btn.setText("Start")

            if self.packet_capture_thread:
                self.packet_capture_thread.stop_packet_capture()

            self.is_capturing_active = False

            # GRAPH
            self.graph_timer.stop()

    # Update the captured packet(s) to the UI
    def update_capture(self, packet_summary, packet):
        packet_each = QListWidgetItem(packet_summary)  # Creating (one) list_widget's item - displaying packet_summary
        packet_each.setData(256, {"packet": packet, "packet_summary": packet_summary})  # Set the (one) list_widget's item
        self.captured_packet.addItem(packet_each)  # Adding the (one) list_widget's item to the list_widget's container

        if self.captured_packet.count() > 50:  # Limit the displayed pkts to 100 pkts only
            self.captured_packet.takeItem(0)

        # GRAPH
        self.graph_packet_count += 1

    # When user clicked on a (one) list item
    def packet_details(self, packet_each):
        packet = packet_each.data(256)  # erm
        packet_in_details_window = PacketDetailsPopup(packet)  # Opening a window for (a) packet's details
        packet_in_details_window.exec()

    # GRAPH
    def update_graph(self):
        self.graph_elapsed_time += 1
        self.packet_count_y.append(self.graph_packet_count)
        self.time_stamps_x.append(self.graph_elapsed_time)

        # # # COMMENT
        window = 10
        if len(self.packet_count_y) >= window:
            packet_avg_window = sum(self.packet_count_y[-window-1:-1]) / window
            packet_diff_with_before = self.packet_count_y[-1] - self.packet_count_y[-2]
            if self.packet_count_y[-1] > packet_avg_window * 2 and packet_diff_with_before > 50:
                a = Alert(datetime.now(),
                          "INFO",
                          "Traffic Spike",
                          f"A sudden increase in network traffic was detected. This may indicate a DoS or DDoS attempt,"
                          f" or large file transfers on the network.",
                          f"A sudden increase in network traffic was detected.",
                          f"Check connected devices for abnormal upload/download activity or block suspicious IPs.",
                          {"current_pkt_count": self.packet_count_y[-1],
                           "avg_pkt_count": packet_avg_window,
                           "graph_time": self.graph_elapsed_time})
                alert_manager.add_alert(a)
                """
                time_spike_x = self.time_stamps_x[-2:]
                packet_spike_y = self.packet_count_y[-2:]
                self.graph_container.plot(time_spike_x, packet_spike_y, pen=pg.mkPen("#e70e06", width=1))
                """
        # # # COMMENT

        if len(self.time_stamps_x) > 30:  # Remove if more than 30 plots
            self.time_stamps_x.pop(0)
            self.packet_count_y.pop(0)

        self.graph_line.setData(self.time_stamps_x, self.packet_count_y)  # Update graph

        if self.graph_elapsed_time > 29:  # Move to the right
            self.graph_container.setXRange(self.graph_elapsed_time - 29, self.graph_elapsed_time)
        else:
            self.graph_container.setXRange(1, 30)

        self.graph_packet_count = 0  # Reset packet counter for the next plot

    def reset_graph(self):
        self.packet_count_y = []
        self.time_stamps_x = []
        self.graph_packet_count = 0
        self.graph_elapsed_time = 0
        self.graph_line.setData([], [])
        self.graph_container.setXRange(1,30)

    def host(self):
        subnet_input = self.subnet_list.currentText()
        subnet_input = subnet_input.lstrip("/").split()[0]

        self.host_scan_btn.setDisabled(True)
        self.host_container.clear()
        self.host_total.clear()

        self.host_discover_thread = HostDiscover(self.iface, self.ip, self.mac, subnet_input)
        self.host_discover_thread.host_discovered_signal.connect(self.update_host)
        self.host_discover_thread.start()

    def update_host(self, discovered_host, packet, total_host):
        self.host_scan_btn.setEnabled(True)

        host_each = QListWidgetItem(discovered_host)
        host_each.setData(256, packet)
        self.host_container.addItem(host_each)
        self.host_total.setText(total_host)

    def host_details(self, host_each):
        host = host_each.data(256)
        host_in_details_window = HostDetailsPopup(host, self.mac)
        host_in_details_window.exec()

    def update_alert(self, alert):
        alert_each = QListWidgetItem(f"{alert.timestamp:%I:%M %p} [{alert.severity}] {alert.category}")
        alert_each.setData(256, alert)
        self.alert_container.addItem(alert_each)

    def alert_details(self, alert_each):
        alert = alert_each.data(256)
        alert_in_details_window = AlertDetailsPopup(alert)
        alert_in_details_window.exec()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    device_db = DeviceDB(NETMON_DEVICES)
    alert_manager = AlertManager()

    window = MainWindow()
    window.setWindowIcon(QIcon('./NetMon-img/NetMon-Logo-Alt-TP.png'))

    window.show()

    exit = app.exec()
    device_db.close()

    sys.exit(exit)