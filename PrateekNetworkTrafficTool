import scapy.all as scapy
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
from tkinter import *
from tkinter import ttk
import threading
import json
from pathlib import Path
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns
from tkinter import messagebox

class PrateekNetworkAnalyzer:
    def __init__(self):
        self.captured_packets = []
        self.is_capturing = False
        
        # Create main window
        self.root = Tk()
        self.root.title("Prateek Network Traffic Analysis Tool")
        self.root.geometry("1200x800")
        
        # Create GUI elements
        self.setup_gui()
        
    def setup_gui(self):
        # Main container
        main_container = ttk.PanedWindow(self.root, orient=HORIZONTAL)
        main_container.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        # Left panel for controls and packet list
        left_panel = ttk.Frame(main_container)
        main_container.add(left_panel, weight=1)
        
        # Right panel for visualizations
        self.right_panel = ttk.Frame(main_container)
        main_container.add(self.right_panel, weight=1)
        
        # Control Frame
        control_frame = ttk.LabelFrame(left_panel, text="Controls", padding=10)
        control_frame.pack(fill=X, padx=5, pady=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture)
        self.stop_button.pack(side=LEFT, padx=5)
        self.stop_button.config(state='disabled')
        
        self.save_button = ttk.Button(control_frame, text="Save Results", command=self.save_results)
        self.save_button.pack(side=LEFT, padx=5)
        
        self.visualize_button = ttk.Button(control_frame, text="Update Visualizations", command=self.update_visualizations)
        self.visualize_button.pack(side=LEFT, padx=5)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(left_panel, text="Statistics", padding=10)
        stats_frame.pack(fill=X, padx=5, pady=5)
        
        self.stats_text = Text(stats_frame, height=5)
        self.stats_text.pack(fill=X)
        
        # Packet List Frame
        packet_frame = ttk.LabelFrame(left_panel, text="Packet List", padding=10)
        packet_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        # Create Treeview
        self.tree = ttk.Treeview(packet_frame, columns=('Time', 'Source', 'Destination', 'Protocol', 'Length'))
        self.tree.heading('Time', text='Time')
        self.tree.heading('Source', text='Source')
        self.tree.heading('Destination', text='Destination')
        self.tree.heading('Protocol', text='Protocol')
        self.tree.heading('Length', text='Length')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(packet_frame, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # Initialize visualization
        self.setup_visualization()
        
        # Add this after creating the tree widget
        self.tree.tag_configure('tcp', background='lightblue')
        self.tree.tag_configure('udp', background='lightgreen')
        self.tree.tag_configure('icmp', background='yellow')

    def setup_visualization(self):
        # Create figure with clean styling
        self.fig = plt.Figure(figsize=(8, 12))
        self.fig.subplots_adjust(hspace=0.4)
        
        # Create subplots
        self.ax1 = self.fig.add_subplot(311)
        self.ax1.set_title('Protocol Distribution')
        
        self.ax2 = self.fig.add_subplot(312)
        self.ax2.set_title('Packet Length Distribution')
        
        self.ax3 = self.fig.add_subplot(313)
        self.ax3.set_title('Traffic Flow Over Time')
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.right_panel)
        self.canvas.get_tk_widget().pack(fill=BOTH, expand=True)

    def update_visualizations(self):
        if not self.captured_packets:
            return
            
        df = pd.DataFrame(self.captured_packets)
        
        # Clear previous plots
        self.ax1.clear()
        self.ax2.clear()
        self.ax3.clear()
        
        # Protocol Distribution - Simple Pie Chart
        protocol_counts = df['protocol'].value_counts()
        self.ax1.pie(protocol_counts.values, 
                     labels=protocol_counts.index,
                     autopct='%1.1f%%')
        self.ax1.set_title('Protocol Distribution')
        
        # Packet Length Distribution - Simple Histogram
        self.ax2.hist(df['length'], bins=30, color='blue', alpha=0.7)
        self.ax2.set_title('Packet Length Distribution')
        self.ax2.set_xlabel('Packet Length (bytes)')
        self.ax2.set_ylabel('Frequency')
        
        # Traffic Flow Over Time - Simple Line Plot
        df['time'] = pd.to_datetime(df['time'], format='%H:%M:%S')
        traffic_over_time = df.groupby('time').size()
        self.ax3.plot(traffic_over_time.index, 
                      traffic_over_time.values,
                      color='blue')
        self.ax3.set_title('Traffic Flow Over Time')
        self.ax3.set_xlabel('Time')
        self.ax3.set_ylabel('Packets')
        plt.setp(self.ax3.xaxis.get_majorticklabels(), rotation=45)
        
        # Update layout and canvas
        self.fig.tight_layout()
        self.canvas.draw()

    def start_capture(self):
        self.is_capturing = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        
        # Start packet capture in a separate thread
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.start()
    
    def stop_capture(self):
        self.is_capturing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
    
    def capture_packets(self):
        scapy.sniff(prn=self.packet_callback, store=False)
    
    def save_results(self):
        if self.captured_packets:
            try:
                # Create results directory if it doesn't exist
                Path("results").mkdir(exist_ok=True)
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                
                # Save to JSON file
                json_filename = f"results/capture_{timestamp}.json"
                with open(json_filename, 'w') as f:
                    json.dump(self.captured_packets, f, indent=4)
                
                # Save visualizations
                self.fig.savefig(f"results/visualization_{timestamp}.png", 
                               bbox_inches='tight', dpi=300)
                
                # Create CSV report instead of Excel
                df = pd.DataFrame(self.captured_packets)
                csv_filename = f"results/report_{timestamp}.csv"
                df.to_csv(csv_filename, index=False)
                
                # Create summary CSV
                summary_data = {
                    'Metric': [
                        'Total Packets',
                        'Unique Sources',
                        'Unique Destinations',
                        'Average Packet Length',
                        'Most Common Protocol',
                        'Largest Packet Size'
                    ],
                    'Value': [
                        len(df),
                        len(df['source'].unique()),
                        len(df['destination'].unique()),
                        f"{df['length'].mean():.2f} bytes",
                        df['protocol'].mode()[0],
                        f"{df['length'].max()} bytes"
                    ]
                }
                summary_filename = f"results/summary_{timestamp}.csv"
                pd.DataFrame(summary_data).to_csv(summary_filename, index=False)
                
                messagebox.showinfo("Success", "Results saved successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results: {str(e)}")

    def run(self):
        self.root.mainloop()

    def packet_callback(self, packet):
        if self.is_capturing:
            time = datetime.now().strftime('%H:%M:%S')
            
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                length = len(packet)
                
                # Determine protocol tag
                tag = ''
                if protocol == 6:  # TCP
                    tag = 'tcp'
                elif protocol == 17:  # UDP
                    tag = 'udp'
                elif protocol == 1:  # ICMP
                    tag = 'icmp'
                
                # Store packet info
                packet_info = {
                    'time': time,
                    'source': src,
                    'destination': dst,
                    'protocol': protocol,
                    'length': length
                }
                self.captured_packets.append(packet_info)
                
                # Update GUI with color tag
                self.tree.insert('', 'end', values=(time, src, dst, protocol, length), tags=(tag,))
                self.update_statistics()

    def update_statistics(self):
        total_packets = len(self.captured_packets)
        if total_packets > 0:
            df = pd.DataFrame(self.captured_packets)
            stats = f"Total Packets: {total_packets}\n"
            stats += f"Unique Sources: {len(df['source'].unique())}\n"
            stats += f"Unique Destinations: {len(df['destination'].unique())}\n"
            stats += f"Average Packet Length: {df['length'].mean():.2f} bytes\n"
            
            self.stats_text.delete(1.0, END)
            self.stats_text.insert(END, stats)

class PacketFilter:
    def __init__(self):
        self.filters = {
            'ip': [],
            'protocol': [],
            'port': [],
            'packet_size': {'min': 0, 'max': float('inf')}
        }
    
    def add_ip_filter(self, ip_address, filter_type='source'):
        """Add IP address filter"""
        self.filters['ip'].append({
            'address': ip_address,
            'type': filter_type
        })
    
    def add_protocol_filter(self, protocol):
        """Add protocol filter"""
        self.filters['protocol'].append(protocol)
    
    def set_packet_size_filter(self, min_size=None, max_size=None):
        """Set packet size range filter"""
        if min_size:
            self.filters['packet_size']['min'] = min_size
        if max_size:
            self.filters['packet_size']['max'] = max_size
    
    def apply_filters(self, packet):
        """Apply all filters to a packet"""
        if packet.haslayer(scapy.IP):
            # Check IP filters
            if self.filters['ip']:
                for ip_filter in self.filters['ip']:
                    if ip_filter['type'] == 'source' and packet[scapy.IP].src != ip_filter['address']:
                        return False
                    if ip_filter['type'] == 'dest' and packet[scapy.IP].dst != ip_filter['address']:
                        return False
            
            # Check protocol filters
            if self.filters['protocol'] and packet[scapy.IP].proto not in self.filters['protocol']:
                return False
            
            # Check packet size
            packet_size = len(packet)
            if not (self.filters['packet_size']['min'] <= packet_size <= self.filters['packet_size']['max']):
                return False
            
            return True
        return False

# 2. Advanced Protocol Analysis

class ProtocolAnalyzer:
    def __init__(self):
        self.protocol_stats = {}
        self.known_protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            # Add more protocols as needed
        }
    
    def analyze_protocol(self, packet):
        """Detailed protocol analysis"""
        if packet.haslayer(scapy.IP):
            proto = packet[scapy.IP].proto
            proto_name = self.known_protocols.get(proto, f'Unknown ({proto})')
            
            if proto_name not in self.protocol_stats:
                self.protocol_stats[proto_name] = {
                    'count': 0,
                    'total_size': 0,
                    'avg_size': 0,
                    'ports_used': set()
                }
            
            stats = self.protocol_stats[proto_name]
            stats['count'] += 1
            stats['total_size'] += len(packet)
            stats['avg_size'] = stats['total_size'] / stats['count']
            
            # Analyze ports if TCP or UDP
            if proto in [6, 17]:  # TCP or UDP
                if packet.haslayer(scapy.TCP):
                    stats['ports_used'].add(packet[scapy.TCP].dport)
                elif packet.haslayer(scapy.UDP):
                    stats['ports_used'].add(packet[scapy.UDP].dport)

# 3. Machine Learning for Anomaly Detection

class AnomalyDetector:
    def __init__(self):
        self.baseline_data = []
        self.model = None
        
    def collect_baseline(self, packet_data, duration=3600):  # 1 hour baseline
        """Collect baseline network behavior"""
        timestamp = packet_data['timestamp']
        self.baseline_data.append({
            'packet_size': packet_data['length'],
            'protocol': packet_data['protocol'],
            'hour': timestamp.hour,
            'minute': timestamp.minute
        })
    
    def train_model(self):
        """Train anomaly detection model"""
        if len(self.baseline_data) > 1000:  # Minimum data points required
            df = pd.DataFrame(self.baseline_data)
            # Example using Isolation Forest
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(contamination=0.1)
            self.model.fit(df[['packet_size', 'hour', 'minute']])
    
    def detect_anomaly(self, packet_data):
        """Detect anomalies in network traffic"""
        if self.model:
            features = [[
                packet_data['length'],
                packet_data['timestamp'].hour,
                packet_data['timestamp'].minute
            ]]
            return self.model.predict(features)[0] == -1  # -1 indicates anomaly

# 4. Network Security Analysis Tools

class SecurityAnalyzer:
    def __init__(self):
        self.suspicious_patterns = {
            'port_scan': {},
            'ddos_attempt': {},
            'suspicious_ips': set()
        }
        self.alert_system = AlertSystem()
    
    def analyze_security(self, packet):
        """Analyze packet for security concerns"""
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Check for port scanning
            self._check_port_scan(src_ip, dst_ip, packet)
            
            # Check for DDoS attempts
            self._check_ddos(src_ip, dst_ip)
            
            # Check against known malicious IPs
            self._check_suspicious_ip(src_ip)
    
    def _check_port_scan(self, src_ip, dst_ip, packet):
        """Detect potential port scanning"""
        if packet.haslayer(scapy.TCP):
            key = f"{src_ip}->{dst_ip}"
            if key not in self.suspicious_patterns['port_scan']:
                self.suspicious_patterns['port_scan'][key] = set()
            
            self.suspicious_patterns['port_scan'][key].add(packet[scapy.TCP].dport)
            
            # Alert if too many different ports are scanned
            if len(self.suspicious_patterns['port_scan'][key]) > 20:
                self.alert_system.trigger_alert(
                    'Port Scan Detected',
                    f'Possible port scan from {src_ip} to {dst_ip}'
                )

# 5. Automated Alert System

class AlertSystem:
    def __init__(self):
        self.alert_levels = {
            'INFO': 0,
            'WARNING': 1,
            'CRITICAL': 2
        }
        self.alert_handlers = []
    
    def add_alert_handler(self, handler):
        """Add new alert handler (email, SMS, log, etc.)"""
        self.alert_handlers.append(handler)
    
    def trigger_alert(self, title, message, level='WARNING'):
        """Trigger an alert across all handlers"""
        alert = {
            'timestamp': datetime.now(),
            'title': title,
            'message': message,
            'level': level
        }
        
        for handler in self.alert_handlers:
            handler.handle_alert(alert)

class EmailAlertHandler:
    def __init__(self, smtp_config):
        self.smtp_config = smtp_config
    
    def handle_alert(self, alert):
        """Send alert via email"""
        # Email sending implementation
        pass

class SMSAlertHandler:
    def __init__(self, sms_config):
        self.sms_config = sms_config
    
    def handle_alert(self, alert):
        """Send alert via SMS"""
        # SMS sending implementation
        pass

# 6. Enhanced Visualization Options

class AdvancedVisualizer:
    def __init__(self):
        self.fig = plt.Figure(figsize=(12, 8))
        self.setup_advanced_plots()
    
    def setup_advanced_plots(self):
        """Setup advanced visualization plots"""
        # Geographical traffic map
        self.ax_geo = self.fig.add_subplot(221)
        
        # Protocol hierarchy tree
        self.ax_tree = self.fig.add_subplot(222)
        
        # Traffic heatmap
        self.ax_heat = self.fig.add_subplot(223)
        
        # Network graph
        self.ax_network = self.fig.add_subplot(224)
    
    def update_visualizations(self, packet_data):
        """Update all visualizations with new data"""
        self._update_geo_map(packet_data)
        self._update_protocol_tree(packet_data)
        self._update_traffic_heatmap(packet_data)
        self._update_network_graph(packet_data)
        
    def _update_geo_map(self, packet_data):
        """Update geographical traffic map"""
        # Implementation for updating geographical visualization
        pass
    
    def _update_protocol_tree(self, packet_data):
        """Update protocol hierarchy tree"""
        # Implementation for updating protocol tree
        pass
        
    def setup_visualization(self):
        # Create figure with clean styling
        self.fig = plt.Figure(figsize=(8, 12))
        self.fig.subplots_adjust(hspace=0.4)
        
        # Create subplots
        self.ax1 = self.fig.add_subplot(311)
        self.ax1.set_title('Protocol Distribution')
        
        self.ax2 = self.fig.add_subplot(312)
        self.ax2.set_title('Packet Length Distribution')
        
        self.ax3 = self.fig.add_subplot(313)
        self.ax3.set_title('Traffic Flow Over Time')
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.right_panel)
        self.canvas.get_tk_widget().pack(fill=BOTH, expand=True)
    
    def packet_callback(self, packet):
        if self.is_capturing:
            # Extract packet information
            time = datetime.now().strftime('%H:%M:%S')
            
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                length = len(packet)
                
                # Store packet info
                packet_info = {
                    'time': time,
                    'source': src,
                    'destination': dst,
                    'protocol': protocol,
                    'length': length
                }
                self.captured_packets.append(packet_info)
                
                # Update GUI
                self.tree.insert('', 'end', values=(time, src, dst, protocol, length))
                self.update_statistics()
    
    def update_statistics(self):
        total_packets = len(self.captured_packets)
        if total_packets > 0:
            df = pd.DataFrame(self.captured_packets)
            stats = f"Total Packets: {total_packets}\n"
            stats += f"Unique Sources: {len(df['source'].unique())}\n"
            stats += f"Unique Destinations: {len(df['destination'].unique())}\n"
            stats += f"Average Packet Length: {df['length'].mean():.2f} bytes\n"
            
            self.stats_text.delete(1.0, END)
            self.stats_text.insert(END, stats)
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    analyzer = PrateekNetworkAnalyzer()
    analyzer.run()

print(plt.style.available)
