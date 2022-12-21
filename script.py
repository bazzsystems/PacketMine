import tkinter as tk
from tkinter import *
import tkinter.ttk as ttk
from tkinter import *
import pyshark
import threading
import asyncio
import tkinter.filedialog as filedialog


class PacketInfo:
    def __init__(self, packet):
        self.packet = packet
        self.timestamp = packet.sniff_time
        self.protocol = packet.transport_layer
        self.info = packet.highest_layer
        self.length = packet.length
        self.src_mac = packet.eth.src
        self.dst_mac = packet.eth.dst
        if self.protocol == "TCP" or self.protocol == "UDP":
            if hasattr(packet, 'ip'):
                self.src = packet.ip.src
                self.dst = packet.ip.dst
                self.sport = packet.tcp.srcport if self.protocol == "TCP" else packet.udp.srcport
                self.dport = packet.tcp.dstport if self.protocol == "TCP" else packet.udp.dstport
            elif hasattr(packet, 'ipv6'):
                self.src = packet.ipv6.src
                self.dst = packet.ipv6.dst
                self.sport = packet.tcp.srcport if self.protocol == "TCP" else packet.udp.srcport
                self.dport = packet.tcp.dstport if self.protocol == "TCP" else packet.udp.dstport
            else:
                self.src = ''
                self.dst = ''
                self.sport = ''
                self.dport = ''
        else:
            if hasattr(packet, 'ipv6'):
                    self.src = packet.ipv6.src
                    self.dst = packet.ipv6.dst
                    self.sport = ''
                    self.dport = ''
            else:
                self.src = ''
                self.dst = ''
                self.sport = ''
                self.dport = ''
        self.extracted_details = {}  # remove extracted_details attribute

class Application:
    def __init__(self, root):
        self.root = root
        self.packets = []
        self.create_widgets()

    def create_widgets(self):
        # Create a menu bar
        self.menu_bar = tk.Menu(self.root)
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Open", command=self.on_open)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.root.config(menu=self.menu_bar)

        # Create a toolbar
        self.toolbar = tk.Frame(self.root, bd=1, relief='raised')
        self.filter_entry = tk.Entry(self.toolbar)
        self.filter_button = tk.Button(self.toolbar, text="Filter", command=self.filter)
        self.toolbar.pack(side='top', fill='x')
        self.filter_entry.pack(side='left')  # fix error here
        self.filter_button.pack(side='left')
        # Create a frame for the treeview and scrollbar
        self.tree_frame = tk.Frame(self.root)
        self.tree_frame.pack(side='left', fill='both', expand=True)

        # Create a scrollbar and treeview
        self.tree_scroll = tk.Scrollbar(self.tree_frame, orient='vertical')
        self.tree = ttk.Treeview(self.tree_frame, columns=('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'),
                                yscrollcommand=self.tree_scroll.set)
        self.tree.heading('#0', text='No.')
        self.tree.heading('#1', text='Time')
        self.tree.heading('#2', text='Source')
        self.tree.heading('#3', text='Destination')
        self.tree.heading('#4', text='Protocol')
        self.tree.heading('#5', text='Length')
        self.tree.heading('#6', text='Info')
        self.tree.column('#0', stretch=0, width=50)
        self.tree.column('#1', stretch=0, width=150)
        self.tree.column('#2', stretch=0, width=150)
        self.tree.column('#3', stretch=0, width=150)
        self.tree.column('#4', stretch=0, width=100)
        self.tree.column('#5', stretch=0, width=100)
        self.tree.column('#6', stretch=0, width=200)
        self.tree.pack(side='left', fill='both', expand=True)
        self.tree_scroll.pack(side='right', fill='y')
        self.tree_scroll.config(command=self.tree.yview)

    def on_open(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.packets = []
            self.tree.delete(*self.tree.get_children())
            capture = pyshark.FileCapture(filepath, keep_packets=False)
            for packet in capture:
                packet_info = PacketInfo(packet)
                self.packets.append(packet_info)
                self.tree.insert('', 'end', values=(len(self.packets), packet_info.timestamp, packet_info.src, packet_info.dst, packet_info.protocol, packet_info.length, packet_info.info))

    def filter(self):
        search_query = self.filter_entry.get()
        self.tree.delete(*self.tree.get_children())
        for packet in self.packets:
            if search_query.lower() in str(packet.timestamp).lower() or search_query.lower() in packet.src.lower() or search_query.lower() in packet.dst.lower() or search_query.lower() in packet.protocol.lower() or search_query.lower() in str(packet.length).lower() or search_query.lower() in packet.info.lower():
                self.tree.insert('', 'end', values=(len(self.packets), packet.timestamp, packet.src, packet.dst, packet.protocol, packet.length, packet.info))

if __name__ == '__main__':
    root = tk.Tk()
    root.title("PacketMine v0.2")
    root.geometry("1000x600")
    app = Application(root)
    root.mainloop()


