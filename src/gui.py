from tkinter import *
from tkinter import ttk
from tkinter import scrolledtext
import tkinter
import sniff
import threading
import inspect
import ctypes


class App:

    def __init__(self, master):
        self.master = master
        self.e = threading.Event()
        self.filter_var = [IntVar(value=0) for i in range(7)]
        self.filter_para = None
        self.proto_dict = ['(tcp and ( port 80)) or (tcp and ( port 443))', 'tcp', 'udp', 'icmp or icmp6', 'ip', 'ip6', 'arp']
        self.main_window()

    # 开始sniff
    def start_sniff(self):
        self.data_box.config(state=tkinter.NORMAL)
        self.data_box.delete(1.0, 'end')
        self.data_box.config(state=tkinter.DISABLED)
        for i in range(7):
            if self.filter_var[i].get() == 1:
                if self.filter_para == None:
                    self.filter_para = self.proto_dict[i]
                else:
                    self.filter_para = self.filter_para + " or " + self.proto_dict[i]
        self.t1 = threading.Thread(target=sniff.start_sniff, args=(self.e, self.filter_para))
        self.t1.Daemon = True
        self.del_list(self.table)
        self.analyse_box.config(state=tkinter.NORMAL)
        self.analyse_box.delete(1.0, 'end')
        self.analyse_box.insert('end', 'The sniffer is running.\nAfter stop sniffer, you can see the results.')
        self.analyse_box.config(state=tkinter.DISABLED)
        self.t1.start()


    def get_start_with_ip_port(self):
        self.data_box.config(state=tkinter.NORMAL)
        self.data_box.delete(1.0, 'end')
        self.data_box.config(state=tkinter.DISABLED)
        if self.entry1.get() != '' and self.entry2.get() != '':
            self.filter_para = '(net ' + self.entry1.get() + ') and (port ' + self.entry2.get() + ') and tcp'
        elif self.entry1.get() != '':
            self.filter_para = '(net ' +self.entry1.get() + ') and tcp'
        elif self.entry2.get() != '':
            self.filter_para = '(port ' +self.entry2.get() + ') and tcp'
        else:
            self.filter_para = None
        self.t1 = threading.Thread(target=sniff.start_sniff, args=(self.e, self.filter_para))
        self.t1.Daemon = True
        self.del_list(self.table)
        self.analyse_box.config(state=tkinter.NORMAL)
        self.analyse_box.delete(1.0, 'end')
        self.analyse_box.insert('end', 'The sniffer is running.\nAfter stop sniffer, you can see the results.')
        self.analyse_box.config(state=tkinter.DISABLED)
        self.t1.start()
        self.sub_tk.destroy()

    # IP+Port+TCP流追踪
    def start_with_IP_Port(self):
        self.entry_txt1 = StringVar()
        self.entry_txt2 = StringVar()
        self.sub_tk = Tk()
        tk_width, tk_height =300, 100
        position = self.window_center(tk_width, tk_height)
        self.sub_tk.geometry(f'{tk_width}x{tk_height}+{position[0]}+{position[1]}')
        self.sub_tk.title("IP+Prot")
        self.label1 = Label(self.sub_tk, text='IP address:', justify=RIGHT, padx=10)
        self.label2 = Label(self.sub_tk, text='Port:', justify=RIGHT, padx=10)
        self.label1.grid(row=1, column=1)
        self.label2.grid(row=3, column=1)
        self.entry1 = Entry(self.sub_tk, textvariable=self.entry_txt1)
        self.entry1.grid(row=1, column=3)
        self.entry2 = Entry(self.sub_tk, textvariable=self.entry_txt2)
        self.entry2.grid(row=3, column=3)
        self.button1 = Button(self.sub_tk, text='Start', command=self.get_start_with_ip_port)
        self.button2 = Button(self.sub_tk, text='Cancel', command=self.sub_tk.destroy)
        sep = ttk.Separator(self.sub_tk, orient=HORIZONTAL)
        sep.grid(row=5)
        self.button1.grid(row=7, column=2)
        self.button2.grid(row=7, column=3)
        self.sub_tk.mainloop()

    # 选择list中的一个包显示analyse
    def show_analyse(self, event):
        self.analyse_box.config(state=tkinter.NORMAL)
        self.data_box.config(state=tkinter.NORMAL)
        self.analyse_box.delete(1.0, 'end')
        self.data_box.delete(1.0, 'end')
        for item in self.table.selection():
            info = self.table.item(item, 'values')

            # analyse_box
            sniff.dpkt_analyse(info[0])
            file = open('data.txt', 'r')
            s = file.read()
            self.analyse_box.insert(END, s.encode('GBK','ignore').decode('GBk'))
            
            # data_box
            data_hex = sniff.dpkt_hex(info[0])
            data_chr = []
            for i in range(len(data_hex)):
                if data_hex[i] >= 32 and data_hex[i] <= 126:
                    char = chr(data_hex[i]) + " "
                else:
                    char = chr(183)
                data_chr.append(char)
            cnt = 1
            for i in range(0, len(data_hex), 16):
                self.data_box.insert('end', f'Row:{cnt}\t\t')
                self.data_box.insert('end', data_hex[i: i+16].hex(' '))
                self.data_box.insert('end', '\t\t\t\t\t\t\t')
                for j in range(16):
                    try:
                        self.data_box.insert('end', data_chr[i+j])
                    except:
                        break
                self.data_box.insert('end', '\n')
                cnt += 1
            self.analyse_box.config(state=tkinter.DISABLED)
            self.data_box.config(state=tkinter.DISABLED)



    # 结束sniff
    def stop_sniff(self):
        self.e.set()
        self.filter_para = None
        for i in range(7):
            self.filter_var[i].set(0)
        self.filter_bar.update()
        self.analyse_box.config(state=tkinter.NORMAL)
        self.analyse_box.delete(1.0, 'end')
        self.analyse_box.config(state=tkinter.DISABLED)
        packets_list = sniff.show_list()
        if packets_list is None:
            self.analyse_box.config(state=tkinter.NORMAL)
            self.analyse_box.delete(1.0, 'end')
            self.analyse_box.insert('end','no packet was captured!')
            self.analyse_box.config(state=tkinter.DISABLED)
        else:
            for p in packets_list:
                self.table.insert('','end',values=p)
            self.table.update()
        self.e = threading.Event()

    
    # 清空列表
    def del_list(self, tree):
        x=tree.get_children()
        for item in x:
            tree.delete(item)


    # 窗口大小
    def window_size(self):
        system_metrics = [self.master.winfo_screenwidth(), self.master.winfo_screenheight()]
        tk_width = system_metrics[0] * 0.6
        tk_height = system_metrics[1] * 0.7
        return int(tk_width), int(tk_height)


    # 窗口大小和居中
    def window_center(self, tk_width, tk_height):
        system_metrics = [self.master.winfo_screenwidth(), self.master.winfo_screenheight()]
        window_x_position = (system_metrics[0] - tk_width) / 2
        window_y_position = (system_metrics[1] - tk_height) / 2
        return int(window_x_position), int(window_y_position)



    # Menu
    def create_menu(self):
        self.menu_bar = Menu(self.master)
        self.filter_bar = Menu(self.menu_bar, tearoff=False)
        self.filter_bar.add_checkbutton(label='HTTP/HTTPS', variable=self.filter_var[0])
        self.filter_bar.add_checkbutton(label='TCP', variable=self.filter_var[1])
        self.filter_bar.add_checkbutton(label='UDP', variable=self.filter_var[2])
        self.filter_bar.add_checkbutton(label='ICMP', variable=self.filter_var[3])
        self.filter_bar.add_checkbutton(label='IP', variable=self.filter_var[4])
        self.filter_bar.add_checkbutton(label='IPv6', variable=self.filter_var[5])
        self.filter_bar.add_checkbutton(label='ARP', variable=self.filter_var[6])
        self.menu_bar.add_cascade(label="Fliter", menu=self.filter_bar)
        self.menu_bar.add_command(label="Start with IP+Port", command=self.start_with_IP_Port)
        self.menu_bar.add_command(label="Start", command=self.start_sniff)
        self.menu_bar.add_command(label="Stop", command=self.stop_sniff)
        root.config(menu=self.menu_bar)
        


    # packet list
    def packet_list_pane(self, frame):
        columns = ['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length']
        self.table = ttk.Treeview(
            master=frame,
            columns=columns,
            show='headings'
        )
        self.table.heading(column='No', text='No' )  
        self.table.heading('Time', text='Time')
        self.table.heading('Source', text='Source' )  
        self.table.heading('Destination', text='Destination' )  
        self.table.heading('Protocol', text='Protocol' )  
        self.table.heading('Length', text='Length' )  
        self.table.column('No', width=10, minwidth=10, anchor=E)  # 定义s列
        self.table.column('Time', width=50, minwidth=50, anchor=E)  # 定义列
        self.table.column('Source', width=50, minwidth=50, anchor=E)  # 定义列
        self.table.column('Destination', width=50, minwidth=50, anchor=E)  # 定义列
        self.table.column('Protocol', width=10, minwidth=10, anchor=S)  # 定义列
        self.table.column('Length', width=10, minwidth=10, anchor=S)  # 定义列
        self.scr_y1 = Scrollbar(frame, orient="vertical")
        self.scr_x1 = Scrollbar(frame, orient="horizontal")
        self.table.config(yscrollcommand=self.scr_y1.set, xscrollcommand=self.scr_x1.set)
        self.scr_y1.config(command=self.table.yview)
        self.scr_x1.config(command=self.table.xview)
        self.scr_y1.pack(side=RIGHT, fill=Y)
        self.table.pack(fill="both", expand=True)
        self.scr_x1.pack(side=BOTTOM, fill=X)
        self.table.bind('<ButtonRelease-1>', self.show_analyse)


    # packet analyse
    def packet_analyse_pane(self, frame):
        f_width = frame.winfo_width()
        self.analyse_box = scrolledtext.ScrolledText(frame, width=int(f_width), state=tkinter.DISABLED)
        self.analyse_box.pack(side=LEFT, fill=BOTH, expand=YES)


    # packet data
    def packet_data_pane(self, frame):
        f_width = frame.winfo_width()
        self.data_box = scrolledtext.ScrolledText(frame, width=int(f_width), state=tkinter.DISABLED)
        self.data_box.pack(side=LEFT, fill=BOTH, expand=YES)


    # 三窗布局
    def window_pane(self):
        self.create_menu()
        self.packet_list = Frame(self.master, relief="sunken")
        self.packet_list.pack(side=TOP, fill=BOTH, expand=YES)
        self.packet_list.pack_propagate(0)
        self.packet_list.update()
        self.packet_list_pane(self.packet_list)
        self.packet_analyse = Frame(self.master, relief="sunken")
        self.packet_analyse.pack(side=TOP, fill=BOTH, expand=YES)
        self.packet_analyse.pack_propagate(0)
        self.packet_analyse.update()
        self.packet_analyse_pane(self.packet_analyse)
        self.data_bar = Frame(self.master, relief="sunken")
        self.data_bar.pack(side=TOP, fill=BOTH, expand=YES)
        self.data_bar.pack_propagate(0)
        self.data_bar.update()
        self.packet_data_pane(self.data_bar)
        



    # 主窗口
    def main_window(self):
        tk_width, tk_height = self.window_size()
        position = self.window_center(tk_width, tk_height)
        self.master.geometry(f'{tk_width}x{tk_height}+{position[0]}+{position[1]}')
        self.master.title("simpleSniff")
        self.master.update()
        self.window_pane()


if __name__ == '__main__':
    root = Tk()
    App(root)
    root.mainloop()