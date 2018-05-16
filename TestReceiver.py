# coding=utf-8
import datetime
import threading
import tkinter
import ctypes
from threading import Thread
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview

from scapy.layers.inet import *
from scapy.layers.l2 import *


packet_list = []
global count
pcapnum = 0
count = 0
stop_receiving = threading.Event()

# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


def on_click_packet_list_tree(event):
    """
    数据包列表单击事件响应函数，在数据包列表单击某数据包时，在协议解析区解析此数据包，并在hexdump区显示此数据包的十六进制内容
    :param event: TreeView单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    item_selected = list(selected_item)
    index = int(item_selected[0])   # 确保获取到正确的index
    # 清空packet_dissect_tree上现有的内容
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    if index == 1:
       packet = packet_list[index]
    else:
       packet = packet_list[index-1]
    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None
    for line in lines:
        chksum_line_check=bool('chksum' in line)
        if line.startswith('#'):
            line = line.strip('# ')
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)
        if chksum_line_check and ((IP in packet) or (TCP in packet) or (UDP in packet)):
            original_IP_chksum = packet.chksum

            packet2compare = Ether(raw(packet))
            # 应该新建一个底层的以太网包，要从以太网层重新开始算，否则怎么都算不对的。
            chksum2compare = packet2compare.chksum
            print(packet.chksum)
            print(chksum2compare)

            if original_IP_chksum == chksum2compare:

                packet_dissect_tree.insert(last_tree_entry, 'end', text=line + '[checksum correct]')
            elif original_IP_chksum != chksum2compare:
                packet_dissect_tree.insert(last_tree_entry, 'end', text=line + '[checksum incorrect]')
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        # 根据新插入数据项的长度动态调整协议解析区的宽度
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)
    # 在hexdump区显示此数据包的十六进制内容
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'


# 测试在界面中显示一个数据包的内容
def just_a_test(pkt):
        packet_list.append(pkt)
        global count
        count += 1
        packet_time = timestamp2time(pkt.time)
        proto_names = ['TCP', 'UDP', 'icmp', 'IP', 'ARP', 'Ether', 'Unknown']
        length = len(pkt)
        info = pkt.summary()
        if pause_button['state'] == 'normal' and pause_button['text'] == '暂停':
         for pn in proto_names:
            if pn in pkt:
                proto = pn
                if ICMP in pkt and pn == 'IP':
                   src = pkt[IP].src
                   dst = pkt[IP].dst

                   packet_list_tree.insert("", 'end', str(count), text=str(count),
                                        values=(str(count), packet_time, src, dst, 'ICMP', length, info))
                elif pn == 'IP':
                   src = pkt[IP].src
                   dst = pkt[IP].dst
                   packet_list_tree.insert("", 'end', str(count), text=str(count),
                                        values=(str(count), packet_time, src, dst, proto, length, info))
                elif TCP in pkt and pn == 'TCP':
                    src = pkt.src
                    dst = pkt.dst
                    packet_list_tree.insert("", 'end', str(count), text=str(count),
                                            values=(str(count), packet_time, src, dst, proto, length, info))
                elif ARP in pkt and pn == 'ARP':

                    hwsrc = pkt.hwsrc
                    hwdst = pkt.hwdst
                    packet_list_tree.insert("", 'end', str(count), text=str(count),
                                            values=(
                                            str(count), packet_time, hwsrc, hwdst,  proto, length, info))
                elif UDP in pkt and pn == 'UDP':
                    src = pkt.src
                    dst = pkt.dst
                    packet_list_tree.insert("", 'end', str(count), text=str(count),
                                            values=(
                                                str(count), packet_time, src, dst, proto, length, info))
                break
        elif pause_button['state'] == 'normal' and pause_button['text'] == '继续':
            pass

        packet_list_tree.update_idletasks()


# 将抓到的数据包保存为pcap格式的文件
def save_captured_data_to_file():
    global pcapnum
    global filename

    pcapnum += 1
    pcap_name = "pacp%d.pcap"%pcapnum
    wrpcap(pcap_name,packet_list)
    packet_list.clear()



def packet_receive():
    filter_text = fitler_entry.get()
    sniff(filter=filter_text, prn=(lambda x: just_a_test(x)),stop_filter=(lambda x:stop_receiving.isSet()))


# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    pause_button['state'] = 'normal'
    global thread
    thread = threading.Thread(target=packet_receive)
    thread.setDaemon(True)
    thread.start()
    start_button['state'] = 'disabled'
    stop_button['state'] = 'normal'



# 暂停按钮单击响应函数
def pause_capture():
    if pause_button['text'] == '暂停':
       pause_button['text'] = '继续'
    elif pause_button['text'] == '继续':
       pause_button['text'] = '暂停'


# 停止按钮单击响应函数
def stop_capture():
    stop_receiving.set()
    start_button['state'] = 'normal'
    stop_button['state'] = 'disabled'
    save_button['state'] = 'normal'
    ques = askyesno('Data not Saved!', 'Data not saved,want to save them?')
    if (ques):
        packet_list_tree.delete(packet_list_tree.get_children())
        save_captured_data_to_file()
        packet_list.clear()
    else:
        stop_button['state'] = 'disabled'
        save_button['state'] = 'disabled'



# 退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据
def quit_program():
    exit(0)


# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
# tk.resizable(0, 0)
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)

main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)

tk.mainloop()

