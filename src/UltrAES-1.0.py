from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
from tkinter.ttk import *
from tkinter import (Tk, END, IntVar, Menu, Text, Message, BooleanVar, LEFT, RIGHT, BOTH, Y,
                     X, YES, Toplevel, ttk, simpledialog)
import tkinter as tk
from tkinter.filedialog import *
from tkinter.messagebox import *
import windnd
import sys
from random import randint, choice
from threading import Thread
import subprocess
from configparser import ConfigParser
import ctypes
import zipfile
import hashlib
import zlib
import string
import datetime as dat
import time

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except:
        pass

def resource_path(relative_path):
    if getattr(sys, 'frozen', False): 
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
filename = resource_path(os.path.join("res", "ICON", "windowicon.ico"))
user_name = os.getlogin()
cfg_file = f"C:/Users/{user_name}/AppData/Local/UltrAES/UltrAES.ini"
config = ConfigParser()
langs = {}
langf = None
lang = None
lang_max = 1101
win_top = None
crypting = False
out_file = None
menu_tearoff = False
new_cfg = False

if not os.path.exists(f"C:/Users/{user_name}/AppData/Local/UltrAES/"):
    os.makedirs(f"C:/Users/{user_name}/AppData/Local/UltrAES/")

def time_now():
    now = dat.datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")

class AskPasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt, initialvalue=""):
        super().__init__(parent)
        self.transient(parent)  # 设置为主窗口的临时窗口
        self.title(title)
        self.parent = parent
        
        # 使对话框模态化（阻止主窗口交互）
        self.grab_set()
        self.focus_set()
        
        # 创建UI元素
        self._create_widgets(prompt, initialvalue)
        
        # 绑定回车和ESC键
        self.bind('<Return>', self._on_ok)
        self.bind('<Escape>', self._on_cancel)
        
        # 窗口关闭协议
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        # 居中对话框
        self._center_dialog()
        
        # 等待对话框关闭
        self.wait_window(self)
    
    def _create_widgets(self, prompt, initialvalue):
        """创建对话框控件"""
        # 主框架
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 提示标签
        lbl_prompt = ttk.Label(main_frame, text=prompt)
        lbl_prompt.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))
        
        # 输入框
        self.entry_var = tk.StringVar(value=initialvalue)
        self.entry = ttk.Entry(main_frame, textvariable=self.entry_var, width=30)
        self.entry.grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=(0, 10))
        self.entry.select_range(0, tk.END)  # 全选初始文本
        self.entry.focus_set()  # 设置焦点
        self.entry.config(show="●") #隐藏密码

        #显示密码
        self.check = BooleanVar()
        self.show_pwd = ttk.Checkbutton(main_frame, text=langs[78], variable=self.check, \
                                     command=self._on_show_pwd)
        self.show_pwd.grid(row=2, column=0, sticky=tk.W)
        
        # 确定按钮
        btn_ok = ttk.Button(main_frame, text=langs[76], command=self._on_ok)
        btn_ok.grid(row=3, column=0, padx=(0, 5), sticky=tk.E)
        
        # 取消按钮
        btn_cancel = ttk.Button(main_frame, text=langs[77], command=self._on_cancel)
        btn_cancel.grid(row=3, column=1, sticky=tk.E)
        
        # 配置列权重
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

    def _on_show_pwd(self, event=None):
        self._show_pwd = self.check.get()
        if self._show_pwd:
            self.entry.config(show="")
        else:
            self.entry.config(show="●")
    
    def _on_ok(self, event=None):
        """确定按钮处理"""
        self.result = self.entry_var.get()
        self.destroy()
    
    def _on_cancel(self, event=None):
        """取消按钮处理"""
        self.result = None
        self.destroy()
    
    def _center_dialog(self):
        """居中对话框"""
        self.update_idletasks()  # 确保窗口尺寸已更新
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        
        dialog_width = self.winfo_reqwidth()
        dialog_height = self.winfo_reqheight()
        
        # 计算居中位置
        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2
        
        self.geometry(f"+{x}+{y}")

def askpassword(title, prompt, **kwargs):
    parent = kwargs.get('parent', None)
    initialvalue = kwargs.get('initialvalue', '')
    
    # 如果没有指定父窗口，尝试获取活动窗口
    if parent is None:
        parent = tk._default_root
    
    dialog = AskPasswordDialog(parent, title, prompt, initialvalue)
    return dialog.result


def init():
    global lang, spath, langs, win_top, menu_tearoff, new_cfg
    if os.path.exists(cfg_file):
        config.read(cfg_file)
        lang = config.get("UltrAES", "lang")
        if config.get("UltrAES", "topmost") == "true":
            win_top = True
        elif config.get("UltrAES", "topmost") == "false":
            win_top = False
        if config.get("UltrAES", "menu_tearoff") == "true":
            menu_tearoff = True
        elif config.get("UltrAES", "menu_tearoff") == "false":
            menu_tearoff = False
    else:
        new_cfg = True
        config.add_section("UltrAES")
        config.set("UltrAES", "lang", "zh_cn")
        config.set("UltrAES", "topmost", "true")
        config.set("UltrAES", "menu_tearoff", "false")
        with open(cfg_file, "w") as conf:
            config.write(conf)
        lang = "zh_cn"
        spath = "None"
        win_top = True
        menu_tearoff = False
    if lang == "zh_cn":
        langf = "zh_cn.txt"
    elif lang == "en_us":
        langf = "en_us.txt"
    lang_file = resource_path(os.path.join("res", "LANG", langf))
    langp = ConfigParser()
    langp.read(lang_file)
    for i in range(1000, lang_max + 1):
        if langp.has_option("Lang", str(i)):
            l = langp.get("Lang", str(i))
            langs[i - 1000] = l
        else:
            pass
    l = langp.get("Help", "about")
    langs["about"] = l

init()

def crypto_file(infile, outfile, password, mode):
    """
    使用密码加密或解密文件
    参数:
        infile: 输入文件路径
        outfile: 输出文件路径
        password: 加密/解密密码
        mode: 模式，"enc"表示加密，"dec"表示解密
    """
    # 验证输入文件是否存在
    if not os.path.exists(infile):
        return
    
    # 生成密码密钥
    hl = hashlib.md5()
    hl.update(password.encode('utf-8'))
    password_list = hl.hexdigest()
    
    hl.update(password_list.encode('utf-8'))
    password_list2 = hl.hexdigest()
    password_data = password_list + password_list2
    
    # 处理文件
    with open(infile, "rb") as a, open(outfile, "wb") as b:
        count = 0
        while True:
            chunk = a.read(4096)  # 每次读取4KB
            if not chunk:
                break
                
            encrypted_chunk = bytearray()
            for byte in chunk:
                # 使用异或运算进行加密/解密
                new_byte = byte ^ ord(password_data[count % len(password_data)])
                count += 1
                encrypted_chunk.append(new_byte)
            
            b.write(encrypted_chunk)


def random_string(length):
    return ''.join(choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))


def generate_key(event=None):
    n = randint(100000,999999)
    k = asksaveasfilename(title=langs[10],initialfile=f"key_AES_{n}.key")
    if k == "":
        return
    key = random_string(32)
    password = askpassword(langs[69], langs[70])
    if password == "" or password == None:
        return
    enpass = askpassword(langs[71], langs[72])
    if password != enpass:
        showerror(langs[14], langs[73])
        return
    with open(f"{k}.tmp","w") as file:
        file.write("--BEGIN KEYFILE--\n")
        file.write(key + "\n")
        file.write("--END KEYFILE--")
    crypto_file(f"{k}.tmp", k, password, "enc")
    os.remove(f"{k}.tmp")
    keyfile_2.delete(0,END)
    keyfile_2.insert(END,k)
    showinfo(langs[11],langs[12])
    new_log(f"{time_now()}  {langs[33]}: {k}")
    return k

def openfile(title=langs[4],filetype=None):
    if filetype == None:
        filet = [(langs[13],"*")]
    else:
        filet = filetype
    filename = askopenfilename(title=title,filetypes=filet)
    return filename
def open_source():
    a = openfile(title=langs[66])
    if a == "":
        return
    infile_2.delete(0,END)
    infile_2.insert(END,a)
def open_key():
    a = openfile(title=langs[67], filetype=[(langs[24], "*.key")])
    if a == "":
        return
    keyfile_2.delete(0,END)
    keyfile_2.insert(END,a)

def outpathf():
    global spath
    a = askdirectory(title=langs[4])
    if a == "":
        return
    outpath_2.delete(0,END)
    outpath_2.insert(END,a)

def directory_to_zip(directory_path):
    """
    将指定目录整体打包到ZIP文件中
    
    参数:
    directory_path (str): 要打包的目录路径
    
    返回:
    str: 生成的ZIP文件路径
    """
    # 确保目录存在
    if not os.path.isdir(directory_path):
        return
    
    # 获取目录的绝对路径和目录名
    abs_directory = os.path.abspath(directory_path)
    base_dir = os.path.basename(abs_directory)
    
    # 创建ZIP文件名 (目录名 + .zip)
    zip_filename = f"{base_dir}.zip"
    zip_path = os.path.join(os.path.dirname(abs_directory), zip_filename)
    
    # 创建ZIP文件并添加目录内容
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # 遍历目录树
        for root, dirs, files in os.walk(abs_directory):
            # 计算当前目录在ZIP中的相对路径
            rel_path = os.path.relpath(root, abs_directory)
            if rel_path == ".":  # 如果是根目录
                zip_root = base_dir
            else:
                zip_root = os.path.join(base_dir, rel_path)
            
            # 添加空目录（在ZIP中以/结尾）
            # 注意：这里直接添加当前目录，而不是循环添加子目录
            if not files and not dirs:  # 空目录处理
                zip_entry = zip_root + "/"
                zipf.write(root, zip_entry)
            
            # 添加文件
            for file in files:
                file_path = os.path.join(root, file)
                # 在ZIP中的相对路径
                zip_entry = os.path.join(zip_root, file)
                zipf.write(file_path, zip_entry)
    
    return zip_path

def check_file(event=None):
    global md5, sha1, sha256, sha384, sha512, crc32  # 添加crc32全局变量
    md5 = ""
    sha1 = ""
    sha256 = ""
    sha384 = ""
    sha512 = ""
    crc32 = 0  # 初始化CRC32值
    if out_file == None:
        showerror(langs[14], langs[50])
        return
    if crypting:
        showerror(langs[14], langs[51])
        return
    win = Toplevel(root)
    win.title(langs[52])
    if win_top == True:
        win.attributes("-topmost", 1)
    win.attributes("-toolwindow", 1)

    show = LabelFrame(win, text=langs[57])
    show.grid(row=0, column=0, padx=1, pady=1, sticky="we")
    
    # 创建文本控件
    text = Text(show, font=("Consolas", 10))
    text.pack(padx=1, pady=1, fill="both", expand=True)
    
    # 创建进度条框架
    progress_frame = Frame(show)
    progress_frame.pack(fill="x", padx=5, pady=5)
    
    # 添加进度标签
    progress_label = Label(progress_frame, text="0%")
    progress_label.pack(side="right", padx=5)
    
    # 添加进度条
    progress = ttk.Progressbar(
        progress_frame, 
        orient="horizontal", 
        length=300, 
        mode="determinate"
    )
    progress.pack(side="left", fill="x", expand=True, padx=5)

    verify = LabelFrame(win, text=langs[58])
    verify.grid(row=1, column=0, padx=1, pady=1, sticky="we")
    verify.rowconfigure(1, weight=1)
    verify.columnconfigure(1, weight=1)
    Label(verify, text=langs[59]).grid(row=0, column=0, padx=1, pady=1)
    alg = Combobox(verify)
    alg["values"] = ("CRC32", "md5", "SHA-1", "SHA-256", "SHA-384", "SHA-512")  # 添加CRC32选项
    alg["state"] = "readonly"
    alg.current(0)
    alg.grid(row=0, column=1, padx=1, pady=1, sticky="we", columnspan=4)
    Label(verify,text=langs[60]).grid(row=1, column=0, padx=1, pady=1)
    data_now = Entry(verify, font=("Consolas", 10))
    data_now.grid(row=1, column=1, padx=1, pady=1, sticky="we", columnspan=4)
    data_now.config(state="disabled")

    Label(verify, text=langs[61]).grid(row=2, column=0, padx=1, pady=1)
    data_in = Entry(verify, font=("Consolas", 10))
    data_in.grid(row=2, column=1, padx=1, pady=1, sticky="we", columnspan=4)
    
    compare_btn = Button(verify, text=langs[62], command=lambda: verify_data())
    compare_btn.grid(row=3, column=0, columnspan=5, pady=5)  # 添加grid布局

    def verify_data(event=None):
        data_f = data_now.get()
        data_i = data_in.get()
        if not data_i:
            showerror(langs[14], langs[63])
            return
        if data_f.lower() == data_i.lower():
            showinfo(langs[21], langs[64])
        else:
            showerror(langs[14], langs[65])

    data_in.bind("<Return>", verify_data)

    def change_alg(event):
        a = alg.get()
        data_now.config(state="normal")
        data_now.delete(0, END)
        if a == "md5":
            d = md5
        elif a == "SHA-1":
            d = sha1
        elif a == "SHA-256":
            d = sha256
        elif a == "SHA-384":
            d = sha384
        elif a == "SHA-512":
            d = sha512
        elif a == "CRC32":  # 添加CRC32处理
            d = f"{crc32:08x}"  # 格式化为8位小写十六进制
        else:
            d = ""
        data_now.insert(END, d)
        data_now.config(state="disabled")
        
    alg.bind("<<ComboboxSelected>>", change_alg)
    
    text.config(state="normal")
    text.delete("0.0", END)
    text.insert(END, langs[53])
    text.config(state="disabled")
    win.update()
    
    try:
        new_log(f"{time_now()}  {langs[101]}")
        file_size = os.path.getsize(out_file)
        read_so_far = 0
        last_percent = -1
        
        md5_checker = hashlib.md5()
        sha1_checker = hashlib.sha1()
        sha256_checker = hashlib.sha256()
        sha384_checker = hashlib.sha384()
        sha512_checker = hashlib.sha512()
        crc32_value = 0  # 初始化CRC32计算值
        
        # 处理零字节文件
        if file_size == 0:
            md5_checker.update(b"")
            sha1_checker.update(b"")
            sha256_checker.update(b"")
            sha384_checker.update(b"")
            sha512_checker.update(b"")
            crc32_value = zlib.crc32(b"") & 0xFFFFFFFF  # 空文件的CRC32
            progress["value"] = 100
            progress_label.config(text="100%")
        else:
            with open(out_file, "rb") as f:
                while chunk := f.read(64 * 1024):
                    md5_checker.update(chunk)
                    sha1_checker.update(chunk)
                    sha256_checker.update(chunk)
                    sha384_checker.update(chunk)
                    sha512_checker.update(chunk)
                    crc32_value = zlib.crc32(chunk, crc32_value) & 0xFFFFFFFF  # 更新CRC32
                    
                    read_so_far += len(chunk)
                    percent = int((read_so_far / file_size) * 100)
                    
                    # 优化：减少UI更新频率
                    if percent != last_percent:
                        progress["value"] = percent
                        progress_label.config(text=f"{percent}%")
                        win.update_idletasks()
                        last_percent = percent
        
        md5 = md5_checker.hexdigest()
        sha1 = sha1_checker.hexdigest()
        sha256 = sha256_checker.hexdigest()
        sha384 = sha384_checker.hexdigest()
        sha512 = sha512_checker.hexdigest()
        crc32 = crc32_value  # 存储最终的CRC32值
        
        text.config(state="normal")
        t = f"""{langs[54]}：

crc32:    {crc32:08x}

md5:      {md5}

sha1:     {sha1}

sha256:   {sha256}

sha384:   {sha384}

sha512:   {sha512}

{langs[55]}"""
        text.delete("0.0", END)
        text.insert(END, t)
        text.config(state="disabled")
        
        # 计算后自动更新比对数据
        change_alg(None)
        
    except Exception as e:
        showerror("Error", str(e))
        new_log(f"{time_now()}  {langs[99]}")
    finally:
        new_log(f"{time_now()}  {langs[100]}")
        progress["value"] = 0
        progress_label.config(text="0%")

font = ("Consolas", 10)
root = Tk()
root.title(langs[0])
root.resizable(0, 0)
if win_top == True:
    root.attributes("-topmost",True)
root.iconbitmap(default=filename)

crypt = Frame(root)
crypt.pack()

cmain = LabelFrame(crypt, text=langs[46])
cmain.grid(row=0, column=0, columnspan=2, padx=1, pady=1, sticky="ns")

infile_1 = Label(cmain,text=langs[1]).grid(row=0,column=0,padx=1,pady=1)
infile_2 = Entry(cmain,font=font)
infile_2.grid(row=0,column=1,columnspan=2,padx=1,pady=1)
infile_3 = Button(cmain,text=langs[4],command=open_source).grid(row=0,column=3,padx=1,pady=1)

keyfile_1 = Label(cmain,text=langs[2]).grid(row=1,column=0,padx=1,pady=1)
keyfile_2 = Entry(cmain,font=font)
keyfile_2.grid(row=1,column=1,columnspan=2,padx=1,pady=1)
keyfile_3 = Button(cmain,text=langs[4],command=open_key).grid(row=1,column=3,padx=1,pady=1)
keyfile_4 = Button(cmain,text=langs[11],command=generate_key).grid(row=1,column=4,padx=1,pady=1)

outpath_1 = Label(cmain,text=langs[3]).grid(row=2,column=0,padx=1,pady=1)
outpath_2 = Entry(cmain,font=font)
outpath_2.grid(row=2,column=1,columnspan=2,padx=1,pady=1)
outpath_3 = Button(cmain,text=langs[4],command=outpathf).grid(row=2,column=3,padx=1,pady=1)

def dragged_file_1(files):
    file = '\n'.join(item.decode('gbk') for item in files)
    infile_2.delete(0,END)
    infile_2.insert(0,file)

def dragged_file_2(files):
    file = '\n'.join(item.decode('gbk') for item in files)
    keyfile_2.delete(0,END)
    keyfile_2.insert(0,file)

windnd.hook_dropfiles(infile_2,func=dragged_file_1)
windnd.hook_dropfiles(keyfile_2,func=dragged_file_2)

style = Style()
style.layout('text.Horizontal.TProgressbar',
             [('Horizontal.Progressbar.trough',
               {'children': [('Horizontal.Progressbar.pbar',
                             {'side': 'left', 'sticky': 'ns'})],
                'sticky': 'nswe'}),
              ('Horizontal.Progressbar.label', {'sticky': ''})])
style.configure('text.Horizontal.TProgressbar', text=langs[29])

opition = LabelFrame(crypt, text=langs[47])
opition.grid(row=0, column=2, padx=1, pady=1, sticky="ns")

checkvar = BooleanVar()
Checkbutton(opition, text=langs[45], variable=checkvar).grid(row=0, column=0, padx=1, pady=1, sticky="we")

Button(opition, text=langs[56], command=check_file).grid(row=2, column=0, padx=1, pady=1, sticky="we")

log_p = LabelFrame(crypt, text=langs[79])
log_p.grid(row=1, column=0, padx=1, pady=1, columnspan=3, sticky="we")

log_frame = Frame(log_p)
log_frame.pack(side=tk.TOP, fill=tk.X, padx=1, pady=1)

log = Text(log_frame, font=("微软雅黑", 10))
log.pack(padx=1, pady=1, side=tk.LEFT, fill=tk.BOTH, expand=True)
scroll = Scrollbar(log_frame)
scroll.pack(side=RIGHT, fill=Y)
scroll.config(command=log.yview)
log.config(yscrollcommand=scroll.set)
log.config(state="disabled")

def new_log(text, line=True):
    log.config(state="normal")
    if line:
        log.insert(END, f"{text}\n")
    else:
        log.insert(END, text)
    log.config(state="disabled")
    log.see(END)
    return

def clean_log(event=None):
    log.config(state="normal")
    log.delete("0.0", END)
    log.config(state="disabled")
    return

p = Progressbar(log_p, style="text.Horizontal.TProgressbar")
p.pack(side=tk.BOTTOM, fill=tk.X, padx=1, pady=1)

def tpmost():
    global win_top
    a = check_top.get()
    if a == True:
        root.attributes("-topmost", True)
        config.set("config", "topmost", "true")
        with open(cfg_file, "w") as file:
            config.write(file)
        win_top = True
        new_log(f"{time_now()}  {langs[98]}")
    else:
        root.attributes("-topmost", False)
        config.set("config", "topmost", "false")
        with open(cfg_file, "w") as file:
            config.write(file)
        win_top = False
        new_log(f"{time_now()}  {langs[97]}")

check_top = BooleanVar(value=win_top)
Checkbutton(opition, text=langs[48], variable=check_top, command=tpmost).grid(row=1,column=0,padx=1,pady=1, sticky="we")

#状态栏
status_bar = Frame(root)
status_bar.pack(padx=1, pady=1, side=tk.BOTTOM, fill=tk.X)
status = tk.Label(status_bar, text=langs[88],
                      anchor=tk.W,
                      relief=tk.SUNKEN,
                      bd=1, bg="#e0e0e0",
                      padx=10)
status.pack(fill=tk.BOTH)

new_log(f"{time_now()}  {langs[94]}")
if new_cfg:
    new_log(f"{time_now()}  {langs[95]} {os.path.abspath(cfg_file)}")
new_log(f"{time_now()}  {langs[96]}")

def encrypt_file(input_path, output_path, key):
    global crypting
    """加密大文件"""
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    insize = os.path.getsize(input_path)
    p["maximum"] = insize
    p["value"] = 0
    style.configure("text.Horizontal.TProgressbar", text=f"{langs[32]}:0%")
    crypting = True
    root.update()
    
    last_update = 0
    update_interval = max(insize // 100, 1024*1024)  # 更新间隔为1%或1MB，取较大者
    
    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        fout.write(iv)  # 写入IV
        prev_chunk = None
        bytes_processed = 0
        
        while True:
            chunk = fin.read(64 * 1024)  # 每次读取64KB
            if not chunk:
                break
                
            if prev_chunk is not None:
                encrypted = cipher.encrypt(prev_chunk)
                fout.write(encrypted)
                bytes_processed += len(prev_chunk)
                
                # 只有当处理的数据量超过更新间隔时才更新UI
                if bytes_processed - last_update >= update_interval:
                    p["value"] = bytes_processed
                    style.configure("text.Horizontal.TProgressbar",
                                    text=f"{langs[30]}:{int(bytes_processed / insize * 100)}%")
                    root.update()
                    last_update = bytes_processed
                
            prev_chunk = chunk
            
        # 处理最后一个chunk并进行填充
        if prev_chunk is not None:
            padded_chunk = pad(prev_chunk, AES.block_size)
            fout.write(cipher.encrypt(padded_chunk))
            p["value"] = insize
            style.configure("text.Horizontal.TProgressbar", text=f"{langs[31]}:100%")
            root.update()
    showinfo(langs[21],langs[22])
    ctypes.windll.user32.FlashWindow(ctypes.windll.kernel32.GetConsoleWindow(), True )
    p["value"] = 0
    p["maximum"] = 0
    crypting = False
    style.configure("text.Horizontal.TProgressbar", text=langs[29])

def decrypt_file(input_path, output_path, key):
    global crypting
    """解密大文件"""
    insize = os.path.getsize(input_path)
    p["maximum"] = insize
    p["value"] = 0
    style.configure("text.Horizontal.TProgressbar", text=f"{langs[32]}:0%")
    crypting = True
    root.update()
    
    last_update = 0
    update_interval = max(insize // 100, 1024*1024)  # 更新间隔为1%或1MB，取较大者
    
    with open(input_path, 'rb') as fin:
        iv = fin.read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        bytes_processed = len(iv)
        p["value"] = bytes_processed
        root.update()
        
        with open(output_path, 'wb') as fout:
            buffer = b''
            while True:
                chunk = fin.read(64 * 1024)
                if not chunk:
                    break
                    
                decrypted = cipher.decrypt(chunk)
                buffer += decrypted
                bytes_processed += len(chunk)
                
                # 只有当处理的数据量超过更新间隔时才更新UI
                if bytes_processed - last_update >= update_interval:
                    p["value"] = bytes_processed
                    style.configure("text.Horizontal.TProgressbar",
                                  text=f"{langs[30]}:{int(bytes_processed / insize * 100)}%")
                    root.update()
                    last_update = bytes_processed
                
                # 写入除最后一个块外的所有完整块
                if len(buffer) > AES.block_size:
                    num_blocks = (len(buffer) - 1) // AES.block_size
                    write_bytes = num_blocks * AES.block_size
                    fout.write(buffer[:write_bytes])
                    buffer = buffer[write_bytes:]
                    
            # 处理最后一个块并尝试去除填充
            try:
                unpadded = unpad(buffer, AES.block_size)
                fout.write(unpadded)
            except ValueError:
                # 如果遇到无效填充，直接写入原始数据
                fout.write(buffer)
                # 设置错误标志，稍后显示警告
                padding_error = True
            
            p["value"] = insize
            style.configure("text.Horizontal.TProgressbar", text=f"{langs[31]}:100%")
            root.update()
    
    # 如果遇到填充错误，显示警告
    if 'padding_error' in locals() and padding_error:
        showwarning(langs[14], langs[68])
    else:
        showinfo(langs[21],langs[23])
    
    ctypes.windll.user32.FlashWindow(ctypes.windll.kernel32.GetConsoleWindow(), True )
    p["value"] = 0
    p["maximum"] = 0
    crypting = False
    style.configure("text.Horizontal.TProgressbar", text=langs[29])

def about():
    a = Tk()
    a.title(langs[8])
    if win_top == True:
        a.attributes("-topmost", True)
    a.attributes("-toolwindow", 1)
    text = Text(a,font=("微软雅黑", 10))
    scroll = Scrollbar(a)
    scroll.pack(side=RIGHT, fill=Y)
    text.pack(side=LEFT, fill=BOTH, expand=True)
    scroll.config(command=text.yview)
    text.config(yscrollcommand=scroll.set)
    t = langs["about"]
    text.insert(END,t)
    text.config(state="disabled")

def change_lang(lang):
    config = ConfigParser()
    config.read(cfg_file)
    config.set("config", "lang", lang)
    with open(cfg_file, "w") as conf:
        config.write(conf)
    showinfo(langs[21],langs[27])
    new_log(f"{time_now()}  {langs[26]}: {lang}")

def on_close(event=None):
    if crypting:
        if askokcancel(langs[28], langs[49]):
            root.destroy()
    else:
        root.destroy()

def crypt_main(source, keyfile, outpath="", password=None):
    global out_file
    if source == "":
        open_source()
    source = infile_2.get()
    if source == "":
        showerror(langs[14],langs[16])
        return
    if os.path.exists(source) == False:
        showerror(langs[14],langs[17])
        return
    source.replace("\\","/")
    if source.split("/")[-1].split(".")[-1] == "enc":
        types = 2
    else:
        types = 1
    if keyfile == "":
        open_key()
    keyfile = keyfile_2.get()
    if keyfile == "":
        showerror(langs[14],langs[18])
        return
    if os.path.exists(keyfile) == False:
        showerror(langs[14],langs[19])
        return
    keyfile.replace("\\","/")
    if os.path.getsize(keyfile) != 68:
        showerror(langs[14],langs[15])
        return
    if os.path.exists(outpath) == False:
        if outpath != "":
            showerror(langs[14],langs[20])
            return
    
    # 如果密码未提供，则从主线程获取
    if password is None:
        # 使用after在主线程中调度密码获取
        root.after(0, lambda: get_password_and_crypt(source, keyfile, outpath))
        return
    
    # 使用提供的密码处理密钥文件
    crypto_file(keyfile, f"{keyfile}.tmp", password, "dec")
    keyfile = f"{keyfile}.tmp"

    if os.path.isdir(source):
        showinfo("提示", langs[84])
        zipname = directory_to_zip(source)
        new_log(f"{time_now()}  {langs[86]}")
        new_log(f"{time_now()}  {langs[85]} {zipname}")
        source = zipname
    
    if types == 1:
        new_log(f"{time_now()}  {langs[89]}")
        status["text"] = langs[80]
        if outpath == "":
            outfilepath = source + ".enc"
        else:
            outfilename = source.split("/")[-1] + ".enc"
            outfilepath = os.path.join(outpath,outfilename)
        with open(keyfile,"r") as file:
            lines = file.readlines()
            if (lines[0].rstrip("\n") != "--BEGIN KEYFILE--") or (lines[2].rstrip("\n") != "--END KEYFILE--"):
                showerror(langs[14], langs[15])
                return
            key = bytes(lines[1].rstrip("\n").encode())
            
        encrypt_file(source,outfilepath,key)
        new_log(f"{time_now()}  {langs[81]}")
        new_log(f"{time_now()}  {langs[90]} {outfilepath}")
        status["text"] = langs[81]
        time.sleep(2)
        status["text"] = langs[88]
    else:
        new_log(f"{time_now()}  {langs[91]}")
        status["text"] = langs[82]
        if outpath == "":
            outfilepath = '.'.join(list(source.split(".")[:-1]))
        else:
            outfilename = '.'.join(list(source.split("/")[-1].split(".")[:-1]))
            outfilepath = os.path.join(outpath,outfilename)
        with open(keyfile,"r") as file:
            lines = file.readlines()
            if (lines[0].rstrip("\n") != "--BEGIN KEYFILE--") or (lines[2].rstrip("\n") != "--END KEYFILE--"):
                showerror(langs[14], langs[15])
                return
            key = bytes(lines[1].rstrip("\n").encode())
        decrypt_file(source,outfilepath,key)
        new_log(f"{time_now()}  {langs[83]}")
        new_log(f"{time_now()}  {langs[92]} {outfilepath}")
        if outfilepath.split(".")[-1] == "zip":
            a = askyesno(langs[41], langs[42])
            if a == True:
                file = zipfile.ZipFile(outfilepath)
                if not zipfile.is_zipfile(outfilepath):
                    showerror(langs[14], langs[44])
                p = askdirectory(title=langs[43])
                file.extractall(path=p)
                new_log(f"{time_now()}  {langs[87]}")
        status["text"] = langs[83]
        time.sleep(2)
        status["text"] = langs[88]
    if checkvar.get() == True:
        os.remove(source)
        new_log(f"{time_now()}  {langs[93]}")
    out_file = outfilepath
    os.remove(keyfile)

def get_password_and_crypt(source, keyfile, outpath):
    """在主线程中获取密码并继续加密过程"""
    password = askpassword(langs[69], langs[75])
    if not password:
        showerror(langs[14], langs[74])
        return
    
    # 启动后台线程执行加密/解密
    p = Thread(target=crypt_main, args=(source, keyfile, outpath, password))
    p.start()

def main():
    source = infile_2.get()
    keyfile = keyfile_2.get()
    outpath = outpath_2.get()
    
    # 启动加密过程（会先获取密码）
    crypt_main(source, keyfile, outpath)

mainmenu = Menu(root,tearoff=menu_tearoff)

if lang == "zh_cn":
    check = IntVar(value=0)
else:
    check = IntVar(value=1)

toolmenu = Menu(mainmenu, tearoff=menu_tearoff)
lang_menu = Menu(toolmenu, tearoff=menu_tearoff)
lang_menu.add_radiobutton(label="简体中文", variable=check, value=0, command=lambda: change_lang("zh_cn"))
lang_menu.add_radiobutton(label="English", variable=check, value=1, command=lambda: change_lang("en_us"))
toolmenu.add_cascade(label=langs[26], menu=lang_menu)
toolmenu.add_command(label=langs[33], command=generate_key, accelerator="Ctrl+G")
toolmenu.add_command(label=langs[56], command=check_file, accelerator="Ctrl+I")
toolmenu.add_separator()
toolmenu.add_command(label=f"{langs[28]}...", command=on_close, accelerator="Ctrl+E")
mainmenu.add_cascade(label=langs[25], menu=toolmenu)

aboutmenu = Menu(root,tearoff=menu_tearoff)
aboutmenu.add_command(label=langs[8],command=about)
mainmenu.add_cascade(label=langs[7],menu=aboutmenu)
root.config(menu=mainmenu)

popmenu = Menu(root, tearoff=menu_tearoff)
p_lang_menu = Menu(popmenu, tearoff=menu_tearoff)
p_lang_menu.add_radiobutton(label="简体中文", variable=check, value=0, command=lambda: change_lang("zh_cn"))
p_lang_menu.add_radiobutton(label="English", variable=check, value=1, command=lambda: change_lang("en_us"))
popmenu.add_cascade(label=langs[26], menu=lang_menu)
popmenu.add_command(label=langs[33], command=generate_key, accelerator="Ctrl+G")
popmenu.add_command(label=langs[56], command=check_file, accelerator="Ctrl+I")
popmenu.add_command(label=langs[8],command=about)
popmenu.add_separator()
popmenu.add_command(label=f"{langs[28]}...", command=on_close, accelerator="Ctrl+E")

def popup(event):
    popmenu.post(event.x_root, event.y_root)

button = Button(cmain,text=langs[6],command=main)
button.grid(row=4,column=2,padx=1,pady=1,sticky="e")
button_2 = Button(cmain, text=langs[28], command=on_close).grid(row=4,column=3,padx=1,pady=1,sticky="we")

root.bind("<Button-3>", popup)
root.bind("<Control-g>", generate_key)
root.bind("<Control-G>", generate_key)
root.bind("<Control-i>", check_file)
root.bind("<Control-I>", check_file)
root.bind("<Control-e>", on_close)
root.bind("<Control-E>", on_close)

root.protocol("WM_DELETE_WINDOW", on_close)
root.mainloop()
