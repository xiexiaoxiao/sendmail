#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import json
import random
import smtplib
from email import message_from_file
from email.utils import parseaddr, formataddr, formatdate
from email.parser import Parser
from email.policy import default
import queue

VERSION = "v1.0"

class EmailSenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"邮件发送工具 {VERSION}")
        self.root.geometry("800x750")  # 增加初始高度
        self.root.resizable(True, True)
        
        # 设置样式
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", background="#e0e0e0", font=('Arial', 10))
        self.style.configure("TLabel", background="#f0f0f0", font=('Arial', 10))
        self.style.configure("Header.TLabel", font=('Arial', 12, 'bold'))
        
        # 创建消息队列，用于在线程间通信
        self.message_queue = queue.Queue()
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # 配置root窗口的grid权重，让main_frame可以扩展
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # 创建界面元素
        self._create_sender_frame()
        self._create_server_frame()
        self._create_recipient_frame()
        self._create_email_frame()
        self._create_log_frame()
        self._create_action_frame()
        
        # 初始化发送状态
        self.sending = False
        self.send_thread = None
        
        # 定期检查消息队列
        self._check_message_queue()
        
        # 窗口自适应调整
        self.root.update()
        window_width = max(800, self.root.winfo_reqwidth())
        window_height = max(750, self.root.winfo_reqheight())
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # 计算窗口位置，使其居中
        x = int((screen_width - window_width) / 2)
        y = int((screen_height - window_height) / 2)
        
        # 设置窗口大小和位置
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    def _create_sender_frame(self):
        """创建发件人配置区域"""
        frame = ttk.LabelFrame(self.main_frame, text="发件人配置", padding="5")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 让frame可以水平扩展
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # 发件人邮箱
        ttk.Label(frame, text="发件人邮箱:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.from_addr_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.from_addr_var, width=30).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # 发件人显示名称
        ttk.Label(frame, text="发件人显示名称:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.from_name_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.from_name_var, width=30).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # 用户名和密码
        ttk.Label(frame, text="SMTP用户名:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.username_var, width=30).grid(row=0, column=3, sticky=tk.W+tk.E, padx=5, pady=5)
        
        ttk.Label(frame, text="SMTP密码:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, width=30, show="*").grid(row=1, column=3, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # 设置列的权重，使得输入框可以扩展
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(3, weight=1)
        
    def _create_server_frame(self):
        """创建服务器配置区域"""
        frame = ttk.LabelFrame(self.main_frame, text="服务器配置", padding="5")
        frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # SMTP服务器
        ttk.Label(frame, text="SMTP服务器:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.server_var = tk.StringVar(value="smtp.163.com")
        ttk.Entry(frame, textvariable=self.server_var, width=20).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # 端口
        ttk.Label(frame, text="端口:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.port_var = tk.IntVar(value=465)
        ttk.Entry(frame, textvariable=self.port_var, width=10).grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # 发送间隔和随机等待
        ttk.Label(frame, text="发送间隔(秒):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.sleep_var = tk.DoubleVar(value=0)
        ttk.Entry(frame, textvariable=self.sleep_var, width=10).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        self.random_sleep_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="使用随机等待(1-3秒)", variable=self.random_sleep_var).grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        # 设置列的权重
        frame.grid_columnconfigure(1, weight=1)
    
    def _create_recipient_frame(self):
        """创建收件人配置区域"""
        frame = ttk.LabelFrame(self.main_frame, text="收件人配置", padding="5")
        frame.grid(row=2, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 单个收件人
        ttk.Label(frame, text="单个收件人:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.to_addr_var = tk.StringVar()
        self.to_addr_entry = ttk.Entry(frame, textvariable=self.to_addr_var, width=30)
        self.to_addr_entry.grid(row=0, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # 收件人列表文件
        ttk.Label(frame, text="收件人列表文件:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.to_list_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.to_list_var, width=30, state="readonly").grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        ttk.Button(frame, text="浏览...", command=self._browse_recipient_list).grid(row=1, column=2, padx=5, pady=5)
        ttk.Button(frame, text="清除", command=lambda: self.to_list_var.set("")).grid(row=1, column=3, padx=5, pady=5)
        
        # 收件人列表信息
        self.recipient_count_var = tk.StringVar(value="收件人数量: 0")
        ttk.Label(frame, textvariable=self.recipient_count_var).grid(row=2, column=0, columnspan=4, sticky=tk.W, padx=5, pady=5)
        
        # 设置列的权重
        frame.grid_columnconfigure(1, weight=1)
        
    def _create_email_frame(self):
        """创建邮件文件配置区域"""
        frame = ttk.LabelFrame(self.main_frame, text="邮件文件", padding="5")
        frame.grid(row=3, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 创建一个Frame来包含Listbox和Scrollbar
        list_frame = ttk.Frame(frame)
        list_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E), padx=5, pady=5)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # EML文件列表
        self.eml_files_listbox = tk.Listbox(list_frame, height=5)
        self.eml_files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.eml_files_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.eml_files_listbox.configure(yscrollcommand=scrollbar.set)
        
        # 添加和删除按钮
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Button(button_frame, text="添加邮件文件", command=self._add_eml_files).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(button_frame, text="删除选中文件", command=self._remove_selected_eml).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(button_frame, text="清空列表", command=self._clear_eml_list).grid(row=0, column=2, padx=5, pady=5)
        
        # 均匀分布按钮
        for i in range(3):
            button_frame.grid_columnconfigure(i, weight=1)
        
        # 存储EML文件路径
        self.eml_files = []
        
        # 设置列的权重
        frame.grid_columnconfigure(0, weight=1)
        
    def _create_log_frame(self):
        """创建日志显示区域"""
        frame = ttk.LabelFrame(self.main_frame, text="发送日志", padding="5")
        frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # 让log_frame能够垂直扩展
        self.main_frame.grid_rowconfigure(4, weight=1)
        
        # 日志文本框
        self.log_text = scrolledtext.ScrolledText(frame, height=10, width=80)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
        # 让文本框可以扩展
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        
    def _create_action_frame(self):
        """创建操作按钮区域"""
        frame = ttk.Frame(self.main_frame, padding="5")
        frame.grid(row=5, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 按钮区域
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 保存配置按钮
        ttk.Button(button_frame, text="保存配置", command=self._save_config).grid(row=0, column=0, padx=5, pady=5)
        
        # 加载配置按钮
        ttk.Button(button_frame, text="加载配置", command=self._load_config).grid(row=0, column=1, padx=5, pady=5)
        
        # 发送按钮
        self.send_button = ttk.Button(button_frame, text="开始发送", command=self._start_sending)
        self.send_button.grid(row=0, column=2, padx=5, pady=5)
        
        # 停止按钮
        self.stop_button = ttk.Button(button_frame, text="停止发送", command=self._stop_sending, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5, pady=5)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=400, mode='determinate', variable=self.progress_var)
        self.progress.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 进度标签
        self.progress_label = ttk.Label(frame, text="准备就绪")
        self.progress_label.grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        
        # 设置列的权重
        frame.grid_columnconfigure(0, weight=1)
        
        # 均匀分布按钮
        for i in range(4):
            button_frame.grid_columnconfigure(i, weight=1)
    
    def _browse_recipient_list(self):
        """浏览选择收件人列表文件"""
        filename = filedialog.askopenfilename(
            title="选择收件人列表文件",
            filetypes=(("文本文件", "*.txt"), ("所有文件", "*.*"))
        )
        if filename:
            self.to_list_var.set(filename)
            self._update_recipient_count()
    
    def _update_recipient_count(self):
        """更新收件人数量显示"""
        filename = self.to_list_var.get()
        if filename and os.path.exists(filename):
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    recipients = [line.strip() for line in f if line.strip() and '@' in line]
                self.recipient_count_var.set(f"收件人数量: {len(recipients)}")
            except Exception as e:
                self.recipient_count_var.set(f"读取错误: {str(e)}")
        else:
            self.recipient_count_var.set("收件人数量: 0")
    
    def _add_eml_files(self):
        """添加EML文件到列表"""
        files = filedialog.askopenfilenames(
            title="选择EML文件",
            filetypes=(("EML文件", "*.eml"), ("所有文件", "*.*"))
        )
        for file in files:
            if file not in self.eml_files:
                self.eml_files.append(file)
                self.eml_files_listbox.insert(tk.END, os.path.basename(file))
    
    def _remove_selected_eml(self):
        """删除选中的EML文件"""
        selected_indices = self.eml_files_listbox.curselection()
        for index in sorted(selected_indices, reverse=True):
            self.eml_files_listbox.delete(index)
            del self.eml_files[index]
    
    def _clear_eml_list(self):
        """清空EML文件列表"""
        self.eml_files_listbox.delete(0, tk.END)
        self.eml_files = []
    
    def _save_config(self):
        """保存当前配置到文件"""
        filename = filedialog.asksaveasfilename(
            title="保存配置",
            defaultextension=".json",
            filetypes=(("JSON文件", "*.json"), ("所有文件", "*.*"))
        )
        if not filename:
            return
        
        config = {
            "from_addr": self.from_addr_var.get(),
            "from_name": self.from_name_var.get(),
            "username": self.username_var.get(),
            "password": self.password_var.get(),  # 注意：这会保存密码明文，生产环境建议加密
            "server": self.server_var.get(),
            "port": self.port_var.get(),
            "sleep": self.sleep_var.get(),
            "random_sleep": self.random_sleep_var.get(),
            "to_addr": self.to_addr_var.get(),
            "to_list_file": self.to_list_var.get()
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            self._log(f"配置已保存到 {filename}")
        except Exception as e:
            self._log(f"保存配置失败: {str(e)}")
            messagebox.showerror("保存失败", f"保存配置失败: {str(e)}")
    
    def _load_config(self):
        """从文件加载配置"""
        filename = filedialog.askopenfilename(
            title="加载配置",
            filetypes=(("JSON文件", "*.json"), ("所有文件", "*.*"))
        )
        if not filename:
            return
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            self.from_addr_var.set(config.get("from_addr", ""))
            self.from_name_var.set(config.get("from_name", ""))
            self.username_var.set(config.get("username", ""))
            if "password" in config:
                self.password_var.set(config.get("password", ""))
            self.server_var.set(config.get("server", "smtp.163.com"))
            self.port_var.set(config.get("port", 465))
            self.sleep_var.set(config.get("sleep", 0))
            self.random_sleep_var.set(config.get("random_sleep", True))
            self.to_addr_var.set(config.get("to_addr", ""))
            self.to_list_var.set(config.get("to_list_file", ""))
            
            self._update_recipient_count()
            self._log(f"配置已从 {filename} 加载")
        except Exception as e:
            self._log(f"加载配置失败: {str(e)}")
            messagebox.showerror("加载失败", f"加载配置失败: {str(e)}")
    
    def _start_sending(self):
        """开始发送邮件"""
        # 检查必填项
        if not self._validate_input():
            return
        
        # 禁用发送按钮，启用停止按钮
        self.sending = True
        self.send_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # 清空日志
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # 收集参数
        params = {
            "from_addr": self.from_addr_var.get(),
            "from_name": self.from_name_var.get(),
            "to_addr": self.to_addr_var.get(),
            "to_list_file": self.to_list_var.get(),
            "server": self.server_var.get(),
            "port": self.port_var.get(),
            "username": self.username_var.get(),
            "password": self.password_var.get(),
            "sleep": self.sleep_var.get(),
            "random_sleep": self.random_sleep_var.get(),
            "eml_files": self.eml_files.copy()
        }
        
        # 启动发送线程
        self.send_thread = threading.Thread(target=self._send_emails, args=(params,))
        self.send_thread.daemon = True
        self.send_thread.start()
    
    def _validate_input(self):
        """验证输入参数"""
        if not self.from_addr_var.get():
            messagebox.showerror("验证失败", "请输入发件人邮箱")
            return False
        
        if not self.username_var.get() or not self.password_var.get():
            messagebox.showerror("验证失败", "请输入SMTP用户名和密码")
            return False
        
        if not self.server_var.get():
            messagebox.showerror("验证失败", "请输入SMTP服务器地址")
            return False
        
        if not self.eml_files:
            messagebox.showerror("验证失败", "请添加至少一个EML文件")
            return False
        
        if not self.to_addr_var.get() and not self.to_list_var.get():
            messagebox.showerror("验证失败", "请输入收件人邮箱或选择收件人列表文件")
            return False
        
        return True
    
    def _stop_sending(self):
        """停止发送邮件"""
        self.sending = False
        self.stop_button.config(state=tk.DISABLED)
        self.progress_label.config(text="正在停止...")
        self._log("用户请求停止发送")
    
    def _send_emails(self, params):
        """在单独的线程中发送邮件"""
        try:
            self.message_queue.put(("log", "开始发送邮件..."))
            self.message_queue.put(("progress_label", "准备发送..."))
            
            # 读取收件人列表
            recipients = []
            if params["to_list_file"]:
                try:
                    with open(params["to_list_file"], 'r', encoding='utf-8') as f:
                        recipients = [line.strip() for line in f if line.strip() and '@' in line]
                    self.message_queue.put(("log", f"从列表文件加载了 {len(recipients)} 个收件人"))
                except Exception as e:
                    self.message_queue.put(("log", f"读取收件人列表失败: {str(e)}"))
                    messagebox.showerror("读取失败", f"读取收件人列表失败: {str(e)}")
                    self._reset_ui()
                    return
            else:
                recipients = [params["to_addr"]]
            
            # 计算总任务数
            total_tasks = len(recipients) * len(params["eml_files"])
            completed_tasks = 0
            
            # 更新进度条最大值
            self.message_queue.put(("progress_max", total_tasks))
            
            # 开始发送
            for recipient in recipients:
                if not self.sending:
                    break
                
                for eml_file in params["eml_files"]:
                    if not self.sending:
                        break
                    
                    self.message_queue.put(("progress_label", f"正在发送到 {recipient}..."))
                    
                    try:
                        # 处理EML文件
                        with open(eml_file, 'r', encoding='utf-8') as f:
                            eml_content = f.read()
                        
                        # 修改邮件头
                        eml_content = self._modify_email_headers(
                            eml_content, 
                            params["from_addr"], 
                            params["from_name"],
                            recipient
                        )
                        
                        # 发送邮件
                        self._send_single_email(
                            params["server"],
                            params["port"],
                            params["username"],
                            params["password"],
                            params["from_addr"],
                            recipient,
                            eml_content
                        )
                        
                        self.message_queue.put(("log", f"成功发送 {os.path.basename(eml_file)} 到 {recipient}"))
                    except Exception as e:
                        self.message_queue.put(("log", f"发送失败 {os.path.basename(eml_file)} 到 {recipient}: {str(e)}"))
                    
                    # 更新进度
                    completed_tasks += 1
                    self.message_queue.put(("progress", completed_tasks))
                    
                    # 等待指定时间
                    if self.sending and (len(params["eml_files"]) > 1 or len(recipients) > 1):
                        sleep_time = 0
                        if params["random_sleep"]:
                            sleep_time = random.uniform(1, 3)
                            self.message_queue.put(("log", f"随机等待 {sleep_time:.2f} 秒..."))
                        elif params["sleep"] > 0:
                            sleep_time = params["sleep"]
                            self.message_queue.put(("log", f"等待 {sleep_time:.2f} 秒..."))
                        
                        if sleep_time > 0:
                            time.sleep(sleep_time)
            
            if self.sending:
                self.message_queue.put(("progress_label", "发送完成"))
                self.message_queue.put(("log", "所有邮件发送完成"))
            else:
                self.message_queue.put(("progress_label", "发送已停止"))
                self.message_queue.put(("log", "邮件发送已停止"))
        
        except Exception as e:
            self.message_queue.put(("log", f"发送过程中发生错误: {str(e)}"))
        
        finally:
            self._reset_ui()
    
    def _modify_email_headers(self, eml_content, from_addr, from_name, to_addr):
        """修改邮件头部信息"""
        # 使用Parser解析邮件内容
        parser = Parser(policy=default)
        msg = parser.parsestr(eml_content)
        
        # 处理发件人
        if from_name:
            new_from = formataddr((from_name, from_addr))
        else:
            new_from = from_addr
        
        if 'From' in msg:
            msg.replace_header('From', new_from)
        else:
            msg.add_header('From', new_from)
        
        # 处理收件人 - 去除昵称
        if 'To' in msg:
            msg.replace_header('To', to_addr)
        else:
            msg.add_header('To', to_addr)
        
        # 更新邮件日期为当前时间
        if 'Date' in msg:
            msg.replace_header('Date', formatdate(localtime=True))
        else:
            msg.add_header('Date', formatdate(localtime=True))
        
        # 添加唯一的Message-ID
        domain = from_addr.split('@')[1]
        message_id = f'<{int(time.time())}_{random.randint(1000, 9999)}@{domain}>'
        if 'Message-ID' in msg:
            msg.replace_header('Message-ID', message_id)
        else:
            msg.add_header('Message-ID', message_id)
        
        # 添加X-Mailer头
        if 'X-Mailer' in msg:
            msg.replace_header('X-Mailer', f'SendmailTool/{VERSION}')
        else:
            msg.add_header('X-Mailer', f'SendmailTool/{VERSION}')
        
        return msg.as_string()
    
    def _send_single_email(self, server, port, username, password, from_addr, to_addr, eml_content):
        """发送单个邮件"""
        try:
            port = int(port)  # 确保端口是整数
            
            if port == 465:
                with smtplib.SMTP_SSL(server, port) as smtp:
                    smtp.login(username, password)
                    smtp.sendmail(from_addr, to_addr, eml_content)
            else:
                with smtplib.SMTP(server, port) as smtp:
                    smtp.ehlo()
                    if smtp.has_extn('STARTTLS'):
                        smtp.starttls()
                        smtp.ehlo()
                    smtp.login(username, password)
                    smtp.sendmail(from_addr, to_addr, eml_content)
        except Exception as e:
            raise Exception(f"发送邮件失败: {str(e)}")
    
    def _reset_ui(self):
        """重置UI状态"""
        self.sending = False
        self.message_queue.put(("send_button_state", tk.NORMAL))
        self.message_queue.put(("stop_button_state", tk.DISABLED))
    
    def _log(self, message):
        """向日志窗口添加消息"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def _check_message_queue(self):
        """检查消息队列，并处理消息"""
        try:
            while True:
                message = self.message_queue.get_nowait()
                
                if message[0] == "log":
                    self._log(message[1])
                elif message[0] == "progress":
                    self.progress_var.set(message[1])
                elif message[0] == "progress_max":
                    self.progress.config(maximum=message[1])
                    self.progress_var.set(0)
                elif message[0] == "progress_label":
                    self.progress_label.config(text=message[1])
                elif message[0] == "send_button_state":
                    self.send_button.config(state=message[1])
                elif message[0] == "stop_button_state":
                    self.stop_button.config(state=message[1])
                
                self.message_queue.task_done()
        
        except queue.Empty:
            pass
        
        # 100毫秒后再次检查
        self.root.after(100, self._check_message_queue)


def main():
    root = tk.Tk()
    app = EmailSenderGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
