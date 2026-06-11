import os
import re
import zipfile
import tempfile
import shutil
import subprocess
import platform
import threading
import json
import sys
import time
import importlib.util
from datetime import datetime
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
from tkinter.scrolledtext import ScrolledText
import httpx
import queue

# 尝试导入 requests
try:
    import requests
except ImportError:
    requests = None

# 代理配置文件
PROXY_CONFIG_FILE = "proxy_config.json"

# 调试日志
debug_logs = []
log_lock = threading.Lock()

def log_message(msg):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with log_lock:
        debug_logs.append(f"[{timestamp}] {msg}")
        if len(debug_logs) > 5000:
            debug_logs.pop(0)
    print(msg)

def get_all_logs():
    with log_lock:
        return debug_logs.copy()

def clear_logs():
    with log_lock:
        debug_logs.clear()

# ------------------------------ 删除操作日志 ------------------------------
deletion_log = []
deletion_log_lock = threading.Lock()

def add_deletion_log(source, file_path, line_numbers, rule_descs, code_snippets):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with deletion_log_lock:
        deletion_log.append({
            "timestamp": timestamp,
            "source": source,
            "file_path": file_path,
            "line_numbers": line_numbers,
            "rule_descs": rule_descs,
            "code_snippets": code_snippets
        })

def get_deletion_log():
    with deletion_log_lock:
        return deletion_log.copy()

def clear_deletion_log():
    with deletion_log_lock:
        deletion_log.clear()

# ------------------------------ 规则动态加载 ------------------------------
MALICIOUS_PATTERNS = {}

def load_rules_from_file(filepath):
    if not os.path.exists(filepath):
        messagebox.showerror("规则文件缺失", f"找不到文件：{filepath}\n请确保该文件存在于程序目录中。")
        return None
    try:
        spec = importlib.util.spec_from_file_location("rules_module", filepath)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "MALICIOUS_PATTERNS"):
            return module.MALICIOUS_PATTERNS
        else:
            messagebox.showerror("规则文件错误", f"{filepath} 中未找到 MALICIOUS_PATTERNS 字典")
            return None
    except Exception as e:
        messagebox.showerror("加载规则失败", f"加载 {filepath} 时出错：{str(e)}")
        return None

# ------------------------------ 代理配置管理 ------------------------------
def load_proxy_config():
    if os.path.exists(PROXY_CONFIG_FILE):
        try:
            with open(PROXY_CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return None
    return None

def save_proxy_config(config):
    with open(PROXY_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

def clear_proxy_config():
    if os.path.exists(PROXY_CONFIG_FILE):
        os.remove(PROXY_CONFIG_FILE)

def check_socks_dependencies():
    if not requests:
        return False, "requests 库未安装"
    try:
        import socks
        return True, None
    except ImportError:
        return False, "缺少 PySocks 库，请执行: pip install PySocks"

def get_requests_proxy_dict(config):
    if not config:
        return None
    proxy_type = config.get("type", "http").lower()
    server = config.get("server", "")
    port = config.get("port", "")
    username = config.get("username", "")
    password = config.get("password", "")
    if not server or not port:
        return None
    if proxy_type == "socks5":
        ok, err = check_socks_dependencies()
        if not ok:
            log_message(f"SOCKS 依赖检查失败: {err}")
            return None
    if username and password:
        auth = f"{username}:{password}@"
    else:
        auth = ""
    proxy_url = f"{proxy_type}://{auth}{server}:{port}"
    return {"http": proxy_url, "https": proxy_url}

def test_proxy_connection(proxy_config, timeout=10):
    if not requests:
        return False, "requests 库未安装", None
    proxies = get_requests_proxy_dict(proxy_config)
    if not proxies:
        return False, "代理配置无效", None
    start_time = time.time()
    try:
        response = requests.get("https://www.google.com", proxies=proxies, timeout=timeout, verify=False)
        elapsed_ms = (time.time() - start_time) * 1000
        if response.status_code == 200:
            return True, f"连接成功 (200)，耗时 {elapsed_ms:.0f}ms", elapsed_ms
        else:
            return False, f"状态码 {response.status_code}", elapsed_ms
    except Exception as e:
        return False, f"测试失败: {str(e)[:60]}", None

# ------------------------------ 扫描核心 ------------------------------
def scan_text_by_line(content_lines: list) -> list:
    findings = []
    for line_no, line in enumerate(content_lines, start=1):
        line_stripped = line.rstrip('\n\r')
        for pattern, desc in MALICIOUS_PATTERNS.items():
            matches = re.findall(pattern, line_stripped)
            for m in matches:
                findings.append((line_no, line_stripped, m, desc))
    return findings

def scan_file(file_path: str) -> dict:
    result = {"path": file_path, "malicious": False, "findings": [], "error": None}
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        findings = scan_text_by_line(lines)
        if findings:
            result["malicious"] = True
            result["findings"] = findings
    except Exception as e:
        result["error"] = str(e)
    return result

def scan_zip(zip_path: str, extract_dir: str) -> list:
    results = []
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)
        for root, _, files in os.walk(extract_dir):
            for file in files:
                full = os.path.join(root, file)
                results.append(scan_file(full))
    except Exception as e:
        results.append({"path": zip_path, "malicious": False, "findings": [], "error": f"解压失败: {e}"})
    return results

def open_file_at_line(file_path, line_number):
    line_number = int(line_number)
    system = platform.system()
    # VS Code
    code_cmd = None
    if system == "Windows":
        possible_paths = [
            r"C:\Program Files\Microsoft VS Code\bin\code.cmd",
            r"C:\Program Files (x86)\Microsoft VS Code\bin\code.cmd",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Microsoft VS Code\bin\code.cmd"),
        ]
        for p in possible_paths:
            if os.path.isfile(p):
                code_cmd = p
                break
        if not code_cmd:
            which_code = shutil.which("code.cmd") or shutil.which("code")
            if which_code:
                code_cmd = which_code
    else:
        which_code = shutil.which("code")
        if which_code:
            code_cmd = which_code
    if code_cmd:
        try:
            target = f"{file_path}:{line_number}"
            subprocess.run([code_cmd, "--goto", target], check=False, timeout=5)
            return
        except Exception as e:
            print(f"VS Code 跳转失败: {e}")
    # Sublime Text
    subl_path = None
    if shutil.which("subl"):
        subl_path = "subl"
    elif system == "Windows":
        common_paths = [
            r"C:\Program Files\Sublime Text\subl.exe",
            r"C:\Program Files (x86)\Sublime Text\subl.exe"
        ]
        for p in common_paths:
            if os.path.isfile(p):
                subl_path = p
                break
    if subl_path:
        try:
            subprocess.run([subl_path, f"{file_path}:{line_number}"], check=False, timeout=5)
            return
        except Exception as e:
            print(f"Sublime Text 跳转失败: {e}")
    # 记事本
    if system == "Windows":
        notepad_path = None
        if os.path.isfile(r"C:\Windows\System32\notepad.exe"):
            notepad_path = r"C:\Windows\System32\notepad.exe"
        elif os.path.isfile(r"C:\Windows\SysWOW64\notepad.exe"):
            notepad_path = r"C:\Windows\SysWOW64\notepad.exe"
        if notepad_path:
            try:
                subprocess.run([notepad_path, file_path], check=False, timeout=5)
                messagebox.showinfo("打开文件",
                    f"已用记事本打开文件：{os.path.basename(file_path)}\n"
                    f"请手动跳转到第 {line_number} 行（记事本不支持自动跳转）。")
                return
            except Exception as e:
                print(f"记事本打开失败: {e}")
    # 最终回退
    try:
        if system == "Windows":
            os.startfile(file_path)
        elif system == "Darwin":
            subprocess.run(["open", file_path], check=False)
        else:
            subprocess.run(["xdg-open", file_path], check=False)
        messagebox.showinfo("打开文件", f"文件已用默认程序打开\n请手动跳转到第 {line_number} 行。")
    except Exception as e:
        messagebox.showerror("打开失败", f"无法打开文件：{str(e)}")

# ------------------------------ 删除辅助函数（带source） ------------------------------
def delete_selected_lines_from_files(tree, source):
    selected = tree.selection()
    if not selected:
        messagebox.showinfo("提示", "未选中任何行")
        return
    items_to_delete = []
    for item in selected:
        values = tree.item(item, "values")
        if len(values) >= 5:
            file_path = values[0]
            line_str = values[4]
            rule_desc = values[2]
            code_snippet = values[3]
            if line_str.isdigit():
                items_to_delete.append((file_path, int(line_str), item, rule_desc, code_snippet))
    if not items_to_delete:
        messagebox.showinfo("提示", "选中的行没有有效的行号信息")
        return

    files_map = {}
    for fp, ln, item_id, rule_desc, snippet in items_to_delete:
        if fp not in files_map:
            files_map[fp] = []
        files_map[fp].append((ln, rule_desc, snippet, item_id))

    total_lines = sum(len(lst) for lst in files_map.values())
    if not messagebox.askyesno("确认删除", f"即将从 {len(files_map)} 个文件中删除 {total_lines} 行恶意代码。\n此操作不可撤销，是否继续？"):
        return

    for file_path, line_list in files_map.items():
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            line_numbers = sorted(set(ln for ln, _, _, _ in line_list), reverse=True)
            rule_descs_for_file = [desc for _, desc, _, _ in line_list]
            code_snippets_for_file = [snippet for _, _, snippet, _ in line_list]
            for ln in line_numbers:
                if 1 <= ln <= len(lines):
                    del lines[ln-1]
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            log_message(f"已从 {file_path} 中删除行: {line_numbers}")
            add_deletion_log(source, file_path, line_numbers, rule_descs_for_file, code_snippets_for_file)
        except Exception as e:
            messagebox.showerror("删除失败", f"处理文件 {file_path} 时出错：{str(e)}")
            return

    refreshed_files = set(fp for fp, _ in files_map.items())
    all_items = tree.get_children()
    for item in all_items:
        values = tree.item(item, "values")
        if len(values) >= 1 and values[0] in refreshed_files:
            tree.delete(item)
    for file_path in refreshed_files:
        res = scan_file(file_path)
        if res["malicious"]:
            for line_no, line_content, match, desc in res["findings"]:
                snippet = line_content.strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."
                tree.insert("", END, values=(
                    file_path, "高危", f"{desc} ({match})", snippet, str(line_no)
                ))
        elif res["error"]:
            tree.insert("", END, values=(file_path, "错误", res["error"], "", "-"))
        else:
            tree.insert("", END, values=(file_path, "安全", "已删除恶意代码，未发现其他恶意模式", "", ""))
    messagebox.showinfo("删除完成", f"已成功删除 {total_lines} 行恶意代码。")

def add_right_click_menu(tree, source):
    tree.configure(selectmode='extended')
    def select_all(event):
        tree.selection_set(tree.get_children())
        return "break"
    tree.bind("<Control-a>", select_all)
    tree.bind("<Control-A>", select_all)

    menu = Menu(tree, tearoff=0)
    menu.add_command(label="删除选中行（从文件中永久删除）", 
                     command=lambda: delete_selected_lines_from_files(tree, source))
    def show_menu(event):
        row_id = tree.identify_row(event.y)
        if row_id and row_id not in tree.selection():
            tree.selection_set(row_id)
        menu.post(event.x_root, event.y_root)
    tree.bind("<Button-3>", show_menu)

# ------------------------------ 设置存储 ------------------------------
SETTINGS_FILE = "settings.json"
def load_settings():
    default = {
        "offline_delete_skill": False,
        "online_delete_skill": True
    }
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for k, v in default.items():
                    if k not in data:
                        data[k] = v
                return data
        except:
            return default
    return default

def save_settings(settings):
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)

# ------------------------------ 持久化管理 ------------------------------
MANAGED_SKILLS_FILE = "managed_skills.json"

def save_managed_skills(skills):
    try:
        with open(MANAGED_SKILLS_FILE, 'w', encoding='utf-8') as f:
            json.dump(skills, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log_message(f"保存 Skill 列表失败: {e}")

def load_managed_skills():
    if os.path.exists(MANAGED_SKILLS_FILE):
        try:
            with open(MANAGED_SKILLS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            log_message(f"加载 Skill 列表失败: {e}")
    return []

# ------------------------------ GUI 主程序 ------------------------------
class MalSkillDetector(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("Skill 安全与管理工具 V1.0")
        self.geometry("1100x800")
        self.configure(bg="#f0f0f0")
        self.scan_list = []            # 离线扫描列表
        self.online_targets = []       # 在线扫描URL列表
        self.proxy_config = load_proxy_config()
        self.settings = load_settings()
        self.scan_mode = "scene"       # 默认恶意高危模式
        self.current_view = "manage"   # 默认显示管理视图
        self.managed_skills = load_managed_skills()
        self.batch_result_window = None
        self.batch_notebook = None
        self.batch_tabs = {}
        self.batch_progress_queue = queue.Queue()
        self.batch_scan_dirs = []
        self.create_widgets()
        self.setup_drag_drop()
        # 为 Skill 管理视图单独绑定拖放 SKILL.md 文件
        self.manage_frame.drop_target_register(DND_FILES)
        self.manage_frame.dnd_bind('<<Drop>>', self.on_skill_md_drop)
        self.after(100, self._process_batch_queue)
        # 提示规则文件
        if not os.path.exists("total_rules.py"):
            messagebox.showwarning("规则文件提醒", "未找到 total_rules.py，全高危操作扫描模式将无法使用。\n请将默认规则文件放入程序目录。")
        if not os.path.exists("Precise_rules.py"):
            messagebox.showwarning("规则文件提醒", "未找到 Precise_rules.py，恶意高危操作扫描模式将无法使用。\n请将场景规则文件放入程序目录。")
        self._load_mode_rules()
        self._load_skills_to_tree()

    def _load_mode_rules(self):
        if self.scan_mode == "default":
            rule_file = "total_rules.py"
            mode_name = "全高危操作扫描模式"
        else:
            rule_file = "Precise_rules.py"
            mode_name = "恶意高危操作扫描模式"
        rules = load_rules_from_file(rule_file)
        if rules is not None:
            global MALICIOUS_PATTERNS
            MALICIOUS_PATTERNS.clear()
            MALICIOUS_PATTERNS.update(rules)
            log_message(f"已切换到{mode_name}，规则数量：{len(MALICIOUS_PATTERNS)}")
        else:
            log_message(f"加载规则失败: {rule_file}")

    def _load_skills_to_tree(self):
        for item in self.skill_tree.get_children():
            self.skill_tree.delete(item)
        for idx, skill in enumerate(self.managed_skills, start=1):
            self.skill_tree.insert("", END, values=(
                idx,
                skill["name"],
                skill["desc"],
                skill["path"],
                skill["agent"],
                skill["file_count"]
            ))
        self.skill_status_var.set(f"已加载 {len(self.managed_skills)} 个 Skill")

    def _save_skills(self):
        save_managed_skills(self.managed_skills)

    # ------------------------------ 视图切换 ------------------------------
    def toggle_view(self):
        if self.current_view == "manage":
            self.manage_frame.pack_forget()
            self.detect_frame.pack(fill=BOTH, expand=True)
            self.detect_toolbar_buttons.pack(side=LEFT, fill=X, expand=True)
            self.manage_toolbar_buttons.pack_forget()
            self.current_view = "detect"
            self.view_btn.config(text="🔙 切换至Skill管理")
        else:
            self.detect_frame.pack_forget()
            self.manage_frame.pack(fill=BOTH, expand=True)
            self.manage_toolbar_buttons.pack(side=LEFT, fill=X, expand=True)
            self.detect_toolbar_buttons.pack_forget()
            self.current_view = "manage"
            self.view_btn.config(text="🔄 切换至安全检测")

    # ------------------------------ 创建界面 ------------------------------
    def create_widgets(self):
        toolbar = Frame(self, bg="#e0e0e0", height=40)
        toolbar.pack(side=TOP, fill=X, padx=5, pady=5)

        self.detect_toolbar_buttons = Frame(toolbar, bg="#e0e0e0")
        mode_frame = Frame(self.detect_toolbar_buttons, bg="#e0e0e0")
        mode_frame.pack(side=LEFT, padx=2)
        self.btn_default = Button(mode_frame, text="🔴 全高危扫描", command=self.set_mode_default, bg="#f0f0f0")
        self.btn_default.pack(side=LEFT, padx=2)
        self.btn_scene = Button(mode_frame, text="🟢 恶意高危扫描（精确）", command=self.set_mode_scene, bg="#4CAF50", fg="white")
        self.btn_scene.pack(side=LEFT, padx=2)

        btn_add = Button(self.detect_toolbar_buttons, text="➕ 添加文件", command=self.add_files)
        btn_add.pack(side=LEFT, padx=2)
        btn_add_dir = Button(self.detect_toolbar_buttons, text="📁 添加目录", command=self.add_directory)
        btn_add_dir.pack(side=LEFT, padx=2)
        btn_clear = Button(self.detect_toolbar_buttons, text="🗑️ 清空列表", command=self.clear_list)
        btn_clear.pack(side=LEFT, padx=2)
        btn_scan = Button(self.detect_toolbar_buttons, text="🔍 离线扫描", bg="#4CAF50", fg="white", command=self.start_offline_scan)
        btn_scan.pack(side=LEFT, padx=2)
        btn_export = Button(self.detect_toolbar_buttons, text="📄 导出报告", command=self.export_report)
        btn_export.pack(side=LEFT, padx=2)
        btn_proxy = Button(self.detect_toolbar_buttons, text="⚙️ 代理设置", bg="#FF9800", fg="white", command=self.open_proxy_settings)
        btn_proxy.pack(side=LEFT, padx=2)
        btn_settings = Button(self.detect_toolbar_buttons, text="⚙️ 设置", bg="#607D8B", fg="white", command=self.open_settings_window)
        btn_settings.pack(side=LEFT, padx=2)

        self.manage_toolbar_buttons = Frame(toolbar, bg="#e0e0e0")
        Label(self.manage_toolbar_buttons, text="Skill 管理模式", bg="#e0e0e0", font=("微软雅黑", 9)).pack(side=LEFT, padx=10)

        btn_debug = Button(toolbar, text="📋 调试日志", bg="#9C27B0", fg="white", command=self.open_debug_logs)
        btn_debug.pack(side=RIGHT, padx=2)
        self.view_btn = Button(toolbar, text="🔄 切换至安全检测", command=self.toggle_view, bg="#2196F3", fg="white")
        self.view_btn.pack(side=RIGHT, padx=10)

        self.detect_toolbar_buttons.pack_forget()
        self.manage_toolbar_buttons.pack(side=LEFT, fill=X, expand=True)

        # ---------- 安全检测视图 ----------
        self.detect_frame = Frame(self, bg="#f0f0f0")
        online_frame = LabelFrame(self.detect_frame, text="在线检测 Skill (支持 GitHub / skills.sh / SkillStore / skill-cn / ClawHub，每行一个URL)", bg="#fafafa", padx=10, pady=10)
        online_frame.pack(side=TOP, fill=X, padx=10, pady=5)
        self.url_text = ScrolledText(online_frame, height=5, width=80, font=("Consolas", 9))
        self.url_text.pack(side=TOP, fill=X, padx=5, pady=5)
        btn_frame = Frame(online_frame, bg="#fafafa")
        btn_frame.pack(side=TOP, fill=X, pady=5)
        self.online_btn = Button(btn_frame, text="🌐 在线检测 (批量)", bg="#2196F3", fg="white", command=self.start_online_scan)
        self.online_btn.pack(side=LEFT, padx=5)
        self.import_btn = Button(btn_frame, text="📂 从文件导入URL列表", command=self.import_urls_from_file)
        self.import_btn.pack(side=LEFT, padx=5)
        self.clear_urls_btn = Button(btn_frame, text="🗑️ 清空URL列表", command=self.clear_urls)
        self.clear_urls_btn.pack(side=LEFT, padx=5)
        self.proxy_status_label = Label(online_frame, text="", fg="blue", bg="#fafafa", font=("微软雅黑", 9))
        self.proxy_status_label.pack(side=LEFT, padx=10)
        self.update_proxy_status_display()
        drop_frame = LabelFrame(self.detect_frame, text="拖放区域", bg="#fafafa", padx=10, pady=10)
        drop_frame.pack(side=TOP, fill=X, padx=10, pady=5)
        drop_label = Label(drop_frame, text="📂 拖放文件、文件夹或 ZIP 压缩包至此\n支持多文件和递归扫描", bg="#fafafa", fg="#555", font=("微软雅黑", 10))
        drop_label.pack()
        list_frame = Frame(self.detect_frame)
        list_frame.pack(side=TOP, fill=BOTH, expand=True, padx=10, pady=5)
        scrollbar = Scrollbar(list_frame)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.listbox = Listbox(list_frame, yscrollcommand=scrollbar.set, font=("Consolas", 9), selectmode=EXTENDED, bg="white", fg="black")
        self.listbox.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.config(command=self.listbox.yview)
        self.listbox_menu = Menu(self.listbox, tearoff=0)
        self.listbox_menu.add_command(label="移除选中的检测目标", command=self._remove_selected_from_scan_list)
        self.listbox.bind("<Button-3>", self._show_listbox_menu)

        self.status_var = StringVar()
        self.status_var.set("就绪 | 共 0 个项目")
        status_bar = Label(self.detect_frame, textvariable=self.status_var, bd=1, relief=SUNKEN, anchor=W, bg="#e0e0e0")
        status_bar.pack(side=BOTTOM, fill=X)

        # ---------- Skill 管理视图 ----------
        self.manage_frame = Frame(self, bg="#f0f0f0")
        top_frame = LabelFrame(self.manage_frame, text="自定义扫描目录（每行一个根目录）", bg="#fafafa", padx=10, pady=10)
        top_frame.pack(side=TOP, fill=X, padx=10, pady=5)
        self.paths_text = ScrolledText(top_frame, height=6, width=100, font=("Consolas", 9))
        self.paths_text.pack(side=TOP, fill=X, pady=5)
        btn_frame = Frame(top_frame, bg="#fafafa")
        btn_frame.pack(side=TOP, fill=X, pady=5)
        Button(btn_frame, text="📂 浏览并添加目录", command=self.browse_add_path, bg="#4CAF50", fg="white").pack(side=LEFT, padx=2)
        Button(btn_frame, text="🔍 检索Skill", command=self.search_skills_from_paths, bg="#2196F3", fg="white").pack(side=LEFT, padx=2)
        common_btn = Button(btn_frame, text="🤖 检索常见AI工具的加载skill", command=self.search_common_tools, bg="#FF9800", fg="white")
        common_btn.pack(side=LEFT, padx=2)
        help_btn = Button(btn_frame, text="?", command=self._show_common_tool_paths, bg="#AAAAAA", width=2)
        help_btn.pack(side=LEFT, padx=1)
        Button(btn_frame, text="🔍 全盘扫描Skill", command=self.full_scan_skills, bg="#9C27B0", fg="white").pack(side=LEFT, padx=2)

        bottom_frame = LabelFrame(self.manage_frame, text="可视化管理列表（双击打开目录、右键菜单、拖放SKILL.md文件增加管理条目）", bg="#fafafa", padx=10, pady=10)
        bottom_frame.pack(side=TOP, fill=BOTH, expand=True, padx=10, pady=5)
        columns = ("ID", "名称", "描述", "路径", "Agent类型", "文件数")
        self.skill_tree = ttk.Treeview(bottom_frame, columns=columns, show="headings", selectmode="extended")
        self.skill_tree.heading("ID", text="ID")
        self.skill_tree.heading("名称", text="Skill名称")
        self.skill_tree.heading("描述", text="描述")
        self.skill_tree.heading("路径", text="路径")
        self.skill_tree.heading("Agent类型", text="Agent类型")
        self.skill_tree.heading("文件数", text="文件数")
        self.skill_tree.column("ID", width=50)
        self.skill_tree.column("名称", width=180)
        self.skill_tree.column("描述", width=320)
        self.skill_tree.column("路径", width=280)
        self.skill_tree.column("Agent类型", width=120)
        self.skill_tree.column("文件数", width=80)
        scrollbar_skill = Scrollbar(bottom_frame, orient=VERTICAL, command=self.skill_tree.yview)
        self.skill_tree.configure(yscrollcommand=scrollbar_skill.set)
        scrollbar_skill.pack(side=RIGHT, fill=Y)
        self.skill_tree.pack(side=LEFT, fill=BOTH, expand=True)

        self.skill_menu = Menu(self.skill_tree, tearoff=0)
        self.skill_menu.add_command(label="打开文件夹（多选）", command=self._open_selected_folders)
        self.skill_menu.add_command(label="从列表中移除（仅移除列表）", command=self._remove_selected_from_list)
        self.skill_menu.add_command(label="永久删除Skill目录（多选）", command=self._delete_selected_skills_permanently)
        self.skill_menu.add_command(label="发送到安全检测", command=self._send_to_security_scan)
        self.skill_menu.add_command(label="从 SKILL.md 文件添加", command=self._add_skill_by_file_dialog)
        self.skill_tree.bind("<Button-3>", self._show_skill_menu)
        self.skill_tree.bind("<Double-1>", lambda e: self._open_selected_folders())
        self.skill_tree.bind("<Control-a>", lambda e: self._select_all_skills())
        self.skill_tree.bind("<Control-A>", lambda e: self._select_all_skills())

        self.skill_status_var = StringVar()
        self.skill_status_var.set("就绪")
        skill_status_bar = Label(self.manage_frame, textvariable=self.skill_status_var, bd=1, relief=SUNKEN, anchor=W, bg="#e0e0e0")
        skill_status_bar.pack(side=BOTTOM, fill=X)

        self.detect_frame.pack_forget()
        self.manage_frame.pack(fill=BOTH, expand=True)

    # ------------------------------ 拖放 SKILL.md 处理 ------------------------------
    def on_skill_md_drop(self, event):
        raw = event.data
        paths = []
        import re
        pattern = r'\{([^}]+)\}|([^\s]+)'
        matches = re.findall(pattern, raw)
        for match in matches:
            token = match[0] if match[0] else match[1]
            token = token.strip()
            if token:
                paths.append(token)
        if not paths:
            for token in raw.split():
                token = token.strip('{}')
                if token:
                    paths.append(token)
        if not paths:
            path_candidates = re.findall(r'[a-zA-Z]:\\[^\\\s]+(?:\\[^\\\s]+)*|/[^/\s]+(?:/[^/\s]+)*', raw)
            if path_candidates:
                paths = path_candidates
        for path in paths:
            path = os.path.normpath(path)
            if os.path.isfile(path) and os.path.basename(path).lower() == "skill.md":
                self._add_skill_from_md_file(path)
                break

    def _add_skill_from_md_file(self, md_file_path):
        dir_path = os.path.dirname(md_file_path)
        if not os.path.isdir(dir_path):
            messagebox.showerror("错误", f"无效的目录：{dir_path}")
            return
        if any(s["path"] == dir_path for s in self.managed_skills):
            messagebox.showinfo("提示", f"Skill 已存在于管理列表中：{dir_path}")
            return
        name = os.path.basename(dir_path)
        desc = self._parse_skill_description(md_file_path)
        file_count = self._count_files(dir_path)
        parent = os.path.dirname(dir_path)
        agent = self._detect_agent_type(parent) if parent else "通用"
        self.managed_skills.append({
            "name": name,
            "desc": desc,
            "path": dir_path,
            "agent": agent,
            "file_count": file_count
        })
        self._save_skills()
        self._load_skills_to_tree()
        self.skill_status_var.set(f"已添加 Skill：{name}")

    def _add_skill_by_file_dialog(self):
        file_path = filedialog.askopenfilename(
            title="选择 SKILL.md 文件",
            filetypes=[("Markdown 文件", "SKILL.md"), ("所有文件", "*.*")]
        )
        if file_path:
            self._add_skill_from_md_file(file_path)

    # ------------------------------ 常见工具路径显示 ------------------------------
    def _show_common_tool_paths(self):
        home = os.path.expanduser("~")
        tool_paths = {
            "Claude Code": os.path.join(home, ".claude", "skills"),
            "Codex": os.path.join(home, ".codex", "skills"),
            "Cursor": os.path.join(home, ".cursor", "skills"),
            "Windsurf": os.path.join(home, ".windsurf", "skills"),
            "GitHub Copilot": os.path.join(home, ".copilot", "skills"),
            "Continue": os.path.join(home, ".continue", "skills"),
            "Gemini CLI": os.path.join(home, ".gemini", "skills"),
            "Cline": os.path.join(home, ".cline", "skills"),
            "Kiro": os.path.join(home, ".kiro", "skills"),
            "Qoder": os.path.join(home, ".qoder", "skills"),
            "Roo Code": os.path.join(home, ".roo", "skills"),
            "Aider": os.path.join(home, ".aider", "skills"),
            "Hermes Agent": os.path.join(home, ".hermes", "skills"),
            "CodeBuddy": os.path.join(home, ".codebuddy", "skills"),
            "Tabby": os.path.join(home, ".tabby", "skills"),
            "OpenHands": os.path.join(home, ".openhands", "skills"),
            "Antigravity": os.path.join(home, ".gemini", "antigravity", "skills"),
            "Lingma": os.path.join(home, ".lingma", "skills"),
            "Qodo": os.path.join(home, ".qodo", "skills"),
        }
        existing = []
        not_exist = []
        for name, path in tool_paths.items():
            if os.path.exists(path):
                existing.append(f"✅ {name}: {path}")
            else:
                not_exist.append(f"❌ {name}: {path}")
        msg = "【实际会扫描的路径】\n\n" + "\n".join(existing) if existing else "无存在的路径\n"
        if not_exist:
            msg += "\n\n【不存在的路径】\n" + "\n".join(not_exist)
        messagebox.showinfo("常见AI工具的Skill扫描路径", msg)

    # ------------------------------ 安全检测列表右键菜单 ------------------------------
    def _show_listbox_menu(self, event):
        index = self.listbox.nearest(event.y)
        if index != -1:
            if not self.listbox.selection_includes(index):
                self.listbox.selection_set(index)
        self.listbox_menu.post(event.x_root, event.y_root)

    def _remove_selected_from_scan_list(self):
        selected = self.listbox.curselection()
        if not selected:
            messagebox.showinfo("提示", "未选中任何目标")
            return
        removed = 0
        for idx in reversed(selected):
            if idx < len(self.scan_list):
                self.scan_list.pop(idx)
                removed += 1
        self.update_listbox()
        self.status_var.set(f"已移除 {removed} 个项目")

    # ------------------------------ 自定义目录管理 ------------------------------
    def browse_add_path(self):
        path = filedialog.askdirectory(title="选择Skill存放根目录")
        if path:
            current = self.paths_text.get(1.0, END).strip().splitlines()
            if path not in current:
                if current:
                    self.paths_text.insert(END, path + "\n")
                else:
                    self.paths_text.insert(1.0, path + "\n")

    def get_paths_from_text(self):
        content = self.paths_text.get(1.0, END).strip()
        if not content:
            return []
        return [line.strip() for line in content.splitlines() if line.strip()]

    # ------------------------------ 检索结果窗口（带最大化） ------------------------------
    def _show_scan_result_window(self, skills, title):
        win = Toplevel(self)
        win.title(title)
        win.geometry("1000x600")
        win.transient(self)
        win.grab_set()
        top_frame = Frame(win)
        top_frame.pack(side=TOP, fill=X, padx=5, pady=5)

        btn_frame_left = Frame(top_frame)
        btn_frame_left.pack(side=LEFT, fill=X, expand=True)
        btn_frame_right = Frame(top_frame)
        btn_frame_right.pack(side=RIGHT)

        def select_all():
            tree.selection_set(tree.get_children())
        btn_select_all = Button(btn_frame_left, text="✅ 全选", command=select_all, bg="#2196F3", fg="white")
        btn_select_all.pack(side=LEFT, padx=2)

        def select_all_and_add():
            tree.selection_set(tree.get_children())
            self._add_selected_from_window(win, tree)
        btn_select_all_add = Button(btn_frame_left, text="➕ 全选并添加", command=select_all_and_add, bg="#4CAF50", fg="white")
        btn_select_all_add.pack(side=LEFT, padx=2)

        btn_add = Button(btn_frame_left, text="➕ 添加到可视化管理", command=lambda: self._add_selected_from_window(win, tree), bg="#FF9800", fg="white")
        btn_add.pack(side=LEFT, padx=2)

        def maximize_window():
            screen_width = win.winfo_screenwidth()
            screen_height = win.winfo_screenheight()
            win.geometry(f"{screen_width}x{screen_height}+0+0")
        btn_max = Button(btn_frame_right, text="🖥️ 最大化", command=maximize_window, bg="#9C27B0", fg="white")
        btn_max.pack(side=RIGHT, padx=5)

        frame = Frame(win)
        frame.pack(side=TOP, fill=BOTH, expand=True, padx=5, pady=5)
        columns = ("ID", "名称", "描述", "路径", "Agent类型", "文件数")
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
        tree.heading("ID", text="ID")
        tree.heading("名称", text="Skill名称")
        tree.heading("描述", text="描述")
        tree.heading("路径", text="路径")
        tree.heading("Agent类型", text="Agent类型")
        tree.heading("文件数", text="文件数")
        tree.column("ID", width=50)
        tree.column("名称", width=180)
        tree.column("描述", width=320)
        tree.column("路径", width=280)
        tree.column("Agent类型", width=120)
        tree.column("文件数", width=80)
        scrollbar = Scrollbar(frame, orient=VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=RIGHT, fill=Y)
        tree.pack(side=LEFT, fill=BOTH, expand=True)
        for idx, skill in enumerate(skills, start=1):
            tree.insert("", END, values=(
                idx,
                skill["name"],
                skill["desc"],
                skill["path"],
                skill["agent"],
                skill["file_count"]
            ))
        def on_double_click(event):
            selected = tree.selection()
            if not selected:
                return
            item = selected[0]
            values = tree.item(item, "values")
            if values:
                path = values[3]
                if platform.system() == "Windows":
                    os.startfile(path)
                elif platform.system() == "Darwin":
                    subprocess.run(["open", path])
                else:
                    subprocess.run(["xdg-open", path])
        tree.bind("<Double-1>", on_double_click)
        def select_all_tree(event):
            tree.selection_set(tree.get_children())
            return "break"
        tree.bind("<Control-a>", select_all_tree)
        tree.bind("<Control-A>", select_all_tree)
        win.current_tree = tree

    def _add_selected_from_window(self, win, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选中要添加的Skill")
            return
        skills_to_add = []
        for item in selected:
            values = tree.item(item, "values")
            if values and len(values) >= 6:
                skills_to_add.append({
                    "name": values[1],
                    "desc": values[2],
                    "path": values[3],
                    "agent": values[4],
                    "file_count": values[5]
                })
        if not skills_to_add:
            messagebox.showwarning("错误", "无法读取选中的Skill数据，请重试。")
            return
        self._add_skills_to_management(skills_to_add)

    def _add_skills_to_management(self, skills):
        added = 0
        for skill in skills:
            if not any(s["path"] == skill["path"] for s in self.managed_skills):
                self.managed_skills.append(skill)
                added += 1
        if added > 0:
            self._save_skills()
            self._load_skills_to_tree()
            self.skill_status_var.set(f"已添加 {added} 个Skill到可视化管理列表")
        else:
            messagebox.showinfo("提示", "所有选中的Skill都已存在，无需重复添加。")

    # ------------------------------ 检索功能 ------------------------------
    def search_skills_from_paths(self):
        paths = self.get_paths_from_text()
        if not paths:
            messagebox.showinfo("提示", "请在左侧输入至少一个目录路径")
            return
        self.skill_status_var.set("正在递归检索...")
        self.update_idletasks()
        def scan_thread():
            skills = []
            error_count = 0
            for base_path in paths:
                if not os.path.exists(base_path):
                    continue
                for root, dirs, files in os.walk(base_path, followlinks=False):
                    try:
                        if "SKILL.md" in files:
                            name = os.path.basename(root)
                            desc = self._parse_skill_description(os.path.join(root, "SKILL.md"))
                            file_count = self._count_files(root)
                            agent = self._detect_agent_type(base_path)
                            skills.append({"name": name, "desc": desc, "path": root, "agent": agent, "file_count": file_count})
                    except PermissionError:
                        error_count += 1
                    except Exception as e:
                        log_message(f"扫描 {root} 出错: {e}")
            self.after(0, lambda: self._show_scan_result_window(skills, f"检索结果 (权限错误 {error_count} 次)"))
            self.after(0, lambda: self.skill_status_var.set("检索完成"))
        threading.Thread(target=scan_thread, daemon=True).start()

    def search_common_tools(self):
        home = os.path.expanduser("~")
        tool_paths = {
            "Claude Code": os.path.join(home, ".claude", "skills"),
            "Codex": os.path.join(home, ".codex", "skills"),
            "Cursor": os.path.join(home, ".cursor", "skills"),
            "Windsurf": os.path.join(home, ".windsurf", "skills"),
            "GitHub Copilot": os.path.join(home, ".copilot", "skills"),
            "Continue": os.path.join(home, ".continue", "skills"),
            "Gemini CLI": os.path.join(home, ".gemini", "skills"),
            "Cline": os.path.join(home, ".cline", "skills"),
            "Kiro": os.path.join(home, ".kiro", "skills"),
            "Qoder": os.path.join(home, ".qoder", "skills"),
            "Roo Code": os.path.join(home, ".roo", "skills"),
            "Aider": os.path.join(home, ".aider", "skills"),
            "Hermes Agent": os.path.join(home, ".hermes", "skills"),
            "CodeBuddy": os.path.join(home, ".codebuddy", "skills"),
            "Tabby": os.path.join(home, ".tabby", "skills"),
            "OpenHands": os.path.join(home, ".openhands", "skills"),
            "Antigravity": os.path.join(home, ".gemini", "antigravity", "skills"),
            "Lingma": os.path.join(home, ".lingma", "skills"),
            "Qodo": os.path.join(home, ".qodo", "skills"),
        }
        existing_paths = [path for path in tool_paths.values() if os.path.exists(path)]
        if not existing_paths:
            messagebox.showinfo("提示", "未找到任何常见AI工具的Skill目录")
            return
        self.skill_status_var.set("正在检索常见AI工具...")
        self.update_idletasks()
        def scan_thread():
            skills = []
            for base_path in existing_paths:
                for root, dirs, files in os.walk(base_path, followlinks=False):
                    try:
                        if "SKILL.md" in files:
                            name = os.path.basename(root)
                            desc = self._parse_skill_description(os.path.join(root, "SKILL.md"))
                            file_count = self._count_files(root)
                            agent = self._detect_agent_type(base_path)
                            skills.append({"name": name, "desc": desc, "path": root, "agent": agent, "file_count": file_count})
                    except PermissionError:
                        continue
            self.after(0, lambda: self._show_scan_result_window(skills, "常见AI工具检索结果"))
            self.after(0, lambda: self.skill_status_var.set("检索完成"))
        threading.Thread(target=scan_thread, daemon=True).start()

    # ------------------------------ 全盘扫描（无管理员检查） ------------------------------
    def full_scan_skills(self):
        self._start_full_scan()

    def _start_full_scan(self):
        self.scan_progress_win = Toplevel(self)
        self.scan_progress_win.title("全盘扫描 Skill")
        self.scan_progress_win.geometry("500x150")
        self.scan_progress_win.transient(self)
        self.scan_progress_win.grab_set()
        Label(self.scan_progress_win, text="正在扫描全盘，请稍候...", font=("微软雅黑", 10)).pack(pady=10)
        self.progress_bar = ttk.Progressbar(self.scan_progress_win, mode='indeterminate')
        self.progress_bar.pack(pady=10, padx=20, fill=X)
        self.progress_bar.start()
        self.scan_status_label = Label(self.scan_progress_win, text="初始化...", fg="blue")
        self.scan_status_label.pack(pady=5)
        threading.Thread(target=self._full_scan_thread, daemon=True).start()

    def _full_scan_thread(self):
        found_skills = []
        if platform.system() == "Windows":
            import string
            drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            roots = drives
        elif platform.system() == "Darwin":
            roots = ["/Users", "/Applications", "/System/Volumes/Data"]
        else:
            roots = ["/home", "/usr", "/opt", "/var"]
        total_dirs = 0
        for root in roots:
            self._update_scan_status(f"正在扫描 {root} ...")
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                try:
                    if "SKILL.md" in filenames:
                        name = os.path.basename(dirpath)
                        desc = self._parse_skill_description(os.path.join(dirpath, "SKILL.md"))
                        file_count = self._count_files(dirpath)
                        agent = self._detect_agent_type(root)
                        found_skills.append({"name": name, "desc": desc, "path": dirpath, "agent": agent, "file_count": file_count})
                        self._update_scan_status(f"发现 Skill: {dirpath}")
                    total_dirs += 1
                    if total_dirs % 1000 == 0:
                        self._update_scan_status(f"已扫描 {total_dirs} 个目录，已发现 {len(found_skills)} 个 Skill")
                except PermissionError:
                    continue
        self.scan_progress_win.after(0, lambda: self._full_scan_complete(found_skills))

    def _update_scan_status(self, msg):
        def update():
            self.scan_status_label.config(text=msg)
            self.scan_progress_win.update()
        self.scan_progress_win.after(0, update)

    def _full_scan_complete(self, found_skills):
        self.progress_bar.stop()
        self.scan_progress_win.destroy()
        if not found_skills:
            messagebox.showinfo("扫描结果", "未在系统中找到任何 Skill 文件。")
            return
        self._show_scan_result_window(found_skills, "全盘扫描结果")

    # ------------------------------ 描述提取增强 ------------------------------
    def _parse_skill_description(self, skill_md_path):
        try:
            with open(skill_md_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            log_message(f"读取描述失败 {skill_md_path}: {e}")
            return "无法读取"

        front_matter_lines = []
        in_front_matter = False
        for line in lines:
            if line.strip() == '---':
                if not in_front_matter:
                    in_front_matter = True
                    continue
                else:
                    break
            if in_front_matter:
                front_matter_lines.append(line)
        
        search_lines = front_matter_lines if front_matter_lines else lines[:200]
        desc_start_idx = -1
        for i, line in enumerate(search_lines):
            if line.lower().lstrip().startswith('description:'):
                desc_start_idx = i
                break
        
        if desc_start_idx == -1:
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and not line.lower().startswith('name:'):
                    if len(line) > 120:
                        return line[:117] + "..."
                    return line
            return "无描述"
        
        first_line = search_lines[desc_start_idx]
        after_colon = first_line.split(':', 1)[1].lstrip()
        desc_parts = []
        if after_colon and not after_colon.startswith(('|', '>', '\n')):
            desc_parts.append(after_colon.strip().strip('"\''))

        j = desc_start_idx + 1
        while j < len(search_lines):
            line = search_lines[j]
            if line.startswith((' ', '\t')) or line.strip() == '':
                stripped = line.strip()
                if stripped:
                    desc_parts.append(stripped)
                j += 1
            else:
                break
        
        if not desc_parts and after_colon.strip() in ('|', '>', ''):
            if len(search_lines) < 300 and not front_matter_lines:
                more_lines = lines[:300]
                k = desc_start_idx + 1
                while k < len(more_lines):
                    line = more_lines[k]
                    if line.startswith((' ', '\t')) or line.strip() == '':
                        stripped = line.strip()
                        if stripped:
                            desc_parts.append(stripped)
                        k += 1
                    else:
                        break
        
        if desc_parts:
            desc = ' '.join(desc_parts).strip()
            desc = re.sub(r'\s*#.*$', '', desc, flags=re.MULTILINE)
            if len(desc) > 120:
                desc = desc[:117] + "..."
            return desc
        
        if after_colon:
            desc = after_colon.strip().strip('"\'')
            if len(desc) > 120:
                desc = desc[:117] + "..."
            return desc
        return "无描述"

    def _count_files(self, dir_path):
        count = 0
        for root, dirs, files in os.walk(dir_path):
            count += len(files)
        return count

    def _detect_agent_type(self, base_path):
        base_lower = base_path.lower()
        if ".claude" in base_lower:
            return "Claude Code"
        elif ".codex" in base_lower:
            return "Codex"
        elif ".cursor" in base_lower:
            return "Cursor"
        elif ".windsurf" in base_lower:
            return "Windsurf"
        elif ".copilot" in base_lower:
            return "GitHub Copilot"
        elif ".continue" in base_lower:
            return "Continue"
        elif ".gemini" in base_lower:
            return "Gemini CLI"
        elif ".cline" in base_lower:
            return "Cline"
        elif ".kiro" in base_lower:
            return "Kiro"
        elif ".qoder" in base_lower:
            return "Qoder"
        elif ".roo" in base_lower:
            return "Roo Code"
        elif ".aider" in base_lower:
            return "Aider"
        elif ".hermes" in base_lower:
            return "Hermes Agent"
        elif ".codebuddy" in base_lower:
            return "CodeBuddy"
        elif ".tabby" in base_lower:
            return "Tabby"
        elif ".openhands" in base_lower:
            return "OpenHands"
        elif ".lingma" in base_lower:
            return "Lingma"
        elif ".qodo" in base_lower:
            return "Qodo"
        else:
            return "通用"

    # ------------------------------ 可视化管理列表操作 ------------------------------
    def _remove_selected_from_list(self):
        selected = self.skill_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "未选中任何Skill")
            return
        if not messagebox.askyesno("确认移除", f"确定要将 {len(selected)} 个选中的Skill从管理列表中移除吗？\n此操作不会删除实际文件。"):
            return
        paths_to_remove = []
        for item in selected:
            values = self.skill_tree.item(item, "values")
            if values:
                paths_to_remove.append(values[3])
        self.managed_skills = [s for s in self.managed_skills if s["path"] not in paths_to_remove]
        self._save_skills()
        self._load_skills_to_tree()
        self.skill_status_var.set(f"已从列表中移除 {len(selected)} 个Skill")

    def _open_selected_folders(self):
        selected = self.skill_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "未选中任何Skill")
            return
        for item in selected:
            values = self.skill_tree.item(item, "values")
            if values:
                path = values[3]
                if platform.system() == "Windows":
                    os.startfile(path)
                elif platform.system() == "Darwin":
                    subprocess.run(["open", path])
                else:
                    subprocess.run(["xdg-open", path])

    def _delete_selected_skills_permanently(self):
        selected = self.skill_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "未选中任何Skill")
            return
        paths_to_delete = []
        for item in selected:
            values = self.skill_tree.item(item, "values")
            if values:
                paths_to_delete.append(values[3])
        if not paths_to_delete:
            return
        if not messagebox.askyesno("确认永久删除", f"确定要永久删除 {len(paths_to_delete)} 个Skill目录及其所有文件吗？\n此操作不可撤销！"):
            return
        deleted_count = 0
        for path in paths_to_delete:
            try:
                if os.path.exists(path):
                    shutil.rmtree(path)
                    deleted_count += 1
                else:
                    log_message(f"目录不存在，跳过删除: {path}")
            except Exception as e:
                messagebox.showerror("删除失败", f"删除 {path} 时出错：{str(e)}")
        if deleted_count > 0:
            self.managed_skills = [s for s in self.managed_skills if s["path"] not in paths_to_delete]
            self._save_skills()
            self._load_skills_to_tree()
            self.skill_status_var.set(f"已永久删除 {deleted_count} 个Skill目录")
        else:
            messagebox.showinfo("提示", "未成功删除任何目录")

    def _send_to_security_scan(self):
        selected = self.skill_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "未选中任何Skill")
            return
        added_count = 0
        for item in selected:
            values = self.skill_tree.item(item, "values")
            if values:
                path = values[3]
                if not any(p == path for (typ, p) in self.scan_list):
                    self.scan_list.append(('dir', path))
                    added_count += 1
        if added_count > 0:
            self.update_listbox()
            self.skill_status_var.set(f"已将 {added_count} 个Skill目录添加到安全检测离线扫描列表")
            if messagebox.askyesno("添加成功", f"已将 {added_count} 个Skill目录添加到离线扫描列表。\n是否立即切换到安全检测视图进行扫描？"):
                self.toggle_view()
        else:
            messagebox.showinfo("提示", "选中的Skill目录已存在于扫描列表中")

    def _show_skill_menu(self, event):
        row_id = self.skill_tree.identify_row(event.y)
        if row_id:
            if row_id not in self.skill_tree.selection():
                self.skill_tree.selection_add(row_id)
            self.skill_menu.post(event.x_root, event.y_root)

    def _select_all_skills(self):
        self.skill_tree.selection_set(self.skill_tree.get_children())

    # ------------------------------ 安全检测模式切换 ------------------------------
    def set_mode_default(self):
        self.scan_mode = "default"
        self._load_mode_rules()
        self.update_mode_buttons()

    def set_mode_scene(self):
        self.scan_mode = "scene"
        self._load_mode_rules()
        self.update_mode_buttons()

    def update_mode_buttons(self):
        if self.scan_mode == "default":
            self.btn_default.config(bg="#FF5722", fg="white")
            self.btn_scene.config(bg="#f0f0f0", fg="black")
        else:
            self.btn_default.config(bg="#f0f0f0", fg="black")
            self.btn_scene.config(bg="#4CAF50", fg="white")

    def update_proxy_status_display(self):
        if self.proxy_config:
            proxy_type = self.proxy_config.get("type", "http")
            server = self.proxy_config.get("server", "")
            port = self.proxy_config.get("port", "")
            self.proxy_status_label.config(text=f"🌐 当前代理: {proxy_type}://{server}:{port}")
        else:
            self.proxy_status_label.config(text="无代理")

    def import_urls_from_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not filepath:
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                urls = f.read().strip().splitlines()
            self.url_text.delete(1.0, END)
            for url in urls:
                url = url.strip()
                if url:
                    self.url_text.insert(END, url + "\n")
            messagebox.showinfo("导入成功", f"已导入 {len([u for u in urls if u.strip()])} 个URL")
        except Exception as e:
            messagebox.showerror("导入失败", f"读取文件时出错：{str(e)}")

    def clear_urls(self):
        self.url_text.delete(1.0, END)

    def get_url_list(self):
        content = self.url_text.get(1.0, END).strip()
        if not content:
            return []
        return [line.strip() for line in content.splitlines() if line.strip()]

    def open_debug_logs(self):
        log_win = Toplevel(self)
        log_win.title("调试日志")
        log_win.geometry("900x500")
        frame = Frame(log_win)
        frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        scrollbar = Scrollbar(frame)
        scrollbar.pack(side=RIGHT, fill=Y)
        text_area = Text(frame, wrap=WORD, yscrollcommand=scrollbar.set, font=("Consolas", 9))
        text_area.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.config(command=text_area.yview)
        for log in get_all_logs():
            text_area.insert(END, log + "\n")
        text_area.see(END)
        btn_frame = Frame(log_win)
        btn_frame.pack(fill=X, padx=5, pady=5)
        def refresh_logs():
            text_area.delete(1.0, END)
            for log in get_all_logs():
                text_area.insert(END, log + "\n")
            text_area.see(END)
        def clear_and_refresh():
            clear_logs()
            refresh_logs()
        Button(btn_frame, text="刷新", command=refresh_logs, width=10).pack(side=LEFT, padx=5)
        Button(btn_frame, text="清空", command=clear_and_refresh, width=10).pack(side=LEFT, padx=5)
        Button(btn_frame, text="关闭", command=log_win.destroy, width=10).pack(side=RIGHT, padx=5)

    # ------------------------------ 代理设置 ------------------------------
    def open_proxy_settings(self):
        win = Toplevel(self)
        win.title("代理设置")
        win.geometry("550x420")
        win.transient(self)
        win.grab_set()
        current = self.proxy_config or {}
        Label(win, text="代理类型:", font=("微软雅黑", 9)).grid(row=0, column=0, sticky="e", padx=10, pady=10)
        type_var = StringVar(value=current.get("type", "http"))
        type_combo = ttk.Combobox(win, textvariable=type_var, values=["http", "https", "socks5"], state="readonly")
        type_combo.grid(row=0, column=1, sticky="w", padx=10, pady=10)
        Label(win, text="服务器地址:", font=("微软雅黑", 9)).grid(row=1, column=0, sticky="e", padx=10, pady=5)
        server_entry = Entry(win, width=30)
        server_entry.insert(0, current.get("server", ""))
        server_entry.grid(row=1, column=1, sticky="w", padx=10, pady=5)
        Label(win, text="端口:", font=("微软雅黑", 9)).grid(row=2, column=0, sticky="e", padx=10, pady=5)
        port_entry = Entry(win, width=10)
        port_entry.insert(0, current.get("port", ""))
        port_entry.grid(row=2, column=1, sticky="w", padx=10, pady=5)
        Label(win, text="用户名 (可选):", font=("微软雅黑", 9)).grid(row=3, column=0, sticky="e", padx=10, pady=5)
        user_entry = Entry(win, width=20)
        user_entry.insert(0, current.get("username", ""))
        user_entry.grid(row=3, column=1, sticky="w", padx=10, pady=5)
        Label(win, text="密码 (可选):", font=("微软雅黑", 9)).grid(row=4, column=0, sticky="e", padx=10, pady=5)
        pass_entry = Entry(win, width=20, show="*")
        pass_entry.insert(0, current.get("password", ""))
        pass_entry.grid(row=4, column=1, sticky="w", padx=10, pady=5)

        test_frame = LabelFrame(win, text="连通性测试", padx=5, pady=5)
        test_frame.grid(row=5, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        test_status_label = Label(test_frame, text="未测试", fg="gray")
        test_status_label.pack(fill=X, padx=5, pady=2)
        def run_connection_test():
            test_config = {
                "type": type_var.get(),
                "server": server_entry.get().strip(),
                "port": port_entry.get().strip(),
                "username": user_entry.get().strip(),
                "password": pass_entry.get().strip()
            }
            if not test_config["server"] or not test_config["port"]:
                test_status_label.config(text="❌ 请填写服务器地址和端口", fg="red")
                return
            if not test_config["port"].isdigit():
                test_status_label.config(text="❌ 端口必须是数字", fg="red")
                return
            test_status_label.config(text="⏳ 测试中，请稍候...", fg="blue")
            win.update()
            def test():
                success, msg, latency = test_proxy_connection(test_config)
                win.after(0, lambda: update_test_result(success, msg, latency))
            def update_test_result(success, msg, latency):
                if success:
                    test_status_label.config(text=f"✅ {msg}", fg="green")
                else:
                    test_status_label.config(text=f"❌ {msg}", fg="red")
            threading.Thread(target=test, daemon=True).start()
        Button(test_frame, text="测试连接", command=run_connection_test, width=12, bg="#4CAF50", fg="white").pack(pady=5)

        btn_frame = Frame(win)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=15)
        def save_proxy():
            proxy_type = type_var.get()
            server = server_entry.get().strip()
            port = port_entry.get().strip()
            if not server or not port:
                messagebox.showerror("错误", "服务器地址和端口不能为空")
                return
            if not port.isdigit():
                messagebox.showerror("错误", "端口必须是数字")
                return
            if proxy_type == "socks5":
                ok, err = check_socks_dependencies()
                if not ok:
                    result = messagebox.askyesno("缺少依赖", f"{err}\n\n是否尝试自动安装？")
                    if result:
                        win.destroy()
                        self.install_socks_dependencies()
                    else:
                        messagebox.showwarning("提示", "未安装 PySocks，SOCKS5 代理可能无法正常工作")
                        return
                    if result:
                        save_proxy_config({"type": proxy_type, "server": server, "port": port,
                                           "username": user_entry.get().strip(),
                                           "password": pass_entry.get().strip()})
                        self.proxy_config = load_proxy_config()
                        self.update_proxy_status_display()
                        messagebox.showinfo("成功", "代理配置已保存")
                        win.destroy()
                        return
                else:
                    save_proxy_config({"type": proxy_type, "server": server, "port": port,
                                       "username": user_entry.get().strip(),
                                       "password": pass_entry.get().strip()})
                    self.proxy_config = load_proxy_config()
                    self.update_proxy_status_display()
                    messagebox.showinfo("成功", "代理配置已保存")
                    win.destroy()
            else:
                save_proxy_config({"type": proxy_type, "server": server, "port": port,
                                   "username": user_entry.get().strip(),
                                   "password": pass_entry.get().strip()})
                self.proxy_config = load_proxy_config()
                self.update_proxy_status_display()
                messagebox.showinfo("成功", "代理配置已保存")
                win.destroy()
        def clear_proxy():
            clear_proxy_config()
            self.proxy_config = None
            self.update_proxy_status_display()
            messagebox.showinfo("成功", "已清空代理配置")
            win.destroy()
        Button(btn_frame, text="保存", command=save_proxy, width=10).pack(side=LEFT, padx=10)
        Button(btn_frame, text="清空代理", command=clear_proxy, width=10).pack(side=LEFT, padx=10)
        Button(btn_frame, text="取消", command=win.destroy, width=10).pack(side=LEFT, padx=10)

    def install_socks_dependencies(self):
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "install", "PySocks"], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                messagebox.showinfo("安装成功", "PySocks 已安装完成\n请重新打开代理设置窗口配置 SOCKS5 代理。")
                return True
            else:
                messagebox.showerror("安装失败", f"自动安装失败\n{result.stderr[:200]}\n请手动执行: pip install PySocks")
                return False
        except Exception as e:
            messagebox.showerror("安装失败", f"自动安装出错: {str(e)}\n请手动执行: pip install PySocks")
            return False

    def open_settings_window(self):
        win = Toplevel(self)
        win.title("设置")
        win.geometry("400x250")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)

        Label(win, text="检测完成后的文件清理策略", font=("微软雅黑", 12)).pack(pady=10)

        offline_var = BooleanVar(value=self.settings.get("offline_delete_skill", False))
        online_var = BooleanVar(value=self.settings.get("online_delete_skill", True))

        frame1 = Frame(win)
        frame1.pack(fill=X, padx=20, pady=5)
        Checkbutton(frame1, text="离线检测完成后删除Skill文件（关闭结果窗口时自动删除解压文件）",
                    variable=offline_var, anchor="w", justify=LEFT).pack(anchor="w")
        Label(frame1, text="注：关闭扫描结果窗口后，Offline_detection 目录下的对应临时文件将被删除", font=("微软雅黑", 8), fg="gray").pack(anchor="w")

        frame2 = Frame(win)
        frame2.pack(fill=X, padx=20, pady=5)
        Checkbutton(frame2, text="在线检测完成后删除Skill文件（关闭结果窗口时自动删除下载和解压文件）",
                    variable=online_var, anchor="w", justify=LEFT).pack(anchor="w")
        Label(frame2, text="注：关闭批量结果窗口后，download 目录下的对应下载文件将被删除", font=("微软雅黑", 8), fg="gray").pack(anchor="w")

        def save():
            self.settings["offline_delete_skill"] = offline_var.get()
            self.settings["online_delete_skill"] = online_var.get()
            save_settings(self.settings)
            win.destroy()
            messagebox.showinfo("设置", "设置已保存")
        Button(win, text="保存", command=save, bg="#4CAF50", fg="white", width=10).pack(pady=15)

    # ------------------------------ 拖放与离线扫描基础 ------------------------------
    def setup_drag_drop(self):
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        raw = event.data
        paths = []
        import re
        pattern = r'\{([^}]+)\}|([^\s]+)'
        matches = re.findall(pattern, raw)
        for match in matches:
            token = match[0] if match[0] else match[1]
            token = token.strip()
            if token:
                paths.append(token)
        if not paths:
            for token in raw.split():
                token = token.strip('{}')
                if token:
                    paths.append(token)
        if not paths:
            path_candidates = re.findall(r'[a-zA-Z]:\\[^\\\s]+(?:\\[^\\\s]+)*|/[^/\s]+(?:/[^/\s]+)*', raw)
            if path_candidates:
                paths = path_candidates
            else:
                messagebox.showinfo("拖放提示", "拖放未能自动识别路径，请使用【添加文件/目录】按钮手动添加。")
                return
        added = 0
        for path in paths:
            path = os.path.normpath(path)
            if os.path.exists(path):
                old_len = len(self.scan_list)
                self.add_path(path)
                new_len = len(self.scan_list)
                added += (new_len - old_len)
        if added > 0:
            self.update_listbox()
            self.status_var.set(f"已添加 {added} 个拖放项目到离线扫描列表")
        else:
            self.status_var.set("拖放未添加任何新项目")

    def add_files(self):
        files = filedialog.askopenfilenames(title="选择文件")
        for f in files:
            self.add_path(f)
        self.update_listbox()

    def add_directory(self):
        dir_path = filedialog.askdirectory(title="选择目录")
        if dir_path:
            self.add_path(dir_path)
        self.update_listbox()

    def add_path(self, path):
        path = os.path.normpath(path)
        if os.path.isfile(path):
            if not any(p == path for (typ, p) in self.scan_list):
                if path.endswith('.zip'):
                    self.scan_list.append(('zip', path))
                else:
                    self.scan_list.append(('file', path))
        elif os.path.isdir(path):
            if not any(p == path for (typ, p) in self.scan_list):
                self.scan_list.append(('dir', path))
        else:
            messagebox.showwarning("无效路径", f"路径不存在: {path}")

    def clear_list(self):
        self.scan_list.clear()
        self.update_listbox()

    def update_listbox(self):
        self.listbox.delete(0, END)
        for typ, path in self.scan_list:
            if typ == 'zip':
                display = f"[ZIP] {path}"
            elif typ == 'dir':
                display = f"[DIR] {path}"
            else:
                display = f"[FILE] {path}"
            self.listbox.insert(END, display)
        self.status_var.set(f"就绪 | 共 {len(self.scan_list)} 个项目")

    # ------------------------------ 离线扫描 ------------------------------
    def start_offline_scan(self):
        if not self.scan_list:
            messagebox.showinfo("提示", "没有待扫描的项目，请先添加文件或目录。")
            return
        self._perform_offline_scan()

    def _perform_offline_scan(self):
        base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Offline_detection")
        os.makedirs(base_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        temp_root = os.path.join(base_dir, f"scan_{timestamp}")
        os.makedirs(temp_root, exist_ok=True)

        result_win = Toplevel(self)
        result_win.title("扫描结果")
        result_win.geometry("1200x700")
        result_win.temp_dir = temp_root

        def on_result_window_close():
            if self.settings.get("offline_delete_skill", False):
                if os.path.exists(temp_root):
                    shutil.rmtree(temp_root, ignore_errors=True)
                    log_message(f"已删除离线扫描目录: {temp_root}")
            else:
                log_message(f"保留离线扫描目录: {temp_root}")
            result_win.destroy()
        result_win.protocol("WM_DELETE_WINDOW", on_result_window_close)

        columns = ("文件", "危险等级", "命中规则", "代码片段", "行号")
        tree = ttk.Treeview(result_win, columns=columns, show="headings", selectmode='extended')
        tree.heading("文件", text="文件路径")
        tree.heading("危险等级", text="危险等级")
        tree.heading("命中规则", text="命中规则")
        tree.heading("代码片段", text="代码片段")
        tree.heading("行号", text="行号")
        tree.column("文件", width=400)
        tree.column("危险等级", width=80)
        tree.column("命中规则", width=280)
        tree.column("代码片段", width=350)
        tree.column("行号", width=60)

        def on_tree_double_click(event):
            selected = tree.selection()
            if not selected:
                return
            item = selected[0]
            values = tree.item(item, "values")
            if len(values) >= 5:
                file_path = values[0]
                line_str = values[4]
                if line_str.isdigit():
                    open_file_at_line(file_path, int(line_str))
                else:
                    messagebox.showerror("错误", f"无效的行号: {line_str}")
        tree.bind("<Double-1>", on_tree_double_click)
        add_right_click_menu(tree, "offline")

        scrollbar = Scrollbar(result_win, orient=VERTICAL, command=tree.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=LEFT, fill=BOTH, expand=True)

        progress = ttk.Progressbar(result_win, mode='indeterminate')
        progress.pack(side=BOTTOM, fill=X)
        progress.start()

        total = len(self.scan_list)
        malicious_count = 0
        def do_scan():
            nonlocal malicious_count
            for idx, (typ, path) in enumerate(self.scan_list):
                result_win.title(f"扫描中... {idx+1}/{total}")
                result_win.update()
                try:
                    if typ == 'zip':
                        zip_subdir = os.path.join(temp_root, f"zip_{idx}")
                        os.makedirs(zip_subdir, exist_ok=True)
                        results = scan_zip(path, zip_subdir)
                        for res in results:
                            if res["malicious"]:
                                malicious_count += 1
                                for line_no, line_content, match, desc in res["findings"]:
                                    snippet = line_content.strip()
                                    if len(snippet) > 120:
                                        snippet = snippet[:117] + "..."
                                    tree.insert("", END, values=(res["path"], "高危", f"{desc} ({match})", snippet, str(line_no)))
                            elif res["error"]:
                                tree.insert("", END, values=(res["path"], "错误", res["error"], "", "-"))
                    elif typ == 'dir':
                        for root, _, files in os.walk(path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                if file_path.lower().endswith('.zip'):
                                    zip_subdir = os.path.join(temp_root, f"dir_{idx}_zip_{os.path.basename(file_path)}")
                                    os.makedirs(zip_subdir, exist_ok=True)
                                    results = scan_zip(file_path, zip_subdir)
                                    for res in results:
                                        if res["malicious"]:
                                            malicious_count += 1
                                            for line_no, line_content, match, desc in res["findings"]:
                                                snippet = line_content.strip()
                                                if len(snippet) > 120:
                                                    snippet = snippet[:117] + "..."
                                                tree.insert("", END, values=(res["path"], "高危", f"{desc} ({match})", snippet, str(line_no)))
                                        elif res["error"]:
                                            tree.insert("", END, values=(res["path"], "错误", res["error"], "", "-"))
                                else:
                                    res = scan_file(file_path)
                                    if res["malicious"]:
                                        malicious_count += 1
                                        for line_no, line_content, match, desc in res["findings"]:
                                            snippet = line_content.strip()
                                            if len(snippet) > 120:
                                                snippet = snippet[:117] + "..."
                                            tree.insert("", END, values=(res["path"], "高危", f"{desc} ({match})", snippet, str(line_no)))
                                    elif res["error"]:
                                        tree.insert("", END, values=(res["path"], "错误", res["error"], "", "-"))
                    else:  # file
                        res = scan_file(path)
                        if res["malicious"]:
                            malicious_count += 1
                            for line_no, line_content, match, desc in res["findings"]:
                                snippet = line_content.strip()
                                if len(snippet) > 120:
                                    snippet = snippet[:117] + "..."
                                tree.insert("", END, values=(res["path"], "高危", f"{desc} ({match})", snippet, str(line_no)))
                        elif res["error"]:
                            tree.insert("", END, values=(res["path"], "错误", res["error"], "", "-"))
                except Exception as e:
                    log_message(f"扫描 {path} 时出错: {e}")
                    tree.insert("", END, values=(path, "错误", f"扫描异常: {str(e)}", "", "-"))
            progress.stop()
            progress.destroy()
            result_win.title(f"扫描完成 - 发现 {malicious_count} 个恶意文件")
            if malicious_count == 0:
                messagebox.showinfo("扫描结果", "未发现已知恶意模式。")
        self.after(10, do_scan)

    # ------------------------------ 在线批量扫描 ------------------------------
    def start_online_scan(self):
        urls = self.get_url_list()
        if not urls:
            messagebox.showwarning("输入为空", "请在文本框中输入至少一个 Skill 链接（每行一个）")
            return
        self.online_targets = urls
        self._perform_batch_online_scan(urls)

    def _perform_batch_online_scan(self, urls):
        if requests is None:
            messagebox.showerror("缺少依赖", "请先安装 requests 库：\npip install requests")
            return

        self.batch_result_window = Toplevel(self)
        self.batch_result_window.title("批量在线检测结果")
        self.batch_result_window.geometry("1300x750")
        self.batch_result_window.protocol("WM_DELETE_WINDOW", self._on_batch_window_close)

        self.batch_notebook = ttk.Notebook(self.batch_result_window)
        self.batch_notebook.pack(fill=BOTH, expand=True, padx=5, pady=5)

        status_frame = Frame(self.batch_result_window)
        status_frame.pack(side=BOTTOM, fill=X)
        self.batch_status_label = Label(status_frame, text="准备扫描...", anchor=W)
        self.batch_status_label.pack(side=LEFT, padx=5)

        self.batch_tabs.clear()
        self.batch_scan_dirs.clear()

        proxies = self._get_proxies_for_request()
        self.scan_threads = []
        for idx, url in enumerate(urls, start=1):
            self._create_batch_tab(idx, url)
            t = threading.Thread(target=self._scan_url_worker, args=(idx, url, proxies), daemon=True)
            t.start()
            self.scan_threads.append(t)

        def monitor_completion():
            for t in self.scan_threads:
                t.join()
            self.after(0, lambda: self.batch_status_label.config(text="批量扫描完成"))
            self.after(0, lambda: messagebox.showinfo("批量扫描完成", f"所有链接扫描完毕，请查看结果窗口中的各标签页。"))
        threading.Thread(target=monitor_completion, daemon=True).start()

    def _scan_url_worker(self, tab_index, url, proxies):
        log_message(f"开始处理链接 {tab_index}: {url}")
        try:
            if "clawhub.ai" in url:
                result = self._scan_clawhub(url, proxies, tab_index)
            elif "skill-cn.com" in url:
                result = self._scan_skill_cn(url, proxies, tab_index)
            elif "skills.sh" in url:
                result = self._scan_skills_sh(url, proxies, tab_index)
            elif "skillstore.io" in url:
                result = self._scan_skillstore(url, proxies, tab_index)
            elif "github.com" in url:
                result = self._scan_github(url, proxies, tab_index)
            else:
                result = {"error": f"不支持的链接: {url}\n目前支持: GitHub, skills.sh, SkillStore, skill-cn, ClawHub"}
        except Exception as e:
            log_message(f"处理链接 {tab_index} 出错: {e}")
            result = {"error": str(e)}
        self.batch_progress_queue.put((tab_index, result))

    def _process_batch_queue(self):
        try:
            while True:
                tab_index, result = self.batch_progress_queue.get_nowait()
                self._update_batch_tab_with_result(tab_index, result)
        except queue.Empty:
            pass
        self.after(100, self._process_batch_queue)

    def _update_batch_tab_with_result(self, tab_index, result):
        if tab_index not in self.batch_tabs:
            return
        frame, tree = self.batch_tabs[tab_index]
        tree.delete(*tree.get_children())

        if "error" in result:
            tree.insert("", END, values=("", "错误", result["error"], "", ""))
            self.batch_notebook.tab(self.batch_notebook.index(frame), text=f"{tab_index} [错误]")
            return

        file_paths = result.get("file_paths", [])
        malicious_count = 0
        for fpath in file_paths:
            res = scan_file(fpath)
            if res["malicious"]:
                malicious_count += 1
                for line_no, line_content, match, desc in res["findings"]:
                    snippet = line_content.strip()
                    if len(snippet) > 120:
                        snippet = snippet[:117] + "..."
                    tree.insert("", END, values=(
                        fpath, "高危", f"{desc} ({match})", snippet, str(line_no)
                    ))
            elif res["error"]:
                tree.insert("", END, values=(fpath, "错误", res["error"], "", "-"))
        if malicious_count == 0 and file_paths:
            tree.insert("", END, values=("", "安全", "未发现已知恶意模式", "", ""))
        self.batch_notebook.tab(self.batch_notebook.index(frame), text=f"{tab_index} [{malicious_count}]")
        add_right_click_menu(tree, "online")

    def _create_batch_tab(self, tab_index, url):
        frame = Frame(self.batch_notebook)
        self.batch_notebook.add(frame, text=str(tab_index))

        columns = ("文件", "危险等级", "命中规则", "代码片段", "行号")
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode='extended')
        tree.heading("文件", text="文件路径")
        tree.heading("危险等级", text="危险等级")
        tree.heading("命中规则", text="命中规则")
        tree.heading("代码片段", text="代码片段")
        tree.heading("行号", text="行号")
        tree.column("文件", width=400)
        tree.column("危险等级", width=80)
        tree.column("命中规则", width=280)
        tree.column("代码片段", width=350)
        tree.column("行号", width=60)

        def on_double_click(event, t=tree):
            selected = t.selection()
            if not selected:
                return
            item = selected[0]
            values = t.item(item, "values")
            if len(values) >= 5:
                file_path = values[0]
                line_str = values[4]
                if line_str.isdigit():
                    open_file_at_line(file_path, int(line_str))
                else:
                    messagebox.showerror("错误", f"无效的行号: {line_str}")
        tree.bind("<Double-1>", on_double_click)

        scrollbar = Scrollbar(frame, orient=VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=RIGHT, fill=Y)
        tree.pack(side=LEFT, fill=BOTH, expand=True)

        tree.insert("", END, values=("", "信息", "扫描中...", "", ""))
        self.batch_tabs[tab_index] = (frame, tree)

    def _on_batch_window_close(self):
        if self.settings.get("online_delete_skill", True):
            for task_dir in self.batch_scan_dirs:
                if os.path.exists(task_dir):
                    shutil.rmtree(task_dir, ignore_errors=True)
                    log_message(f"已删除在线扫描目录: {task_dir}")
        else:
            log_message(f"保留在线扫描目录: {self.batch_scan_dirs}")
        self.batch_result_window.destroy()
        self.batch_result_window = None
        self.batch_notebook = None
        self.batch_tabs.clear()
        self.batch_scan_dirs.clear()

    # ------------------------------ 各平台扫描函数 ------------------------------
    def _get_proxies_for_request(self):
        proxies = None
        if self.proxy_config:
            proxy_info = f"使用代理: {self.proxy_config.get('type')}://{self.proxy_config.get('server')}:{self.proxy_config.get('port')}"
            log_message(f"代理配置: {proxy_info}")
            proxies = get_requests_proxy_dict(self.proxy_config)
            if proxies is None:
                log_message("代理配置无效，将不使用代理")
            else:
                log_message(f"代理对象已创建: {proxies}")
        else:
            log_message("未配置代理，直接连接")
        return proxies

    def _scan_github(self, repo_url, proxies, tab_index=None):
        match = re.search(r'github\.com/([^/]+)/([^/]+)', repo_url)
        if not match:
            return {"error": "无法解析 GitHub 仓库地址"}
        owner, repo = match.group(1), match.group(2)
        if repo.endswith('.git'):
            repo = repo[:-4]
        log_message(f"开始 GitHub 检测: {owner}/{repo}")
        zip_url_main = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
        zip_url_master = f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip"

        script_dir = os.path.dirname(os.path.abspath(__file__))
        download_root = os.path.join(script_dir, "download")
        os.makedirs(download_root, exist_ok=True)
        timestamp = int(time.time())
        task_dir = os.path.join(download_root, f"{repo}_{timestamp}")
        os.makedirs(task_dir, exist_ok=True)
        if tab_index is not None:
            self.batch_scan_dirs.append(task_dir)
        zip_path = os.path.join(task_dir, f"{repo}.zip")
        downloaded = False
        for branch_url in [zip_url_main, zip_url_master]:
            try:
                r = requests.get(branch_url, stream=True, timeout=30, proxies=proxies)
                if r.status_code == 200:
                    with open(zip_path, 'wb') as f:
                        for chunk in r.iter_content(8192):
                            f.write(chunk)
                    downloaded = True
                    break
            except:
                continue
        if not downloaded:
            return {"error": f"无法下载 {owner}/{repo}"}
        try:
            extract_dir = os.path.join(task_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_dir)
            all_files = []
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    all_files.append(os.path.join(root, file))
            return {"file_paths": all_files, "project_name": repo}
        except Exception as e:
            return {"error": str(e)}

    def _scan_clawhub(self, url, proxies, tab_index=None):
        try:
            resp = requests.get(url, timeout=15, proxies=proxies)
            if resp.status_code != 200:
                return {"error": f"页面状态码: {resp.status_code}"}
            html = resp.text
            pattern1 = r'https://[a-z0-9-]+\.convex\.site/api/v1/download\?slug=[^"\'&\s]+'
            match1 = re.search(pattern1, html)
            if match1:
                download_url = match1.group(0)
                slug_match = re.search(r'slug=([^&]+)', download_url)
                skill_name = slug_match.group(1) if slug_match else "clawhub_skill"
                return self._download_and_scan_zip(download_url, skill_name, proxies, tab_index)
            pattern2 = r'/api/v1/packages/[^"\']+/versions/[^"\']+/artifact/download'
            match2 = re.search(pattern2, html)
            if match2:
                api_path = match2.group(0)
                download_url = f"https://clawhub.ai{api_path}"
                slug_match = re.search(r'packages/([^/]+)/versions', download_url)
                skill_name = slug_match.group(1) if slug_match else "clawhub_artifact"
                return self._download_and_scan_tgz(download_url, skill_name, proxies, tab_index)
            return {"error": "未在页面中找到任何可用的下载链接"}
        except Exception as e:
            return {"error": str(e)}

    def _scan_skill_cn(self, url, proxies, tab_index=None):
        match = re.search(r'/skill/(\d+)', url)
        if not match:
            return {"error": "无法从 URL 中提取技能 ID"}
        skill_id = match.group(1)
        api_url = f"https://www.skill-cn.com/api/skills/{skill_id}/download"
        try:
            resp = requests.get(api_url, timeout=15, proxies=proxies, stream=True)
            if resp.status_code == 200:
                content_type = resp.headers.get('content-type', '')
                if 'application/zip' in content_type or 'application/octet-stream' in content_type:
                    return self._download_and_scan_zip(api_url, f"skill_cn_{skill_id}", proxies, tab_index)
            return self._fallback_github_from_page(url, proxies, tab_index)
        except Exception as e:
            return {"error": str(e)}

    def _scan_skills_sh(self, url, proxies, tab_index=None):
        try:
            resp = requests.get(url, timeout=15, proxies=proxies)
            if resp.status_code != 200:
                return {"error": f"页面状态码: {resp.status_code}"}
            html = resp.text
            github_match = re.search(r'https://github\.com/([^/\s]+/[^/\s]+)', html)
            if github_match:
                repo_url = github_match.group(0)
                return self._scan_github(repo_url, proxies, tab_index)
            return {"error": "无法从 skills.sh 页面提取 GitHub 地址"}
        except Exception as e:
            return {"error": str(e)}

    def _scan_skillstore(self, url, proxies, tab_index=None):
        slug_match = re.search(r'/skills/([^/?]+)', url)
        if not slug_match:
            return {"error": "无法从 URL 中提取技能 slug"}
        skill_slug = slug_match.group(1)
        api_url = f"https://skillstore.io/api/skills/{skill_slug}/download"
        try:
            resp = requests.get(api_url, timeout=15, proxies=proxies, stream=True)
            if resp.status_code == 200:
                content_type = resp.headers.get('content-type', '')
                if 'application/zip' in content_type or 'application/octet-stream' in content_type:
                    return self._download_and_scan_zip(api_url, f"skillstore_{skill_slug}", proxies, tab_index)
            return self._fallback_github_from_page(url, proxies, tab_index)
        except Exception as e:
            return {"error": str(e)}

    def _fallback_github_from_page(self, url, proxies, tab_index=None):
        try:
            resp = requests.get(url, timeout=15, proxies=proxies)
            if resp.status_code != 200:
                return {"error": f"页面状态码: {resp.status_code}"}
            html = resp.text
            repo_match = re.search(r'(https://github\.com/[^/\s]+/[^/\s]+/tree/main/)', html)
            if not repo_match:
                repo_match = re.search(r'(https://github\.com/[^/\s]+/[^/\s]+/tree/[^/\s"]+)', html)
            if repo_match:
                repo_url = repo_match.group(1)
                return self._scan_github(repo_url, proxies, tab_index)
            return {"error": "无法从页面中提取 GitHub 仓库信息"}
        except Exception as e:
            return {"error": str(e)}

    def _download_and_scan_zip(self, download_url, skill_name, proxies, tab_index=None):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        download_root = os.path.join(script_dir, "download")
        os.makedirs(download_root, exist_ok=True)
        timestamp = int(time.time())
        safe_name = re.sub(r'[\\/*?:"<>|]', '_', skill_name)
        task_dir = os.path.join(download_root, f"{safe_name}_{timestamp}")
        os.makedirs(task_dir, exist_ok=True)
        if tab_index is not None:
            self.batch_scan_dirs.append(task_dir)
        zip_path = os.path.join(task_dir, f"{safe_name}.zip")
        try:
            r = requests.get(download_url, stream=True, timeout=60, proxies=proxies)
            r.raise_for_status()
            with open(zip_path, 'wb') as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
            extract_dir = os.path.join(task_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_dir)
            all_files = []
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    all_files.append(os.path.join(root, file))
            return {"file_paths": all_files, "project_name": safe_name}
        except Exception as e:
            return {"error": str(e)}

    def _download_and_scan_tgz(self, download_url, skill_name, proxies, tab_index=None):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        download_root = os.path.join(script_dir, "download")
        os.makedirs(download_root, exist_ok=True)
        timestamp = int(time.time())
        safe_name = re.sub(r'[\\/*?:"<>|]', '_', skill_name)
        task_dir = os.path.join(download_root, f"{safe_name}_{timestamp}")
        os.makedirs(task_dir, exist_ok=True)
        if tab_index is not None:
            self.batch_scan_dirs.append(task_dir)
        tgz_path = os.path.join(task_dir, f"{safe_name}.tgz")
        try:
            r = requests.get(download_url, stream=True, timeout=60, proxies=proxies)
            r.raise_for_status()
            with open(tgz_path, 'wb') as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
            extract_dir = os.path.join(task_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            import tarfile
            with tarfile.open(tgz_path, 'r:gz') as tf:
                tf.extractall(extract_dir)
            all_files = []
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    all_files.append(os.path.join(root, file))
            return {"file_paths": all_files, "project_name": safe_name}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------ 导出报告 ------------------------------
    def export_report(self):
        offline_targets = []
        for typ, path in self.scan_list:
            if typ == 'zip':
                offline_targets.append(f"[ZIP] {path}")
            elif typ == 'dir':
                offline_targets.append(f"[DIR] {path}")
            else:
                offline_targets.append(f"[FILE] {path}")
        online_targets_display = [f"[URL] {url}" for url in self.online_targets]

        del_log = get_deletion_log()
        online_deletions = [entry for entry in del_log if entry.get("source") == "online"]
        offline_deletions = [entry for entry in del_log if entry.get("source") == "offline"]

        report_lines = []
        report_lines.append("恶意 Skill 检测报告")
        report_lines.append("=" * 80)
        report_lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")

        report_lines.append("【在线扫描目标】")
        if online_targets_display:
            for target in online_targets_display:
                report_lines.append(f"  {target}")
        else:
            report_lines.append("  无在线扫描目标")
        report_lines.append("")
        report_lines.append("【在线扫描 - 删除操作记录】")
        if online_deletions:
            for entry in online_deletions:
                report_lines.append(f"时间: {entry['timestamp']}")
                report_lines.append(f"文件: {entry['file_path']}")
                for i, (line_num, code_snippet) in enumerate(zip(entry['line_numbers'], entry['code_snippets'])):
                    report_lines.append(f"  行 {line_num}: {code_snippet}")
                    if i < len(entry['rule_descs']):
                        report_lines.append(f"    命中规则: {entry['rule_descs'][i]}")
                report_lines.append(f"删除行号汇总: {', '.join(map(str, entry['line_numbers']))}")
                report_lines.append("-" * 40)
        else:
            report_lines.append("  无删除操作记录")
        report_lines.append("")

        report_lines.append("【离线扫描目标】")
        if offline_targets:
            for target in offline_targets:
                report_lines.append(f"  {target}")
        else:
            report_lines.append("  无离线扫描目标")
        report_lines.append("")
        report_lines.append("【离线扫描 - 删除操作记录】")
        if offline_deletions:
            for entry in offline_deletions:
                report_lines.append(f"时间: {entry['timestamp']}")
                report_lines.append(f"文件: {entry['file_path']}")
                for i, (line_num, code_snippet) in enumerate(zip(entry['line_numbers'], entry['code_snippets'])):
                    report_lines.append(f"  行 {line_num}: {code_snippet}")
                    if i < len(entry['rule_descs']):
                        report_lines.append(f"    命中规则: {entry['rule_descs'][i]}")
                report_lines.append(f"删除行号汇总: {', '.join(map(str, entry['line_numbers']))}")
                report_lines.append("-" * 40)
        else:
            report_lines.append("  无删除操作记录")
        report_lines.append("")
        report_lines.append("【检测说明】")
        report_lines.append("  离线扫描结果窗口关闭时，根据设置决定是否删除解压文件。")
        report_lines.append("  在线批量扫描结果窗口关闭时，根据设置决定是否删除下载文件。")
        report_lines.append("=" * 80)

        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("文本文件", "*.txt")])
        if not save_path:
            return
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write("\n".join(report_lines))
            messagebox.showinfo("导出成功", f"报告已保存到：{save_path}")
        except Exception as e:
            messagebox.showerror("导出失败", f"保存报告时出错：{str(e)}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app = MalSkillDetector()
    if "--full-scan" in sys.argv:
        app.after(500, app.full_scan_skills)
    app.mainloop()