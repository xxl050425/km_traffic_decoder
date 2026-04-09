# KeyMouse Traffic Decoder (GUI)

一个用于分析键鼠流量的图形化工具，支持直接导入文本流量或 `pcap/pcapng/cap` 包进行解码与分析。

## 功能

- 键盘解码
  - USB 键盘（8 字节）
  - PS/2 键盘 Set1 / Set2
- 鼠标解码
  - USB 鼠标（4 字节）
  - USB 鼠标（8 字节变体）
  - PS/2 鼠标（3 字节）
- 流量包直读
  - 通过 `tshark` 自动提取 `usbhid.data / usb.capdata`
- 分析视图
  - 重建文本
  - 事件日志
  - 统计信息
  - 按键分析
  - 鼠标轨迹

## 环境要求

- Python 3.8+
- Windows（当前 GUI 和打包流程在 Windows 下验证）
- 可选：`tshark`（若要直接分析 `pcap/pcapng`）

## 快速运行

```powershell
python .\app.py
```

## 安装构建依赖（用于打包 EXE）

```powershell
pip install -r .\requirements-dev.txt
```

## 打包 EXE

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1
```

打包输出：

- `dist\km_traffic_decoder.exe`

## 项目结构

```text
km_traffic_decoder/
├─ app.py
├─ README.md
├─ LICENSE
├─ .gitignore
├─ requirements-dev.txt
└─ scripts/
   └─ build_exe.ps1
```

## 说明

- `*.exe`、`build/`、`dist/` 默认已被 `.gitignore` 忽略。
- EXE 不直接放在仓库文件中，使用 GitHub Packages 分发（见仓库 `Packages` 页面）。
