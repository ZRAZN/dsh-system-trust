# dsh-system-trust

让 DeepSeek Harness（DSH）的模型请求不再因为「HTTPS 中间人证书」报错。

## 它解决什么问题

卡巴斯基、ESET、Avast、Bitdefender、Zscaler、公司代理等安全软件会监听 HTTPS 流量，把服务器证书替换成自己签发的证书。Node.js（DSH 的模型请求走 Node 的 TLS 栈）只信任内置的根证书，不认这些「中间人根证书」，于是请求直接失败：

```
DeepSeek Messages request failed (502)
self-signed certificate in certificate chain
```

常见的临时方案是手动导出证书并设置 `NODE_EXTRA_CA_CERTS`，但它只对**新启动的进程**生效，DSH 桌面版从托盘/快捷方式启动时经常继承不到，表现为「设置了也没用 / 重启又坏」。

## 它做什么

DSH 启动时，本插件：

1. 读取**操作系统的根证书存储**（Windows：`Cert:\LocalMachine\Root` + `Cert:\CurrentUser\Root`；macOS：`security find-certificate`；Linux：系统 CA bundle）；
2. 把这些根证书**无条件**合并进 Node 的默认信任库（Node 24 用 `tls.setDefaultCACertificates`，旧版本 patch `tls.createSecureContext`）——因为安全软件可能在任何时刻开始/停止拦截，不能等探测失败再修；
3. 用严格校验连接 `api.deepseek.com`，把结果写到 `~/.dsh/system-trust-status.json`；之后每 5 分钟复查一次并更新状态。

之后 DSH 里所有走 Node TLS 的请求（模型 API、插件下载等）都会信任系统根证书，包括安全软件的中间人证书。

## 安装

本地安装：

```
dsh plugin install link:D:/插件/dsh-system-trust
```

或发布到 npm 后：

```
dsh plugin install dsh-system-trust
```

安装后**重启 DSH**（插件在宿主启动时执行）。重启后查看：

```powershell
Get-Content "$env:USERPROFILE\.dsh\system-trust-status.json"
```

- `"ok": true, "action": "none"`：证书本来就正常，未做任何改动；
- `"ok": true, "action": "installed", "roots": 132`：已注入系统根证书，问题已修复；
- `"ok": false`：注入后仍失败，文件里的 `error` 有具体原因。

## 安全说明

注入系统根证书 = 让 Node 信任这台机器上所有受信任的根（包括安全软件/公司代理的中间人证书）。这是企业环境和安全软件环境下的标准做法，但会降低 TLS 的严格性。如果你只需要信任某一张证书，可以不用本插件，改用手动设置 `NODE_EXTRA_CA_CERTS` 指向该证书的 PEM 文件。

本插件不做任何网络请求之外的操作：不修改系统证书存储，只读取；不写入除状态文件外的任何文件。

## 兼容性

- DSH 内置 Node 24：使用 `tls.setDefaultCACertificates`；
- 旧版 Node：patch `tls.createSecureContext`，把系统根并入每次建连的 `ca`；
- Windows / macOS / Linux 都支持（Windows 用 PowerShell 读证书存储，无需额外依赖）。
