# 🔐 SSH 公钥安装脚本说明

> 一键安装 SSH 公钥、修改端口、禁用密码登录等功能的实用脚本。

---

## 📘 基本语法

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) [选项...] <参数>
🧩 选项说明
选项	说明	参数要求
-o	覆盖模式，必须写在最前面才会生效	无
-g	从 GitHub 获取公钥	GitHub 用户名
-u	从 URL 获取公钥	公钥文件的 URL
-f	从 本地文件 获取公钥	本地文件路径
-p	修改 SSH 端口	端口号
-d	禁用密码登录	无

🪄 生成 SSH 密钥对
如果你还没有密钥，可以执行以下命令后一路回车：

bash
复制代码
ssh-keygen -t ecdsa -b 521
✅ 适用于 Windows 10 (1803+) PowerShell / WSL / Linux / macOS 等环境。
💡 521 位 ECDSA 密钥比 RSA 更安全，验证速度更快。

生成后，会在 ~/.ssh/ 目录下看到两个文件：

id_ecdsa —— 私钥

id_ecdsa.pub —— 公钥（就是我们要安装到远程主机的）

🏠 家目录路径说明
系统	路径示例
Linux 普通用户	/home/用户名
Linux root 用户	/root
macOS	/Users/用户名
Windows 10	C:\Users\用户名

🚀 安装公钥
① 从 GitHub 获取公钥
先在 GitHub 的 SSH Keys 页面添加你的公钥。
例如用户名为 carsonmoon：

bash
复制代码
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) -g carsonmoon
② 从 URL 获取公钥
将公钥文件上传到网盘或服务器，然后使用下载链接：

bash
复制代码
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) -u https://carsonmoon.com/key.pub
③ 从本地文件获取公钥
将公钥传到 VPS（例如 /root/key.pub），然后执行：

bash
复制代码
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) -f ~/key.pub
⚙️ 进阶选项
覆盖模式（-o）
覆盖原有的 ~/.ssh/authorized_keys 文件：

bash
复制代码
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) -o -g carsonmoon
或简写：

bash
复制代码
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) -og carsonmoon
禁用密码登录（-d）
确认密钥登录正常后，可禁用密码登录：

bash
复制代码
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) -d
修改 SSH 端口（-p）
例如修改为 2222 端口：

bash
复制代码
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) -p 2222
🧠 一键综合操作示例
安装密钥、修改端口、禁用密码登录，一条命令搞定：

bash
复制代码
bash <(curl -fsSL https://raw.githubusercontent.com/carsonmoon/ssh-installer/main/key.sh) -og carsonmoon -p 2222 -d
💬 提示
该脚本仅修改当前服务器的 SSH 登录方式，不影响系统其他配置。

如使用覆盖模式（-o），请务必确保你保留了私钥备份，否则可能无法再次登录。
