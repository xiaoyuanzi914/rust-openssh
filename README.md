# rust-openssh

`rust-openssh` 是一个将 OpenSSH 从 C 语言移植到 Rust 编程语言的项目。源地址请参考：https://github.com/openssh/openssh-portable，它实现了 SSH 协议（版本 2），用于安全的远程登录、命令执行和文件传输。该项目旨在使用 Rust 的特性（如内存安全和并发支持）提供更安全、高效、现代的 OpenSSH 实现。

## 特性

- **SSH 客户端（`ssh`）**：安全的远程登录和命令执行。
- **SSH 服务器（`sshd`）**：安全的远程服务器访问和管理。
- **文件传输工具**：
  - `scp`（安全拷贝协议）
  - `sftp`（安全文件传输协议）
- **密钥管理工具**：
  - `ssh-keygen`：用于生成 SSH 密钥。
  - `ssh-agent`：在内存中管理 SSH 密钥。
- **附加工具**：包括密钥扫描、服务器管理等工具。

## 兼容性

`rust-openssh` 旨在支持各种类 Unix 操作系统，包括：

- Linux
- macOS
- BSD 系统
- Cygwin

该项目为不在其他平台上提供的 OpenBSD API 提供了兼容层，并通过沙箱化特性增强了对更多操作系统的安全性。


## 构建 rust-openssh

### 前置条件

要构建 `rust-openssh`，你需要安装以下工具：

- [Rust](https://www.rust-lang.org/)（Rust 工具链）
- [Cargo](https://doc.rust-lang.org/cargo/)（Rust 的包管理和构建工具）
- OpenSSL 或 LibreSSL（推荐安装，以获得完整的加密功能）
- zlib（可选，若需要传输压缩支持）
- FIDO2 安全令牌支持（需要 `libfido2`）

### 运行/测试

首先，克隆项目仓库：

git clone https://github.com/xiaoyuanzi914/rust-openssh.git
cd rust-openssh

克隆后，你可以使用 Cargo 来构建项目：

cargo build --release

构建完成后，你可以运行测试以确保一切正常：

cargo test

如果你希望在构建过程中配置特定选项，可以使用 Cargo 特性和环境变量。有关可用的构建选项，请参见 `Cargo.toml` 文件和 `build.rs` 脚本。
