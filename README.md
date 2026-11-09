# PortGuard · 飞牛 NAS 端口态势感知

把 `ss -tulnp` 的几十行天书，变成能读懂、能判断、能行动的情报。

PortGuard 是一个飞牛 fnOS 原生应用（`.fpk`），用**全只读**的方式采集端口、进程、cgroup、容器与 nftables 数据，回答五个问题：

1. **哪些端口在监听？到底是谁在用？** —— 端口 → 进程 → 容器 / systemd → 飞牛应用，四层归因
2. **哪些端口开着却没人用？** —— 活跃 / 低频 / 闲置 / 僵尸 / 幽灵，五种判定，附连接数与流量证据
3. **3306 是什么？** —— 内置 200+ 端口指纹，看到端口号就知道服务、风险与处置建议
4. **哪些端口在冲突？** —— 双协议同号、端口共享、映射抢占、声明不符、归属异常
5. **暴露面有多大？** —— 区分「仅本机」「局域网」「公网 IPv6 可直连」

![端口矩阵](assets/screenshot-matrix.png)

## 为什么不是又一个 `ss` 前端

| | `ss -tulnp` | 普通端口面板 | PortGuard |
|---|---|---|---|
| 端口列表 | ✅ | ✅ | ✅ |
| 服务语义（3306 = MySQL） | ❌ | 部分 | ✅ 204 条知识库 |
| 容器内真实进程 | ❌ 只看到 `docker-proxy` | ❌ | ✅ `nsenter` 穿透 + cgroup 反查 |
| 归属到飞牛应用 | ❌ | ❌ | ✅ 路径 / manifest / systemd 三级匹配 |
| 「开着没人用」的判定 | ❌ | ❌ | ✅ 滑动窗口 + nft 计数器 |
| 端口冲突分类 | ❌ | ❌ | ✅ 6 类 |
| 暴露面与风险评分 | ❌ | ❌ | ✅ 含公网 IPv6 检测 |
| 只读保证 | ✅ | 不一定 | ✅ 不写系统、不启停服务 |

## 截图

| 应用视图 | 证据链详情 |
|---|---|
| ![应用视图](assets/screenshot-apps.png) | ![端口详情](assets/screenshot-detail.png) |

## 判定模型

### 七种状态

| 状态 | 含义 | 判据 |
|---|---|---|
| 活跃 `ACTIVE` | 窗口内确有访问 | 连接峰值 ≥ 5 或外部流量 ≥ 100 包 |
| 低频 `WARM` | 偶尔被访问 | 有连接但低于活跃阈值 |
| 闲置 `IDLE` | 开着没人用 | 窗口内 0 连接、0 流量，且进程存活 > 30 min |
| 刚启动 `FRESH` | 还看不出 | 进程存活 < 30 min，避免重启被误判 |
| 僵尸 `ORPHAN` | 端口占着、服务没了 | 有监听但无进程归属（socket 残留） |
| 内核态 `KERNEL` | 内核直接持有 | 如 NFS 2049，用户态查不到 fd |
| 幽灵 `GHOST` | 以为开着，其实没服务 | 有映射/防火墙声明但无监听 |

### 六类冲突

`DUAL_PROTO` 双协议同号（正常）、`SHARED` 多进程共享（正常）、`MAP_CONFLICT` 映射抢占（真冲突）、`DECL_MISMATCH` 声明与实际不符、`HIJACK` 归属异常、`GHOST_*` 幽灵端口。

> 前两类只提示、不报警——`30019` 同时有 TCP/UDP、`5353` 被 avahi 与影视服务共享，都是正常现象。误报会让工具失去信任。

### 风险评分

```
风险 = 暴露面 + 服务敏感度 + 鉴权证据   （0–100，≥70 高，40–69 中）
```

其中「本应监听全网卡」的服务（nginx、SMB、飞牛网关等）会按 60% 折算暴露分，避免所有服务都变成高风险的评分通胀。

## 安装

### 方式一：应用中心手动安装（推荐）

1. 从 [Releases](https://github.com/HUIdada1/fnOS_port_monitoring/releases) 下载 `portguard.fpk`
2. 飞牛 Web → 应用中心 → 右上角「手动安装」→ 选择 fpk
3. 安装向导中设置访问口令
4. 桌面出现「端口态势感知」图标，点击打开

### 方式二：命令行

```bash
sudo appcenter-cli manual-install enable
sudo appcenter-cli install-fpk portguard.fpk
sudo appcenter-cli status portguard
```

### 方式三：从源码构建

```bash
git clone https://github.com/HUIdada1/fnOS_port_monitoring.git
cd fnOS_port_monitoring
fnpack build -d .
# 产物：portguard.fpk
```

`fnpack` 是飞牛自带的打包工具（fnOS 上位于 `/usr/local/bin/fnpack`），也可以直接在 NAS 上构建。

> **架构说明**：manifest 使用 `platform = all`。若你的 `fnpack` 版本不接受该值，把 `platform` 改成 `x86` 或 `arm` 分别构建即可——代码是纯 Python，无任何二进制依赖。

## 使用

安装后访问 `http://<NAS地址>:18110`，或直接点桌面图标。

- **首次访问**：需在安装后 30 分钟内、从内网或本机设置访问口令（至少 8 位）
- **忘记口令**：重置即可（不会丢失数据）

```bash
VAR=$(readlink -f /var/apps/portguard/var)
/var/apps/portguard/target/portguardd --init --data "$VAR" --password '新的口令'
/var/apps/portguard/cmd/main start
```

- **报告导出**：右上角「报告」→ Markdown / CSV / JSON
- **深链**：`?view=apps`、`?port=3306` 可直接打开指定视图或端口详情

## 权限说明（为什么是 root）

端口归因需要读 `/proc/<pid>/fd`、`/proc/<pid>/cgroup`，以及 `nft list ruleset` 与容器网络命名空间。这些在 Linux 上只有 root 能读全。**这也是同类工具（1Panel、Lucky、fntermx）都以 root 运行的原因。**

PortGuard 的只读承诺：

- 不修改任何系统配置、不启停任何服务、不写 `/etc` 或 `/proc`
- 唯一的写操作发生在应用自己的数据目录（`TRIM_PKGVAR`）：SQLite 数据库、配置、日志
- 你可以自己验证：

```bash
# 观察 10 秒内所有写类系统调用，正常应只出现数据目录内的路径
sudo strace -f -p $(cat /var/apps/portguard/var/run/portguard.pid) \
  -e trace=openat,unlink,rename,write -qq 2>&1 | grep -v '/var/apps/portguard'
```

## 兼容性

| 项目 | 支持情况 |
|---|---|
| fnOS | 1.1.8 及以上（低版本可自行下调 `os_min_version`） |
| 架构 | x86_64 / ARM64（纯 Python，无二进制） |
| Docker | 有则穿透归因，无则自动降级，不影响使用 |
| 非 root | 可启动，但只能看到本用户进程，界面会提示权限受限 |
| 多存储卷 | 全部走 `TRIM_*` 环境变量，不硬编码 `/vol1` |
| 无 `ss` | 以 `/proc` 为主，`ss` 仅作兜底 |

## 已知限制

- 容器内进程名依赖 `nsenter`；distroless 等极简镜像可能读不到进程名，但能确认端口在监听
- 网关 socket 模式（走飞牛统一网关、不暴露端口）尚未启用，当前为独立端口 18110
- 时间线只记录端口开合与状态变化，趋势图表在路线图中
- 未在 ARM 实机验证（逻辑上无差异）

## 开发

```bash
# 仅需 Python 3.8+，无第三方依赖
python3 tests/smoke.py
```

测试覆盖：`/proc` 地址解析、七态判定、冲突检测、多持有者归因、容器解析、HTTP 鉴权流程。

目录结构：

```
app/            # 安装后即 target/
  portguardd    # 入口：采集循环 + HTTP 服务
  pg_collect.py # /proc 采集
  pg_analyze.py # 状态机 / 冲突 / 评分
  pg_apps.py    # 应用清单、容器元数据、netns 穿透
  pg_net.py     # nftables DNAT 与流量计数
  pg_store.py   # SQLite 快照 / 事件 / 标注
  pg_server.py  # HTTP API 与会话鉴权
  kb_ports.json # 端口知识库
  ui/           # 单页界面（零 CDN）
cmd/            # 生命周期脚本
config/         # 权限与资源声明
wizard/         # 安装 / 配置向导
tests/          # 冒烟测试
```

## 路线图

- [ ] 端口历史趋势图（数据已入库，缺可视化）
- [ ] 网关 socket 模式，彻底不暴露 TCP 端口
- [ ] docker-compose 声明端口与实际映射的差异检测
- [ ] 知识库社区共建（PR 只改 JSON）
- [ ] ARM 实机验证

## 许可

[MIT](LICENSE)

> PortGuard 与飞牛官方无关，为第三方开源项目。使用前请自行评估风险。
