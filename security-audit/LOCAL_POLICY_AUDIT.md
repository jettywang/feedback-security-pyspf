# pyspf local policy（`local=` / libspf_local）授权语义审查报告

日期：2026-11-12
范围：`spf.py` 中 `insert_libspf_local_policy` → `query.check` → `check1` →
`check0` 的完整求值路径，重点核对“接收方本地放行”是否会被伪装成“发件域名授权”。
所有结论均可离线复跑：`security-audit/run_audit.sh`（用内存 DNS 区替换
`spf.DNSLookup`，不发任何网络请求）。

## 1. 调用链与插入点

- `query.__init__` 把 `local=` 存到 `self.libspf_local`（`spf.py:397`）。
- 仅在顶层 `query.check()` 中，当“域名 SPF 文本存在且 local 非空”时拼接一次
  （`spf.py:616` 起）。随后交给 `check1(..., recursion=0)`。
- `include:`（`spf.py:955`）与 `redirect=`（`spf.py:1011`）递归调用 `check1`，
  递归分支拿到的是 DNS 原文，**不会再经过拼接函数**。
- 拼接算法 `insert_libspf_local_policy`（`spf.py:1995`，内部实现
  `_insert_libspf_local_policy_indexed` 于 `spf.py:1956`）：反转 token，找“最后一个
  带默认（pass）限定符的机制”，把整段 local 字符串插到它后面；找不到这种机制就
  原样返回（不拼接）。

## 2. 拼接规则如何改变域策略（字符串矩阵，PART A 实测）

| 原始记录 | local | 拼接结果 | 含义 |
|---|---|---|---|
| `v=spf1 -all` | `mx` | `v=spf1 -all`（不变） | 全显式 fail，local 被**静默丢弃** |
| `v=spf1` | `a mx ptr` | `v=spf1 a mx ptr` | 空记录：local 成为唯一机制 |
| `v=spf1 mx -all` | `a ptr` | `v=spf1 mx a ptr -all` | local 在域 `-all` 短路**之前**求值 |
| `v=spf1 mx -include:x +all` | `a ptr` | `v=spf1 mx a ptr -include:x +all` | local 先于显式 `+all` |
| `v=spf1 redirect=t` | `ip4:...` | `v=spf1 redirect=t ip4:...` | 文本上 local 在 modifier 后，但机制先求值 |
| `v=spf1 -all exp=_e` | `ip4:...` | `v=spf1 -all exp=_e ip4:...` | **死代码**：local 落到 `-all` 之后，永不求值 |
| `v=spf1 -ip4:x -all` | `ip4:...` | 原样不变 | 无默认限定符机制 → 丢弃 |
| `v=spf1 +all` | `ip4:...` | 原样不变 | 全显式限定符 → 丢弃 |

要点：插入位置由“记录里是否存在默认限定符机制”决定，与管理员直觉里的“在 all
之前统一加白名单”并不等价。`-all` 强拒绝记录可能完全不被本地白名单影响，而
`mx -all` 这类记录又会被本地规则抢先放行——是否生效高度依赖记录写法。

## 3. 求值顺序与结果差异（PART B 实测，客户端 192.0.2.66 仅被 local 授权）

| 域名记录形态 | 无 local | 启用 local | 命中机制(启用后) | 来源 |
|---|---|---|---|---|
| `ip4:其他 -all`（strict） | fail | **pass** | `ip4:192.0.2.66` | local |
| `mx +ip4:其他 -all`（plus） | fail | **pass** | local ip4 | local |
| `~ip4:… ?ip4:… ~all`（qual） | softfail | softfail（不变） | `~all` | domain |
| `include:sub -all`（incl） | fail | **pass** | local ip4 | local |
| `include:无SPF -all`（inclnone） | permerror | permerror（不变） | — | — |
| `redirect=target(-all)`（redir） | fail | **pass** | local ip4 | local |
| `redirect=target(include…)`（redir2） | fail | **pass** | local ip4 | local |
| `redirect=无SPF`（redirbad） | permerror | **pass** | local ip4 | local |
| 域名无 SPF（none） | none | none（不变） | — | — |
| `-all exp=…`（exp，死代码） | fail | fail（不变） | `-all` | domain |
| `mx +all`（plusall） | pass | pass（但改由 local 命中） | local ip4 | local |
| `-ip4:… -all`（allfail） | fail | fail（不变） | `-all` | domain |

### 对“拒绝短路”的影响
- local 机制位于域末尾 `all` 之前，因此一旦 local 命中即 `break`，**原本的
  `-all`/`~all` 短路被提前覆盖**：strict/redir/incl 三类从 fail 翻成 pass。
- 但 local 自身也带限定符且参与同样的短路（PART edge 实测）：`~ip4`→softfail、
  `?ip4`→neutral、`-ip4`/`-all`→fail、`+all`→pass。即本地规则既能放行也能拒绝，
  且在域 `all` 之前生效。
- 当拼接被跳过（全显式 fail、`+all`、exp 死代码布局）时，域拒绝短路**原样保留**，
  local 不产生任何效果，也没有任何告警。

## 4. 递归域是否被再次插入（PART C 实测，明确结论）

对 include / redirect / redirect→include 三种链，拼接函数在每次 `check()` 中
**只被调用 1 次**，入参始终是顶层记录：

```
incl.example.com   inserts=1  入参=['v=spf1 include:sub.example.com -all']
redir.example.com  inserts=1  入参=['v=spf1 redirect=target.example.com']
redir2.example.com inserts=1  入参=['v=spf1 redirect=target2.example.com']
```

结论：本地策略**不会**在递归的 include/redirect 域上二次插入。本地规则只在顶层
记录的命名空间里求值一次；其 `%{d}` 等宏也按顶层发件域展开，不会变成被包含域。
唯一例外是“顶层无机制、落到 redirect”时，local 仍先于 redirect 求值（见 redir 行），
但 redirect 目标本身不被插入 local。

## 5. 已确认的其他语义风险（PART edge）

- **DNS 预算不豁免**：源码注释称“Processing limits not applied to local
  policy”，但实测 local 中的 `mx/a/ptr/exists/include` 同样调用 `check_lookups()`，
  会占用 10 次 DNS 查询上限并计入 void lookup（`local mx` 使 lookups 1→2；无 MX 时
  `void_lookups=2`）。只有 `ip4/ip6` 不耗查询。local 可能把原本合规的记录推过上限。
- **非幂等**：对已拼接记录再次 `check(spf=<拼接结果>)` 会重复插入
  （`… ip4:x ip4:x -all`），调用方不要把拼接结果回灌。
- **无 SPF 域不生效**：`dns_spf` 返回 None 时不拼接，结果保持 `none`，local 无法
  凭空授权。
- **结果伪装（核心问题）**：local 命中产生的 `pass` 与域授权 `pass` 在返回元组、
  说明文案（`sender SPF authorized`）、`mechanism`、Received-SPF 头
  （"domain of … designates … as permitted sender"）上完全一致，调用方无法区分，
  容易把接收方例外误报为对方域名认可。

## 6. 接口改造：显式来源标记（向后兼容）

默认字符串拼接与所有既有返回值**逐字节不变**（官方 429 个 YAML 用例继续通过），
在此之上新增只增不改的来源能力：

- `query.authorization_source()`（`spf.py:1611`）/ 属性 `result_source`：
  `'domain'` = 发件域发布记录命中；`'local'` = 接收方 local 命中；
  `None` = 无机制命中（neutral/none/error）或尚未 check。
- `query.mechanism_source`：与 `mechanism` 对应的来源。
- `query.get_header(res, annotate_source=True)`（`spf.py:1623`）：在 Received-SPF
  头追加 `x-policy-source=local|domain;`。默认不传时头部**完全不变**，老消费者无感。
- 来源判定基于**插入位置切片**而非机制文本（`spf.py:895`、`spf.py:1956`
  返回的 start/count），因此当域记录与 local 含完全相同的机制文本时，仍能正确归到
  `domain`（见单测 `testLocalPolicyIdenticalTextPosition`），避免文本匹配误判。

新增单测位于 `test/testspf.py` 的 `SPFTestCases`（7 个，全离线），覆盖：拼接不变性、
索引切片、local/domain 来源、相同文本去歧义、限定符来源、递归仅插入一次。
完整套件 `Ran 435 tests OK`。

## 7. 接入建议

1. 启用 `local=` 后，**不要**仅凭 `result=='pass'` 判定“域授权”。读取
   `q.authorization_source()`：`local` 的 pass 应在日志/计费/反欺诈策略里记为
   “接收方本地例外”，而非发件域认可。
2. 对外出具 Received-SPF/Authentication-Results 时，若需要让下游区分，显式传
   `annotate_source=True`；兼容场景保留默认头部，但在内部数据模型单独存来源字段。
3. 不要假设 local 一定生效：全显式 fail（`-all`、`+all`）、`exp=` 前置等布局会让
   local 被静默丢弃或成为死代码。上线前用 `run_audit.sh` 对目标记录实测，而不是只看
   拼接字符串。
4. local 中优先用 `ip4/ip6`；如用 `mx/a/ptr/exists/include`，需把其 DNS 计入查询与
   void 预算，避免把合规记录推入 permerror。
5. 不要把拼接后的 SPF 文本回传给 `check(spf=...)` 重复求值（非幂等）；来源信息一律
   从查询对象的属性读取，不要自行字符串匹配。
6. local 机制同样支持 `-/?/~` 限定符并先于域 `all` 短路，配置 local 时按“可拒绝”的
   完整权限对待，而非仅白名单。

## 8. 复跑方式

```
sh security-audit/run_audit.sh
```
- `security-audit/local_policy_audit.py`：PART A 字符串矩阵 / B 全求值矩阵 /
  C 递归插入计数 / D 头部文案。
- `security-audit/local_policy_edge.py`：限定符、DNS/void 预算、死代码、非幂等。
- `security-audit/source_provenance.py`：新来源标记与头部标注、相同文本去歧义。
- 单元测试：`cd test && ../.venv/bin/python testspf.py`。
