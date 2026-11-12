# SPF 邮件头取证重算（基于 pyspf）

不信任历史 `Received-SPF` / `Authentication-Results` 里写的 `pass`，而是用
**可信连接与信封元数据**和**固定的离线 DNS 视图**，通过 pyspf 的头解析与
`query.check()` 接口重新执行 SPF 评估，输出可重放、可审计的一致性结论。

## 设计原则

1. **头自报身份与可信输入分离**：头中的 `client-ip`、`envelope-from`、`helo`
   仅作为证据解析；重算只使用 `TrustedInput` 中的真实来源地址，头值与可信值
   冲突时记录为 `evidence_conflicts`，绝不覆盖真实来源。
2. **零网络、可重放**：`OfflineDNSView` 在 `offline_dns()` 上下文内替换
   `spf.DNSLookup`（pyspf 唯一 DNS 入口，见 `spf.py` 的 `query.dns`），所有查询
   命中内存快照并写入审计日志；视图带 SHA-256 指纹，相同视图两次运行结果一致。
3. **原始证据不被覆盖**：每个 finding 保留逐字原始折叠头、解析告警、实际使用
   的输入、pyspf 结果、命中机制和本次查询日志；解析失败的头仍然保留并触发基于
   可信输入的重算，结论标记为 `indeterminate` 而不是静默通过。
4. **历史 DNS 免责声明**：每份报告都带 `dns_caveat`——重算只能证明与*当前提供的
   离线视图*一致，不能证明历史投递时刻的真实 DNS 应答相同（记录可能已变更/过期）。

## 身份选择（HELO vs MAIL FROM）

- 头显式给出 `identity=helo`（或 A-R 只有 `smtp.helo` 属性）→ 评估 HELO 身份。
- 头缺身份字段 → 按 RFC 7208 默认评估 MAIL FROM，并在 reasons 中说明。
- MAIL FROM 为空（退信）→ 按 RFC 7208 2.4 自动切换为 HELO 身份，
  sender 传空串，pyspf 内部以 `postmaster@<helo>` 处理。
- 两个身份都会各自执行一次评估并记录，`recomputed_primary` 为与头声明对应的主结果。

## 结论取值

- `consistent`：头声明结果与重算结果相同，reasons 列出匹配身份、域、机制与来源 IP。
- `inconsistent`：结果不同（如伪造 pass 但可信信封实际 `fail`）。
- `indeterminate`：头无法解析、重算得到 temperror/permerror、或无可用可信身份。
- `no_spf_claims`：头部中没有任何 SPF 声明。

## 快速使用

```python
from spf_forensics import OfflineDNSView, TrustedInput, recheck_headers

view = OfflineDNSView(view_id="snapshot-1", missing="empty")
view.put("example.com", "TXT", [["v=spf1 ip4:192.0.2.10 -all"]])

trusted = TrustedInput(
    client_ip="203.0.113.66",          # 来自可信连接日志，而非邮件头
    helo="mx.example.com",
    mail_from="billing@example.com",
)
report = recheck_headers(raw_header_block, trusted, view)
print(report.overall_consistency)      # inconsistent / consistent / indeterminate
report.as_dict()                        # 完整证据包（JSON 可序列化）
```

离线视图缺失记录的策略 `missing`：

- `empty`（默认）：返回空应答，等同 NXDOMAIN/NoAnswer，通常得到 SPF `none`。
- `temperror`：抛 `spf.TempError`，让视图缺口显式暴露为 `indeterminate`。
- `strict`：抛 `OfflineDNSMissing`，用于测试期强制视图完整性。

## 演示与测试

```
.venv/bin/python demo_forensics.py
.venv/bin/python -m unittest tests.test_forensics -v
```

演示包含伪造 `pass` 头但可信来源未授权（标 inconsistent）和合法一致样本
（列出 ip4 机制匹配依据）。测试覆盖多份结果、缺失 identity、HELO/MAIL FROM
选择、空信封、解析失败、DNS 缺口、证据冲突与重放确定性。
