---
title: "Policy Guard Frontline Guide"
linkTitle: "Policy Guard Frontline"
---

# Policy Guard Frontline Guide

这份文档面向一线，目标是快速判断 Everoute 的两类策略熔断问题：

- 内存熔断
- 规则数量熔断

只讲结论、现象、怎么查、怎么调，不展开源码细节。

## 1. 这两个熔断分别在保护什么

Everoute agent 在处理安全策略时，会先做两道保护：

- 内存熔断：当 agent 进程内存太高时，先暂停继续处理新增或变更，避免把 agent 顶死。
- 规则数量熔断：当某个策略或某个关联对象预计会展开成过多规则时，提前拒绝这次变更，避免后续计算和下发把内存打爆。

可以把它理解成：

- 内存熔断是“当前机器已经快扛不住了”
- 规则数量熔断是“这次改动看起来就太大，先别做”

## 2. 实现原理，简版

### 2.1 内存熔断

- agent 会读取自身进程内存占用，优先看 RSS。
- 这个值和配置的内存阈值比较。
- 超过阈值后，memory breaker 打开。
- breaker 打开时，新的策略变更会被拒绝，并在一段时间后自动重试。
- 如果后续内存降下来了，breaker 会自动关闭，之前被挡住的对象会重新进入正常处理。

几点要记住：

- 阈值配置为 `0` 时，等于关闭这个熔断。
- 这个机制是“动态探测”的，不是一次配置后永远不变。
- 一线看到的内存告警，重点不是单纯看 Go heap，而是看 agent 进程整体内存占用。

### 2.2 规则数量熔断

- 在真正应用策略前，agent 会先估算这次变更最终会展开成多少条规则。
- 如果估算值大于规则上限，就直接拒绝这次变更。
- 这样做的目的，是在规则还没真正铺开前，提前拦住高风险变更。
- 这个限制同样支持动态调整，`0` 表示关闭限制。

几点要记住：

- 默认规则上限是 `20000`。
- 这个熔断更像“事前预警”，不是等内存爆了才拦。
- 新增和修改会被挡住，删除或者缩小范围通常可以继续执行。

## 3. 相关指标怎么看

agent 会把这两个熔断的状态都暴露成 metrics，常用的看法如下。

### 3.1 内存熔断相关

- `everoute_ms_policy_memory_usage_bytes`
- `everoute_ms_policy_memory_threshold_bytes`
- `everoute_ms_policy_memory_breaker_open`
- `everoute_ms_policy_memory_breaker_open_total`
- `everoute_ms_policy_memory_breaker_recover_total`
- `everoute_ms_policy_memory_breaker_rejected_objects`

你可以这样理解：

- `policy_memory_usage_bytes` 是当前内存占用
- `policy_memory_threshold_bytes` 是阈值
- `policy_memory_breaker_open` 是 breaker 是否已经打开
- `policy_memory_breaker_rejected_objects` 是当前被内存熔断挡住的对象

### 3.2 规则数量熔断相关

- `everoute_ms_policy_rule_estimate_limit`
- `everoute_ms_policy_rule_estimate_rejected_value`

你可以这样理解：

- `policy_rule_estimate_limit` 是当前规则上限
- `policy_rule_estimate_rejected_value` 是被规则数量熔断挡下来的对象对应的预计规则数

### 3.3 看整体策略压力的指标

下面这两个指标不是熔断本身的判定条件，但在看内存熔断时非常有用，因为它们能告诉你当前 agent 的策略规模有多大：

- `everoute_ms_rule_entry_num_total`
- `everoute_ms_rule_entry_num`

你可以这样理解：

- `rule_entry_num_total` 是 agent 当前承载的总规则数
- `rule_entry_num` 是单条策略当前承载的规则数，label 里 `name` 对应策略名

如果内存熔断已经打开，优先对比这两个指标：

- 总规则数是否明显偏高
- 是否某一条策略特别大，导致整体规则规模被拉高

带 `hostname` 的查看示例：

```promql
everoute_ms_rule_entry_num_total
  * on (_tenant_id, instance_id) group_left (hostname)
    everoute_observe_instance_info
```

```promql
topk(10,
  everoute_ms_rule_entry_num
    * on (_tenant_id, instance_id) group_left (hostname)
      everoute_observe_instance_info
)
```

如果你想直接看某一条策略：

```promql
everoute_ms_rule_entry_num{name="tower-space/tower.sp.internal-controller"}
  * on (_tenant_id, instance_id) group_left (hostname)
    everoute_observe_instance_info
```

### 3.4 告警阈值的小坑

内存熔断告警里，页面展示的是 MiB，因为告警表达式把字节除以了 `1024 / 1024` 再比较。

但是 agent 内部 RPC 和 metric 存的是字节。

所以一线调参时要分清：

- 告警里的阈值，很多时候是 MiB 口径
- `policy-guard memory-threshold set` 这个命令接收的是 bytes

## 4. Release 里的相关告警

release 里和这块相关的告警主要有 5 个。

### 4.1 `policy-memory-breaker-open`

含义：

- agent 的内存熔断已经打开，并且内存持续高于阈值。

怎么看：

- 先看 `everoute_ms_policy_memory_breaker_open`
- 再看 `everoute_ms_policy_memory_usage_bytes`
- 最后看 `everoute_ms_policy_memory_threshold_bytes`

怎么判断问题：

- 如果 `breaker_open=1`，且内存持续高于阈值，说明是典型的内存压力问题。
- 如果只是短时抖动，一般会自动恢复。

怎么处理：

- 先找这台机器上是不是有超大策略、超大成员集，或者短时间内大量编辑。
- 先减规则规模，再考虑临时加大 agent 可用内存。

### 4.2 `policy-rule-limit-exceeded`

含义：

- 某个安全策略本身的预计规则数超过了限制。

怎么看：

- 看告警标签里的 `namespace`
- 看告警标签里的 `name`
- 看 `tower_id`
- 看 `operation`
- 看 `everoute_ms_policy_rule_estimate_rejected_value{resource="policy"}`

怎么判断问题：

- 这是“某条策略太大了”。
- 如果同一条策略反复触发，基本就是策略 selector、端口组合或协议组合过多。

怎么处理：

- 缩小策略对象范围。
- 减少规则对象数量。
- 合并重复规则。
- 能拆分的策略就拆分。

### 4.3 `policy-vm-rule-limit-exceeded`

含义：

- 某个 VM 相关对象触发了规则数量熔断。

怎么看：

- 看 `hostname`
- 看 `target_display`
- 看 `everoute_ms_policy_rule_estimate_rejected_value{resource="group_members"}`

怎么判断问题：

- 这不是单独某条策略一定有问题，而是这个 VM 关联进来的策略组合太大。

怎么处理：

- 回头查引用这个 VM 的安全策略。
- 缩小这些策略的匹配范围。
- 让这个 VM 少命中一些高复杂度策略。

### 4.4 `policy-vm-label-rule-limit-exceeded`

含义：

- 某个 VM 标签对象触发了规则数量熔断。

怎么看：

- 看 `target_display`
- 看 `everoute_ms_policy_rule_estimate_rejected_value{resource="group_members"}`

怎么判断问题：

- 本质和 VM 熔断一样，只是对象类型不同。
- 通常说明标签覆盖范围太大，导致很多 VM 同时被卷进去。

怎么处理：

- 缩小标签选择范围。
- 降低标签关联到的策略数量。

### 4.5 `policy-pod-securitygroup-rule-limit-exceeded`

含义：

- Pod 安全组相关对象触发了规则数量熔断。

怎么看：

- 看 `securitygroup_id`
- 看 `everoute_ms_policy_rule_estimate_rejected_value{resource="group_members"}`

怎么判断问题：

- 这个安全组关联的策略组合太大。

怎么处理：

- 收缩安全组的成员范围。
- 减少引用这个安全组的策略数量。
- 减少单条策略中的规则展开组合。

## 5. 一线排障顺序

建议按这个顺序看：

1. 先看告警是内存熔断还是规则数量熔断。
2. 再看告警标签，确认是 `policy` 还是某个 `group_members` 对象。
3. 再看 agent 当前状态。
4. 最后决定是“改策略”还是“改阈值”。

### 5.1 先看状态

通过 `everoute-cli` 进入后，命令行根命令显示为 `erctl`，下面的 `policy-guard` 子命令直接可用。

```bash
erctl policy-guard status
```

输出里重点看：

- `memory.enabled`
- `memory.breaker-open`
- `memory.threshold`
- `rule.enabled`
- `rule.rule-limit`

### 5.2 再看对应 metrics

内存熔断优先看：

- `everoute_ms_policy_memory_usage_bytes`
- `everoute_ms_policy_memory_threshold_bytes`
- `everoute_ms_policy_memory_breaker_open`
- `everoute_ms_policy_memory_breaker_rejected_objects`

如果要判断是不是“整体策略配置压力”导致的内存问题，再一起看：

- `everoute_ms_rule_entry_num_total`
- `everoute_ms_rule_entry_num`

规则数量熔断优先看：

- `everoute_ms_policy_rule_estimate_limit`
- `everoute_ms_policy_rule_estimate_rejected_value`

### 5.3 再看对象是谁

如果是 `policy-rule-limit-exceeded`，重点看策略名和命名空间。

如果是 VM 或标签相关的熔断，重点看：

- `target_display`
- `securitygroup_id`

然后回查这些对象引用了哪些策略。

## 6. 怎么做调整

### 6.1 推荐优先做的事

优先顺序是：

1. 缩小策略范围。
2. 减少规则数。
3. 减少端口和协议组合。
4. 减少不必要的成员对象。
5. 必要时再调高阈值。

### 6.2 在线调参命令

查看当前状态：

```bash
erctl policy-guard status
```

调整内存阈值，单位是 bytes：

```bash
erctl policy-guard memory-threshold set 2147483648
```

调整规则数量上限：

```bash
erctl policy-guard rule-limit set 30000
```

临时关闭内存熔断：

```bash
erctl policy-guard memory disable
```

临时关闭规则数量熔断：

```bash
erctl policy-guard rule disable
```

说明：

- `memory-threshold set 0` 表示关闭内存阈值。
- `rule-limit set 0` 表示关闭规则数量限制。
- 关熔断只适合临时止血，不建议长期这么做。

### 6.3 什么情况下可以调大阈值

可以考虑调大阈值的场景：

- 业务确认这次只是策略规模正常增长。
- 机器内存还有余量。
- 当前问题更像是阈值偏保守，而不是策略设计有明显问题。

不建议只靠调阈值的场景：

- 策略和成员规模持续增长。
- 同一个对象反复触发规则熔断。
- agent 已经长期处于高内存状态。

## 7. 一句话总结

- 内存熔断看的是“agent 当前是不是已经快顶不住了”。
- 规则数量熔断看的是“这次变更展开后会不会太大”。
- 告警出现后，先定位是哪个策略或对象，再决定是缩小范围，还是临时调阈值。
