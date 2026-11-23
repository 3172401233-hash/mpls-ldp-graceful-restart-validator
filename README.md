# mpls-ldp-graceful-restart-validator

验证 MPLS LDP 优雅重启(Graceful Restart)、标签保留和邻接恢复。

> **说明:本工具是离线状态校验器,不建立真实 LDP 会话、不收发 LDP 报文。**
> 它根据输入的会话、映射、计时器与恢复事件时间线,逐阶段推演每个 FEC
> 的可用状态,用于发现"旧标签 + 新邻居"组合导致的转发黑洞。

## 环境

- Node.js >= 24.16.0(开发版本 24.16.0)

## 使用

```sh
node bin/ldp-gr-validator.js examples/sample-input.json
```

输出 JSON 报告:

- `phases[]`:每个事件应用后的逐阶段快照(时间、事件、各 FEC 状态)。
- `summary`:最终时刻每个 FEC 的评估结果:
  - `status`:`available` / `stale-only` / `down`
  - `available`:是否可承载新流量(stale 绑定一律为 `false`)
  - `retainedLabel`:当前保留/使用的标签
  - `recoveryPath`:恢复后使用的完整 LSP 路径
  - `via`:选中的下一跳邻居
  - `blackholeReason`:黑洞原因,见下表

## 输入模型

| 字段 | 含义 |
| --- | --- |
| `sessions` | LDP 会话:`id`、`local`/`peer`、`grCapable`、`recoveryTime`(标签保留秒数) |
| `adjacencies` | 邻接关系(会话与接口的绑定) |
| `fecs` | FEC 列表(`id`、`prefix`) |
| `mappings` | FEC→标签映射(`fec`、`session`、`label`) |
| `nextHops` | 每个 FEC 的下一跳候选,数组顺序即优先级(双归场景列两个) |
| `lspPaths` | 每个 FEC 的 LSP 路径与状态 |
| `restartFlags` | 重启标记(`router`、`restarting`) |
| `events` | 按 `time` 排序的恢复事件时间线 |
| `now` | 评估截止时刻(缺省取最后一个事件的时间) |

事件类型:`session-down`、`session-up`、`mapping`(新/刷新映射)、
`withdraw`、`path-change`、`nexthop-change`、`restart`。

## 校验规则与黑洞原因

- **stale 不承载新流量**:邻居(GR)重启后旧映射转为 `stale` 并启动标签
  保留计时器,仅供控制面恢复,`available=false`
  (`stale-binding-retained-no-new-traffic`)。
- **stale 超时**:保留计时器到期仍未重新通告,旧标签清除(`stale-timeout`)。
- **提前新映射**:重启端在 stale 到期前发送新映射,旧标签立即释放、替换。
- **旧标签复用**:旧标签值被同一会话上的其它 FEC 占用时,原 stale 绑定
  失效(`label-reused-conflict`)。
- **整路径校验**:恢复以整条 LSP 路径可用为准,邻居握手成功不够
  (`path-broken`);下一跳不可达单独报告(`next-hop-unreachable`)。
- **会话抖动**:60 秒窗口内 3 次 down 触发阻尼,其映射不再可信
  (`session-flapping`)。
- **双归切换**:按 `nextHops` 优先级在多条会话间选择可用映射;主邻居
  重启时自动评估备份邻居的路径与可达性。

## 测试

```sh
node --test
```

覆盖:双归恢复、双归切换失败、stale 不发布新流量、stale 超时、
映射冲突(标签复用)、提前新映射、路径撤销、下一跳不可达、会话抖动、
非 GR 会话中断。
