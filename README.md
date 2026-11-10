# font2trust

**从字体资产到授权可信度判断** —— 代码字体版权合规检测系统（一期 · 纯 Python 工程，T1–T11 完成 + T12–T14 缺陷回归）。

**目标**：扫描完成后，仓库里每一种字体都能回答四个问题——
用了什么字体 / 是否允许使用及依据 / 判断到什么程度 / 有问题怎么改。

> ⚠️ **免责声明**：本系统为自动化检测与证据归档产出，**不构成侵权结论**。
> 许可证元数据缺失 ≠ 未获授权；识别到许可证 ≠ 已完成核验；fsType 限制 ≠ 禁止商用。
> 「已确认允许/不允许」以技术部负责人审核签署为准。
> **核心原则：扫描工具只发现和收集证据，不替代授权判断。**

---

## 快速开始（离线可跑，无 AI 依赖）

### 运行条件（三者满足即可，结果确定可复现）

1. **依赖离线安装**：
   ```bash
   pip install -r requirements.txt          # 联网环境
   pip download -r requirements.txt -d wheels   # 离线包(一次)
   pip install --no-index --find-links wheels -r requirements.txt
   # 可选组件(许可证扫描): pip install scancode-toolkit==32.5.0
   #   缺失时自动跳过, 不影响其他环节
   ```
2. **仓库可达**：内网 GitLab（token 走环境变量）或 `mode: local` 本地目录
3. **随包数据在位**：`config/`（词库/白名单）、`license_sources/`（许可证原文）、`templates/`

### 单命令执行

```bash
export GITLAB_TOKEN=xxxx            # 只读 token（read_api + read_repository，不落盘）
python -m scripts.main --projects config/projects.local.yaml   # auto: 发现+全量扫描
python -m scripts.main --projects config/projects.local.yaml --discover-only  # 只看清单
python -m scripts.main              # 默认 config/projects.yaml（manual 模板）
python -m scripts.main --reuse-scancode   # 迭代调试: 复用扫描缓存
python -m scripts.main --skip-scancode    # 无 scancode 环境
python -m scripts.main --no-email         # 跳过邮件环节
python -m scripts.main --discover-fallback # 发现失败时复用上次清单(报告标注原因)
```

> **auto 模式（P1a）**：范围 = `auto.groups` + 子组（实测两种口径结果一致）；
> 发现失败**显式报错**，不会静默退回手工清单。全量 35 个项目在本机约 1–2 小时，
> 已配 `repo_concurrency: 2` 与 `unpackage` 排除；分批上线用 `auto.include` 试点。

### 产物

```
reports/current/            # 本次运行
├── report.html             # 八区块报告(00任务清单/01总览/02结论/03证据/04整改/05CSS链 + 06组件/07名称线索)
├── report.json             # 机读数据
├── scan_plan.json          # 扫描任务清单: 计划/成功/失败/过滤(覆盖自证)
├── projects_discovered.json# auto 发现清单(计划扫描什么, 随批次归档)
├── 字体授权台账.md          # 15 字段台账(每字体一行+文件明细)
├── scancode_<name>.json    # 许可证扫描原始输出
├── email_preview.html      # 邮件预览(占位期不发送)
├── summary.md / run.log    # run.log 只含本次运行(批次日志随归档留存)
reports/history/<run_id>/   # 每批次归档(文件级, 无DB; keep_runs 自动清理)
font-compliance/<字体>/      # 证据目录四件套(含许可证原文, 找不到则记"证据未找到")
```

> 输出位置可配置：`config/scanner.yaml` 的 `general.reports_dir` / `general.evidence_dir`，
> 测试与隔离运行指向临时区，不写正式目录。

---

## 目录结构

```
config/
├── scanner.yaml        # 全局(路径/扩展名/排除/扫描超时/保留策略)
├── projects.yaml       # 仓库清单模板(公开版; ${GITLAB_HOST}/${GITLAB_TOKEN} 注入)
├── license_rules.yaml  # 词库 + 许可证分类 + 五档条件表(配置驱动)
├── whitelist.yaml      # 合规字体白名单(status=active 才生效, git 管理)
└── email.yaml          # SMTP 占位(enabled=false 仅渲染预览)
scripts/                # 正式包(16 模块, 每模块 docstring 即接口契约)
templates/              # report.html / email_template.html(模板与代码分离)
license_sources/        # 许可证原文源库(OFL/MIT/CC-BY 全文 + 官方声明)
tests/                  # T2–T11 验收测试 + T12–T14 缺陷回归 + run_all 汇总
tests/fixtures/         # 测试基线(不入库; 重建见「测试基线重建」)
docs/                   # 实施方案(v1.3 拆解依据) / 核实报告 / 验收对照
```

## 测试基线重建（tests/fixtures 不入库）

`tests/fixtures/`（基线仓库副本 + 扫描缓存）已被 `.gitignore` 排除。
克隆本仓库后如需运行测试，按下列步骤重建（需目标仓库访问权限）：

```bash
# 1) 执行一次正式运行（生成克隆与扫描缓存）
python -m scripts.main --projects config/projects.local.yaml
# 2) 复制基线（去掉其中的 .git）
cp -r workspace/<name> tests/fixtures/repo_baseline && rm -rf tests/fixtures/repo_baseline/.git
# 3) 复制扫描缓存
cp reports/current/scancode_<name>.json tests/fixtures/scancode_baseline.json
# 4) 验证基线就绪
python tests/test_t2.py
```

## 关键工作流

### 白名单 = 人工核实入口（"已确认允许"唯一来源）

```bash
# 1. 新字体核实(三层证据: 本地声明/官方原文/哈希比对) → 归档证据目录
# 2. 登记 config/whitelist.yaml, status: pending_review → active(负责人签署, git 留痕)
# 3. 重跑 → 该字体结论自动翻转为"已确认允许"(tests/test_t5.py 双向验证)
```

### 四结论与状态模型（互不混淆）

| 维度 | 取值 |
|---|---|
| 授权结论 | 已确认允许(仅白名单) / 已确认不允许(仅人工) / 授权待确认 / 技术无法判断 |
| 风险等级 | 高危 / 中危 / 低危 / 信息 |
| 审核状态 | 待确认 / 待评估 / 已核实 / 已整改 |
| 许可证状态 | 已识别 / 证据待补 / 已核实 / 存在冲突 / 未知 |
| 使用状态 | 正在使用 / 存在引用未确认运行时 / 未发现引用 / 已移除 / 已替换 |

## 占位项（接入状态）

| 项 | 配置 | 当前状态 |
|---|---|---|
| GitLab | `config/projects.local.yaml` 的 `auto:` 段 + `GITLAB_TOKEN` 环境变量 | **auto 已实现（P1a/P1c）**：组+子组发现、分页、过滤、命名去重、失败显式报错、免落盘克隆凭证。**启用前置**：换 `read_api`+`read_repository` 最小权限长期 token（现有 token 已过敏感期、2026-12-10 到期） |
| SMTP | `email.yaml` + `SMTP_PASSWORD` | `enabled: false`, 仅渲染预览 |
| 收件人 | `email.yaml recipients` | 占位, 待技术部负责人确认 |
| 调度 | — | 二期(方案 §10 P0–P3, 含 Docker/Linux 实测) |

## 验收与测试

```bash
python tests/run_all.py     # 全量汇总(PASS/FAIL 表, 退出码供 CI 判读)
python tests/run_all.py t5 t13   # 指定编号

python tests/test_t2.py   # 字体扫描(基线 24文件/12去重/18解析)
python tests/test_t3.py   # CSS(48引用 + 评审bug回归)
python tests/test_t4.py   # ScanCode(复用+全新)
python tests/test_t5.py   # 结论引擎(白名单双向翻转+五分类三口径)
python tests/test_t6.py   # 台账+证据(不补写许可证原则, 证据目录写临时区)
python tests/test_t7.py   # 五区块报告
python tests/test_t8.py   # 历史归档(无DB)
python tests/test_t9.py   # 邮件占位+文件级环比(预览写临时区)
python tests/test_t11.py  # 端到端冒烟(含"不污染正式产物"守卫, 见 T11)
python tests/test_t12.py  # 配置变更感知(仓库/分支切换重建克隆)
python tests/test_t13.py  # 多仓库端到端(≥2 仓库 + 任务清单 + 并发, P0-1 回归)
python tests/test_t14.py  # 来源推导/high判定/白名单匹配/环比身份(P1 回归)
python tests/test_t15.py  # GitLab 项目发现器(分页/401/过滤/命名, mock API)
python tests/test_t16.py  # 容量控制 + 扫描任务清单(P1b/P1c)
```

验收基准：`docs/验收对照-20261109.md`（九条标准实测对照）。
拆解依据：`docs/实施方案.md` **v1.3**（唯一任务清单）。
