# CertManager

## 下载 Debug APK

[CertManager-debug.apk](downloads/CertManager-debug.apk)（1.1.0，58,748,968 字节）。在 GitHub 文件页点击下载按钮获取；私有仓库需要有访问权限。

校验文件：[SHA256SUMS.txt](downloads/SHA256SUMS.txt)。APK SHA-256：

```text
af1cab456da9457e8d9d3eeeb5bd87495c4b84ad255595d32e492ea5b6056d93
```

此包使用 Debug 签名，尚未经过 HyperOS 真机验收；功能和限制见下文与 `VALIDATION.md`。

## 1.1.0：用户 CA 清理

首页新增“CA 安全警告处理”，用户证书页新增“清理全部用户 CA”入口。页面展示实际可见用户 CA 数量、当前环境可安全自动卸载数、跳过数、每张证书的 Subject / Issuer / SHA-256 / 用户 ID / 全部来源位置、备份状态、进度与逐项结果。

**普通 Root 安装的关键限制：**本版不会通过直接删文件、调用不稳定 Binder 事务或修改系统数据库来冒充卸载。只有本应用已合法配置为当前资料的 device/profile owner，并且在凭据 API 中观察到该 CA 时，才具备公开 DPM 自动卸载能力。普通 Magisk / KernelSU / APatch 授权通常仍会显示“可安全自动卸载 0”，批量处理会备份并逐项跳过；请使用对应资料的系统证书设置真正卸载。应用不会自行 provision 设备所有者。此限制符合“无法可靠卸载必须跳过”的要求，也意味着不能声称已自动解决用户设备上的 HyperOS 警告。

清理流程：

1. 第一次确认列出扫描可见数量、用户分布、预计可处理/跳过数量，并提醒 VPN、企业网络和 HTTPS 抓包工具受影响。
2. 重新扫描，为所有用户 CA 的每个已读取 API / 文件来源分别备份原始字节，回读校验证书 DER 指纹和原始字节摘要。中途失败不生成可提交票据，不执行任何卸载，已有备份保留。
3. 第二次确认显示最终捕获的范围、指纹和备份编号，须勾选影响确认。五分钟内有效的内存票据只能使用一次；取消不删除备份。
4. 提交后，在第一次卸载前再次核验全部目标及全部备份。任何目标消失、变化、不可读或备份损坏都会阻止开始删除。
5. 逐张重验 Root、白名单来源和指纹，通过公开 DPM API 卸载可处理项，其他项明确跳过。每次卸载后重新扫描并查凭据 API；一个目标失败会保留备份并继续记录其他目标的结果。
6. 最终重新扫描所有已知可访问来源。残留、不可读或覆盖丢失均不能计为已验证成功。清理检查点在首次卸载前以及每项操作后原子保存；检查点写入失败立即停止，应用重开不会自动重放操作。
7. 建议手动重启，再从“重启后复查／重新扫描”入口检查。使用可读取的系统 `BOOT_COUNT` 与之前检查点比较；不可读时明确报告无法确认重启。比较仍存在的目标、已验证移除后再次出现的目标、模块匹配指纹、新系统来源匹配和重复位置。不会仅凭零计数宣称 HyperOS 警告已经消失。

扫描新增内容：

- `pm list users` 与已知用户存储目录共同发现用户 / 工作资料；每个读取失败的 API 或目录都有覆盖诊断。凭据服务通过当前资料的 AndroidCAStore 查询，并在拥有管理权限时补充 DPM `getInstalledCaCerts`。
- 用户 CA、系统 CA、Root 模块 CA 分别分类。同一证书的 API 别名和实际文件位置均保留，规范列表按来源、用户、指纹去重。重复位置与跨资料同指纹作为诊断，可能是别名或挂载，不据此额外删文件。
- `cacerts-removed` 的可解析证书或空标记仅进入禁用诊断，永不进入清理目标。
- Root 模块只读扫描 `/data/adb/modules/<validated-id>/` 下的 `system/etc/security/cacerts`、`system/system/etc/security/cacerts`、`system/apex/com.android.conscrypt/cacerts`、`apex/com.android.conscrypt/cacerts`、`cacerts`、`certs`、`certificates`。仅接受白名单哈希名或模块内 `.pem/.der/.crt/.cer` 文件名，拒绝符号链接、规范路径变化和遍历。
- 只读检查 `disable` / `remove` 标记，以及固定启动脚本中的 CA / Conscrypt 关键词；不执行脚本，不读取或输出完整脚本。关键词和模块证书副本只说明可能注入，不证明模块正在加载；系统来源中匹配模块的证书仍保留系统分类，绝不删除。
- 自定义模块外置路径、`modules_update`、临时命名空间挂载、私有服务和厂商存储可能未覆盖。无法承诺全设备穷尽发现；无用户 CA 但仍警告时，页面引导检查工作资料、第二空间、设备管理策略和未覆盖来源。

清理实现位于 `domain/Inventory.kt`（来源分类与覆盖证据）、`domain/Cleanup.kt`（全量备份门槛、一次性票据、持久检查点与复查）、`ui/CleanupScreen.kt`。`CleanupTests.kt` 使用离线公开测试证书及伪网关，覆盖来源扫描、批量备份、失败前置阻断、部分成功、残留、中途撤权和重启后复查。实际测试及构建结果见 `VALIDATION.md`。新增测试证书 `cleanup-ca.der` 的私钥已删除，未包含在工程中。


面向 Android 10–16（API 29–36）的本地 CA 证书管理应用。包名 `com.certmanager.android`，Kotlin、Jetpack Compose Material 3、MVVM + Repository、Coroutines + StateFlow。默认简体中文，支持英语、系统/浅色/深色模式及 Android 12+ 动态配色。没有网络权限。

## 构建与交付

需要 JDK 17 或 21、Android SDK Platform 36 和 Build Tools 35.0.0。Android Studio 可直接打开本目录。配置 `ANDROID_HOME` 或本地 `local.properties` 的 `sdk.dir`，然后执行：

```bash
./gradlew testDebugUnitTest
./gradlew assembleDebug
./gradlew lintDebug
```

APK 默认输出 `app/build/outputs/apk/debug/app-debug.apk`。使用 Gradle 8.13 Wrapper（固定官方分发包 SHA-256）、AGP 8.9.2、Kotlin 2.1.20。工程不包含 SDK、下载缓存、签名私钥或环境专用代理配置；首次构建需访问 Google Maven、Maven Central 及 Gradle 分发服务。实际构建结果见 `VALIDATION.md`。

交付 APK 为本环境生成的 **debug 签名**，用于测试，不是发布包。最初的云端构建和交付阶段未创建远程仓库、未使用 CI、未推送或发布 APK。后续按项目所有者授权将源码同步至 GitHub；不包含 GitHub Actions 或 APK 自动发布配置。SDK、构建缓存、签名密钥、真实设备证书和备份不进入仓库；测试目录中仅保留专为离线单元测试生成的公开证书。

## 实现范围与系统限制

| 功能 | 实现方式与边界 |
| --- | --- |
| Root | 按钮请求 `su -c id -u`，适用采用该协议的 Magisk、KernelSU、APatch；每次危险操作重验 UID 0。没有 Root 时应用内只读，可备份、导出、跳转设置。管理器品牌不依赖包名识别。未在真机验证三种管理器。 |
| 当前资料证书 | 官方 `AndroidCAStore`，读取真实 X.509 证书，保留别名及用户 ID。API 可见仅表示当前查询视图，不代表所有应用都信任它。Android 7+ 应用可能通过 network security config 拒绝用户 CA，应用也可能固定公钥。 |
| 多用户/工作资料 | Root 授权后通过 `pm list users` 发现用户，探测每个用户的已知证书目录；资料锁定、SELinux 或厂商策略可能拒绝读取。没有越权跨资料安装/卸载 API。需在对应资料中运行应用完成恢复或进入该资料的设置。 |
| 用户目录 | 探测 `/data/misc/user/<id>/cacerts-{added,removed}`、`/data/misc_ce/<id>/cacerts-{added,removed}` 及 user 0 的旧版 `/data/misc/keychain/…`。探测不等于声明所有版本都使用这些目录。文件必须符合单张证书文件名规范；拒绝符号链接和规范路径不一致。 |
| 系统目录 | 同时探测 `/system/etc/security/cacerts` 与 `/apex/com.android.conscrypt/cacerts`，并与 API 结果按用户、来源和指纹去重。两个目录的相同系统证书优先保留 APEX 来源。始终只读。 |
| 禁用检测 | 可读取 `cacerts-removed` 且可解析其中证书时，按当前用户和证书指纹关联系统 CA。其他情况下明确显示“未确认”，不根据文件缺失推断禁用。 |
| 删除 | 仅允许用户 CA（禁用记录和模块 CA 不属于删除目标）：验证 Root → 验证来源/路径 → 重读指纹 → 原子备份并回读验证 → 用户确认 → 重验 → 操作 → 重新检查。若本应用已经是 device/profile owner，则使用公开 `DevicePolicyManager.uninstallCaCert`；普通安装通常没有此能力，转到系统可信凭据设置由用户卸载。不会自动申请或配置设备所有者。 |
| 删除复查 | API 可见证书在设置返回后再次按指纹查询；仍存在则报告失败并保留备份。仅目录可见的证书无法可靠判断 KeyChain 活跃状态，返回时要求人工核实，不报告删除成功。删除流程不接受系统 CA，不执行文件删除命令。 |
| 导入/恢复 | 支持单张 PEM / DER / CRT / CER CA，校验 Basic Constraints，拒绝私钥及多张证书包；后缀不作为安全依据。按当前用户的证书 DER 指纹查重。恢复原 Android 用户，系统 CA 备份只可导出。操作须 Root 授权及用户确认。 |
| Android 10 安装 | 使用 `KeyChain.createInstallIntent`，仍需用户在系统安装器确认及满足锁屏条件。 |
| Android 11–16 安装 | 官方禁止普通应用通过上述 Intent 安装 CA。先由用户通过 SAF 保存证书，再进入安全设置，手动选择“安装证书 → CA 证书”及刚保存的文件；返回应用后检查目标指纹。不会伪装成静默恢复。取消、策略阻止或未观察到目标指纹时报告失败并保留备份。 |
| 备份 | 应用 `noBackupFilesDir/certificates/` 内 `.cmb` 容器，记录原始读取字节、原始字节 SHA-256、证书 DER SHA-256、来源、用户 ID、读取位置、UUID 和时间。临时文件写入、fsync、原子 rename、回读核验；不支持原子移动时失败关闭。损坏备份保留并报告诊断，其他有效备份仍可读取。 |
| 导出 | SAF 让用户选定位置，不申请广泛存储权限；支持原始证书、标准 PEM 和完整 `.cmb` 备份。完整备份可再次导入，核验后保存为新的本地备份再恢复。 |

**原始字节含义：**能读取磁盘文件时保留该文件的原始 PEM/DER 字节；只能通过 `AndroidCAStore` 读取时，保存系统 API 返回证书的 DER 编码，无法还原原先导入文件的文本排版。来源在详情中可见。

**备份完整性与真实性：**SHA-256 可检测损坏和不一致，不是数字签名，不能证明外部备份来源可信。导入备份仍必须人工审查指纹。备份包含证书及元数据，不收集私钥，也不加密；受 Android 应用沙箱保护。卸载应用会删除私有备份，建议显式导出留存。`allowBackup=false` 且数据提取规则排除备份与设备迁移。

**系统设置入口：**优先使用可解析的可信凭据设置 Intent，否则退回官方 `Settings.ACTION_SECURITY_SETTINGS`。厂商界面和路径可能不同；系统无入口时提供错误提示，需手动进入设置。未使用隐藏 API、反射或修改 APEX、系统分区、SELinux。

## 操作示例

1. 首页刷新，查看实际可见数量；如需完整探测，点击请求 Root 并在管理器中授权。
2. 用户证书页可按名称/到期时间/用户排序，按有效期和用户筛选，搜索 subject、issuer、序列号和指纹。
3. 点卡片查看 X.509 详情、复制指纹、备份或导出。删除前应用先完成并核验备份，再出现确认弹窗；取消会保留备份。
4. 普通安装的删除操作进入系统设置，请核对目标指纹并仅删除该张证书；返回查看复查结果。
5. 备份页恢复时，Android 11+ 会先让你保存 `.crt`，随后在安全设置手动安装，返回核对。

## 结构

- `domain/Certificate.kt`：X.509 解析、PEM 导出、指纹和重复检测。
- `domain/ShellPolicy.kt`：封闭 Root 只读命令类型及精确路径白名单，无任意脚本入口。
- `domain/BackupStore.kt`：有界二进制格式、双摘要校验、原子落盘。
- `domain/Operations.kt`：确认票据、备份前置、危险操作重验及恢复验证，使用可替换网关进行离线测试。
- `data/RootShell.kt`：超时、输出上限、并发排空、进程清理和最多 100 条内存日志；日志不含证书正文、subject 或私钥。
- `data/CertificateRepository.kt`：Android KeyStore、Root 文件探测、用户发现、设备管理能力检测。
- `ui/CertViewModel.kt`：IO 调度、StateFlow 状态与事件通道、串行操作及失败提示。
- `ui/CertApp.kt`：Compose 五页导航、详情、筛选、确认与主题/语言。
- `MainActivity.kt`：SAF、KeyChain、设置入口和外部流程返回检查。

## 测试及真机验收

`app/src/test/resources/test-ca.*` 是专为离线测试生成的公开测试证书，不是设备证书，不能用作可信生产根。测试私钥已删除。测试只操作 TemporaryFolder 与伪网关，不执行 su、不访问 AndroidCAStore、不触碰设备证书。

单元测试覆盖解析、指纹（与独立 OpenSSL 输出比对）、命令参数、路径遍历、原始备份完整性、重复证书、删除失败/授权变化/备份失败/缺少确认、恢复失败/跨用户/重复/系统备份拒绝。实际结果见 `VALIDATION.md`。

仍需在 HyperOS 及 Android 13–16 真机上验证：

- 三种 Root 管理器的授权 UI、拒绝/永久拒绝、超时、授权撤销及 SELinux enforcing 下的读取。
- API 与各目录的实际证书清单；主用户、第二空间、工作资料锁定/解锁与跨资料可见性。
- APEX 更新后证书来源、系统禁用标记、设置入口和厂商差异。
- 备份后在设置中单张卸载，再返回验证；中途取消和系统缓存更新。
- Android 11+ 手动安装/恢复、重复导入、设备策略拒绝、锁屏限制和安装取消。
- 仅在预先配置的测试 device/profile owner 上验证设备管理 API 分支。本应用不会自动 provision，普通用户无需配置。
- 深浅色、动态配色、中英文、大字体、窄屏、旋转、文件选择器返回和进程回收。

外部文件/设置流程的在途数据保留在 ViewModel，可跨一般配置变化。系统杀进程时不会自动重放安装或删除；请重新打开应用刷新并核验。云端 JVM 测试与静态检查不能替代以上真机测试。
