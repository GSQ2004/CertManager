# CertManager

面向已 Root Android 设备的原生 CA 证书管理器，重点适配小米 HyperOS。Kotlin、Jetpack Compose、Material 3、MVVM / Repository、Coroutines / StateFlow。默认简体中文，支持英文、浅色/深色和 Material You 动态配色。

## 1.2.0：受控 Root 文件级卸载

修复原来的统一阻止逻辑：`canUninstall()` 不再把 Device/Profile Owner 视为所有来源的前提。按**证书实际来源与运行时证据**选择策略：

| 来源 | 处理方式 |
| --- | --- |
| 已验证传统 `/data/misc/user/<userId>/cacerts-added/<hash>.<index>` 文件 | 原生守卫复核通过后，提供 **Root 文件级卸载**与恢复；实现待真机验证 |
| 凭据服务 / AndroidCAStore 独有来源 | 已具备合法 Device/Profile Owner 能力时使用公开 DPM API；否则使用对应资料的系统设置 |
| 系统 CA / Conscrypt APEX | 只读浏览、导出、备份，绝不改分区 |
| Root 模块证书、覆盖挂载或匹配到模块副本的用户 CA | 不自动移出，提示检查模块 |
| 未知来源、元数据不可读、用户未验证、原生助手不可用 | 阻止 Root 修改；允许可行的只读备份与系统设置入口 |

不会自动 provision 设备所有者，不调用私有 Binder 事务，不修改系统数据库，不 Hook 或隐藏警告，不关闭 SELinux / Verified Boot，不自动重启。

### 用户提供的 HyperOS 真机证据

用户报告：在 Android 17 / API 37、HyperOS、KernelSU（Root 上下文 `u:r:ksu:s0`）、用户 0 上，将一张传统用户 CA 从 `cacerts-added` 移到其他目录并重启后，CA 安全警告消失。

这是**此前手动方案的真机结果**，不是本版本应用代码的真机验收。未把目标 Subject、历史指纹或文件名写入业务逻辑，也未提交用户证书或设备日志。该案例不能证明所有 Android 17 / HyperOS 设备适用。

### 卸载的安全链路

1. 验证 Root UID 0，并由 `cmd user list` 核实用户；验证来源与精确文件路径。
2. 用随 APK 构建的 JNI 守卫读取文件：逐级 `openat(O_DIRECTORY | O_NOFOLLOW)` 固定父目录，拒绝符号链接、非普通文件、多硬链接、不安全权限和非预期所有者（当前仅接受文件 UID 0 / 1000）。
3. 仅接受 ext4 / f2fs 的传统目录；检测目标、证书目录或用户目录上的额外挂载，拒绝覆盖挂载及未知文件系统。
4. 解析 X.509，计算 **DER SHA-256 指纹**，与所选证书匹配；原始文件 SHA-256 单独记录。
5. 原子创建 UUID 私有备份并 fsync / 回读：原始字节、来源、用户、原始路径（含文件名）、指纹、原始哈希、UID/GID、权限、SELinux 上下文、设备/ inode / 时间 / 父目录身份、备份版本和时间。v2 另校验元数据摘要，兼容 v1。
6. 显示证书名称、指纹、用户、路径、备份编号、策略及风险，等待明确确认。批量还有范围确认与影响勾选；票据五分钟内一次有效。
7. 在特权进程内再次验证备份指纹，原生代码重读原始字节、核对元数据及文件身份，复核父目录仍是原目录。
8. 使用 `renameat2(RENAME_NOREPLACE)` 移至同用户下的 `/data/misc/user/<id>/certmanager-quarantine/<backup-UUID>.removed`。隔离区必须 root 所有、0700 且同文件系统。拒绝覆盖与 EXDEV，**不做跨文件系统复制后删除**，不运行 `rm`。
9. 原子移出后核对实际移出对象的 inode 与字节；若发现路径替换则回滚，若原位置已被占用则保留隔离对象并报告人工处理路径，不覆盖新对象。提交后 fsync 并复查活动位置；发现重新出现即报错，不自动重试。
10. 扫描所有可见来源，分别记录备份校验、已移出数量、未处理/失败、活动目录复查、重启后复查与用户手动确认警告消失。缓存中的 CA 可能仍可见；**文件移出不等于系统警告消失**。

目录描述符、原子禁止覆盖和提交后对象核验用于防止常见路径替换；检测到变化或无法验证时中止，必要时保留隔离对象和私有备份。无法防御另一个拥有同等 Root 权限、持续恶意改写系统的进程。不要与其他 CA 管理器同时修改同一资料；并发和掉电恢复仍需真机验证。

隔离区是保留原文件的 root 私有区域，不替代应用私有备份。不会自动清理该区域。应用卸载会清除私有备份；请先导出 `.cmb`。

### 恢复

带文件元数据的备份使用 `RootFileCertificateRestorer`：读取并校验 → 核实原用户 → 检查目标不存在及同资料重复证书 → 显示确认 → 在同文件系统的 root 私有隔离区创建独占暂存文件 → 写入/校验 → 恢复 UID/GID、权限、原 SELinux 上下文 → 校验并 fsync → 原子禁止覆盖发布 → 重新读取验证。权限、上下文、重复检测或目标检查失败均中止并保留备份；发布前失败的暂存文件保留在隔离区并报告位置，不在活动 CA 目录留下半成品，也不执行名字有竞态风险的 unlink。不覆盖现有对象。发布后异常会报告失败/未确认，不能假定文件未写入。

旧 v1 或无文件元数据的用户 CA 备份使用原资料的系统安装流程。系统和模块备份只允许导出。Root 恢复无需将文件写到当前资料，始终验证备份中的原用户和白名单目标；不支持安全条件不明的跨存储恢复。可能需要重启。

## 功能

- 显式 su 检测/授权、UID 0 验证、SELinux 上下文、超时、stdout / stderr / 退出码、最多 100 条结果日志；拒绝或超时进入只读模式。
- AndroidCAStore、具备合法资格时的凭据 API、多用户传统目录、misc_ce、旧 keychain、system 和 Conscrypt APEX 发现；读取失败保留“未知”覆盖状态。
- 用户 / 系统 / 模块 CA 分类；系统禁用标记诊断；按用户、来源、指纹去重并保留所有位置，重复及跨资料证书诊断。
- Subject、Issuer、序列号、有效期、DER SHA-256、签名与公钥算法、Basic Constraints、Key Usage、Extended Key Usage、用户及全部来源。
- 搜索、排序、状态/用户筛选、复制指纹、PEM / DER 导出、原始备份导出、单张及批量备份、单张及逐项批量卸载、备份恢复。
- SAF 导入 PEM / DER / CRT / CER 或 `.cmb`，最大约 1 MiB，拒绝私钥与证书 bundle，检查 CA 属性和重复证书。安装前显示详情与信任风险。
- Android 10 使用系统 `KeyChain.createInstallIntent`；Android 11+ 普通应用不能用它直接安装 CA，因此先通过 SAF 保存文件，再打开系统安全设置，由用户选择“安装 CA 证书”。返回后检查安装结果，取消不会报告成功。
- 首页“CA 安全警告处理”：可见用户 CA、可处理/受限项、多资料、模块线索、逐项清理结果、重新扫描、重启后复查、警告消失的用户确认。绝不隐藏系统警告。

## 系统与工具链

- minSdk 29（Android 10），目标运行范围 Android 13–17；当前包含 **arm64-v8a / x86_64** 两种原生库，32 位设备暂不支持。
- compile / target SDK **36**：沿用已有稳定 API 36 行为，并升级 AGP 到支持 API 36 的 8.11.1。API 37 设备可以运行 target 36 应用；没有用未经验证的 API 37 私有接口代替运行时检查。Android 17 真机适配仍以本应用实测为准。
- Gradle Wrapper 8.13（包含 JAR、固定 SHA-256）、Kotlin 2.1.20、Compose BOM 2025.04.01、JDK 17、build-tools 36.0.0、NDK 27.2.12479018、CMake 3.22.1。保留原项目其余稳定依赖。
- 原生库使用 16 KiB ELF segment 对齐、静态 libc++，APK 提取原生库供 root `app_process` 使用。
- Magisk / KernelSU / APatch 使用通用 `su -c`。命令封闭且参数白名单，修改只在 JNI 守卫中完成，不依赖 shell 的 `mv` 参数差异。原生助手由安装 APK 的 classpath 启动，不能从任意目录加载代码；原生加载/SELinux 不兼容时禁用文件级操作。

## 本地编译与安装

```sh
sdkmanager 'platforms;android-36' 'build-tools;36.0.0' 'ndk;27.2.12479018' 'cmake;3.22.1' 'platform-tools'
# 设置 ANDROID_HOME 或在未提交的 local.properties 写 sdk.dir
chmod +x gradlew
./gradlew --no-daemon testDebugUnitTest lintDebug assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Android Studio 打开工程根目录并同步。首次需要访问 Google Maven、Maven Central 和 Gradle 分发服务。APK：`app/build/outputs/apk/debug/app-debug.apk`；测试与 Lint 报告：`app/build/reports/`。未执行的真机检查不能由构建结果代替，见 [VALIDATION.md](VALIDATION.md)。

## APK 下载与发布

从 [GitHub Releases](https://github.com/GSQ2004/CertManager/releases) 下载对应版本的 APK 和同页的 `SHA256SUMS.txt`。在下载目录运行 `sha256sum -c SHA256SUMS.txt` 可核对文件完整性。

普通推送、拉取请求和手动运行会执行单元测试、Lint 和 APK 构建。发布时，先更新应用版本，再推送对应的版本标签（例如 `v1.2.2`）。标签工作流通过检查后，会把 APK 和校验文件直接上传到 GitHub 预发布页面。Actions 保留构建日志和验证报告。

### 签名与升级

当前预发布 APK 使用 CI 调试签名。不同构建的签名可能不同，若系统提示签名不兼容，请先导出全部私有备份，再卸载旧版并安装新包。独立 Release 签名的配置见 [app/build.gradle.kts](app/build.gradle.kts)。

## 测试、结构与截图

保留原 40 项 JVM 测试，新增 24 项 Root 文件边界与失败注入测试（共 64 项），包含文件身份变化、符号链接/非普通文件拒绝的边界错误、移动/EXDEV 失败、损坏备份、目标已存在、权限和 SELinux 恢复失败、Root 拒绝/超时、多用户、重复、重现、重启复查及确认状态。所有测试使用公开测试 CA、TemporaryFolder 与可注入网关/进程，不修改真实设备 CA。原生代码交叉编译不等于已在 Android 上验证其 syscalls。

主要实现：

- `domain/RootFiles.kt`：文件策略、元数据、卸载与一次性恢复票据。
- `data/RootFileStore.kt`、`RootWorker.kt`、`src/main/cpp/certguard.cpp`：受控特权进程与原生文件守卫。
- `domain/BackupStore.kt`：v1/v2 原子备份和完整性校验。
- `domain/Operations.kt`、`Cleanup.kt`：单张/批量预检、确认与持久结果。
- `data/CertificateRepository.kt`：真实来源发现、运行时策略与系统 API。
- `ui/CertViewModel.kt`、`CertApp.kt`、`CleanupScreen.kt`：Material 3 页面、风险确认、结果与诊断。

截图说明见 [docs/screenshots/README.md](docs/screenshots/README.md)。没有用原型或模拟证书截图冒充真机运行。

## 已知限制与待真机验证

- 本版本应用 Root 卸载、恢复、JNI 加载、KernelSU / Magisk / APatch、HyperOS 设置入口和 Android 13–17 行为均 **待真机验证**。此前手动移出案例与本应用实现严格区分。
- 普通应用不能遍历全部凭据服务；锁定资料、SELinux、其他挂载命名空间、私有数据库和自定义模块来源可能不可见。可见 CA 为 0 不证明警告消失。
- 模块诊断仅检查白名单目录、disable/remove 标记与固定启动脚本关键词，不执行模块脚本，不证明模块当前已注入；持续注入可能使 CA 重启后重新出现。
- `cacerts-removed` 是禁用标记，不保证厂商/Conscrypt 的实际状态；禁用和系统 CA 恢复均不提供虚假按钮。
- 系统缓存、设备管理、企业资料和第二空间可能使警告延迟或由其他 CA 触发。清理后仍有警告时检查覆盖信息、其他资料和模块，不隐藏提示或重复盲删。
- 非 ext4/f2fs、符号链接、额外目标/目录挂载、原子 rename 不支持、元数据不可读或无法恢复 SELinux 时拒绝 Root 文件操作。跨文件系统移动明确失败，不实现复制后删除降级。
- 根权限下的 APK / JNI 加载策略可能被 OEM SELinux 阻止；这会导致候选不可操作，不能通过关闭 SELinux 绕过。
- Root 原子移动不更新厂商私有凭据数据库。应用会标明活动文件移出、保留备份并要求重启复查，不能宣称通用官方卸载成功。
- 批量历史保存最近一轮检查点；进程中断可能显示 PENDING / FAILED / 未确认，不能自动重放操作。私有备份与 root 隔离原件保留；请刷新核对、导出备份，必要时人工处理。
- `.cmb` 哈希检测意外损坏，不提供来源签名或加密；只恢复可信备份，核对指纹。卸载/清除数据会删除私有备份。
- 安装用户 CA 不代表所有应用信任它：Network Security Config、自有库和证书固定都可能影响信任。

## 安全警告

安装 CA 会扩大资料信任范围，恶意 CA 可能使受其信任的连接被拦截；卸载可能导致企业资料、应用或网络不可用。只管理自己有权管理的设备，核对指纹，保留离线备份，并在测试设备先验证。不要同时运行其他证书修改工具。云端构建和 JVM 测试不能替代真机验收。

MIT License，见 [LICENSE](LICENSE)。
