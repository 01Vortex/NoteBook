

> Git 是目前世界上最先进的分布式版本控制系统，由 Linux 之父 Linus Torvalds 创建
> 本笔记涵盖 Git 从入门到进阶的完整知识体系

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [基本操作](#3-基本操作)
4. [分支管理](#4-分支管理)
5. [远程仓库](#5-远程仓库)
6. [标签管理](#6-标签管理)
7. [撤销与回退](#7-撤销与回退)
8. [暂存与清理](#8-暂存与清理)
9. [变基操作](#9-变基操作)
10. [子模块](#10-子模块)
11. [工作流](#11-工作流)
12. [高级技巧](#12-高级技巧)
13. [Git Hooks](#13-git-hooks)
14. [最佳实践](#14-最佳实践)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Git？

Git 是一个分布式版本控制系统。简单来说，它能帮你：
- **记录文件的每次修改**：谁改了什么，什么时候改的
- **回到任意历史版本**：改错了可以"后悔"
- **多人协作开发**：不会互相覆盖代码
- **分支开发**：同时开发多个功能互不影响

### 1.2 Git vs SVN

| 特性 | Git | SVN |
|------|-----|-----|
| 类型 | 分布式 | 集中式 |
| 离线工作 | ✅ 完全支持 | ❌ 需要联网 |
| 分支 | 轻量、快速 | 重量、慢 |
| 存储 | 快照 | 差异 |
| 速度 | 快 | 较慢 |

### 1.3 Git 三个区域

```
工作区（Working Directory）
    ↓ git add
暂存区（Staging Area / Index）
    ↓ git commit
本地仓库（Local Repository）
    ↓ git push
远程仓库（Remote Repository）
```

**工作区**：你实际编辑文件的地方
**暂存区**：准备提交的文件清单（像购物车）
**本地仓库**：提交后的历史记录
**远程仓库**：GitHub/GitLab 等服务器上的仓库

### 1.4 文件状态

```
未跟踪（Untracked）→ 暂存（Staged）→ 已提交（Committed）
                         ↑                    ↓
                    已修改（Modified）←────────┘
```

---

## 2. 安装与配置

### 2.1 安装 Git

**Windows：**
```bash
# 下载安装包
https://git-scm.com/download/win

# 或使用 winget
winget install Git.Git
```

**Linux (Ubuntu/Debian)：**
```bash
sudo apt update
sudo apt install git
```

**Mac：**
```bash
# 使用 Homebrew
brew install git

# 或安装 Xcode Command Line Tools
xcode-select --install
```

**验证安装：**
```bash
git --version
```

### 2.2 基本配置

```bash
# 设置用户名和邮箱（必须！）
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# 查看配置
git config --list
git config user.name

# 配置级别
# --system  系统级（所有用户）
# --global  用户级（当前用户所有仓库）
# --local   仓库级（当前仓库，默认）

# 设置默认编辑器
git config --global core.editor "code --wait"  # VS Code
git config --global core.editor "vim"          # Vim

# 设置默认分支名
git config --global init.defaultBranch main

# 配置别名（提高效率）
git config --global alias.st status
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.ci commit
git config --global alias.lg "log --oneline --graph --all"

# 配置换行符处理
# Windows
git config --global core.autocrlf true
# Mac/Linux
git config --global core.autocrlf input

# 配置凭证存储
git config --global credential.helper store    # 永久存储
git config --global credential.helper cache    # 临时缓存
```

### 2.3 SSH 配置

```bash
# 生成 SSH 密钥
ssh-keygen -t ed25519 -C "your.email@example.com"
# 或使用 RSA
ssh-keygen -t rsa -b 4096 -C "your.email@example.com"

# 查看公钥
cat ~/.ssh/id_ed25519.pub

# 将公钥添加到 GitHub/GitLab
# Settings → SSH Keys → Add SSH Key

# 测试连接
ssh -T git@github.com
ssh -T git@gitlab.com

# 配置多个 SSH 密钥（多账号）
# ~/.ssh/config
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_github

Host gitlab.com
    HostName gitlab.com
    User git
    IdentityFile ~/.ssh/id_ed25519_gitlab
```

---

## 3. 基本操作

### 3.1 创建仓库

```bash
# 初始化新仓库
git init
git init project-name  # 创建目录并初始化

# 克隆远程仓库
git clone https://github.com/user/repo.git
git clone git@github.com:user/repo.git
git clone https://github.com/user/repo.git my-folder  # 指定目录名
git clone --depth 1 https://github.com/user/repo.git  # 浅克隆（只克隆最新版本）
```

### 3.2 查看状态

```bash
# 查看工作区状态
git status
git status -s  # 简洁模式

# 状态标记说明
# ?? - 未跟踪
# A  - 新添加到暂存区
# M  - 修改过
#  M - 修改但未暂存
# MM - 修改后暂存，又修改了
# D  - 删除
```

### 3.3 添加文件

```bash
# 添加单个文件
git add file.txt

# 添加多个文件
git add file1.txt file2.txt

# 添加所有文件
git add .
git add -A
git add --all

# 添加指定类型文件
git add *.js
git add src/

# 交互式添加
git add -p  # 逐块选择要添加的内容
```

### 3.4 提交更改

```bash
# 提交
git commit -m "提交信息"

# 添加并提交（跳过 git add，仅限已跟踪文件）
git commit -am "提交信息"

# 修改最后一次提交
git commit --amend -m "新的提交信息"
git commit --amend --no-edit  # 不修改信息，只添加文件

# 空提交（用于触发 CI）
git commit --allow-empty -m "Trigger CI"
```

### 3.5 查看历史

```bash
# 查看提交历史
git log
git log --oneline           # 单行显示
git log --graph             # 图形化显示
git log --all               # 显示所有分支
git log -n 5                # 最近5条
git log --author="name"     # 按作者筛选
git log --since="2024-01-01"  # 按日期筛选
git log --grep="keyword"    # 按提交信息筛选
git log -- file.txt         # 查看文件历史
git log -p                  # 显示详细差异

# 常用组合
git log --oneline --graph --all --decorate

# 查看某次提交
git show commit_hash
git show HEAD
git show HEAD~2  # 前两次提交

# 查看差异
git diff                    # 工作区 vs 暂存区
git diff --staged           # 暂存区 vs 最新提交
git diff HEAD               # 工作区 vs 最新提交
git diff branch1 branch2    # 两个分支差异
git diff commit1 commit2    # 两次提交差异
git diff -- file.txt        # 指定文件差异
```

### 3.6 .gitignore 文件

`.gitignore` 用于指定不需要 Git 跟踪的文件。

```gitignore
# 注释

# 忽略所有 .log 文件
*.log

# 忽略 node_modules 目录
node_modules/

# 忽略 build 目录
build/
dist/

# 忽略所有 .env 文件
.env
.env.*

# 忽略 IDE 配置
.idea/
.vscode/
*.swp

# 忽略 OS 文件
.DS_Store
Thumbs.db

# 不忽略特定文件（取反）
!important.log

# 忽略根目录下的文件（不递归）
/config.local.js

# 忽略任意目录下的 temp 文件夹
**/temp/

# 忽略 doc 目录下的所有 .pdf 文件
doc/**/*.pdf
```

```bash
# 已跟踪的文件添加到 .gitignore 后不会自动忽略
# 需要先从暂存区移除
git rm --cached file.txt
git rm -r --cached folder/

# 查看被忽略的文件
git status --ignored

# 强制添加被忽略的文件
git add -f ignored_file.txt
```

---

## 4. 分支管理

### 4.1 分支基础

分支是 Git 最强大的功能之一。你可以把分支想象成平行宇宙，每个分支都是独立的开发线。

```bash
# 查看分支
git branch          # 本地分支
git branch -r       # 远程分支
git branch -a       # 所有分支
git branch -v       # 显示最后一次提交

# 创建分支
git branch feature-login

# 切换分支
git checkout feature-login
git switch feature-login      # Git 2.23+ 推荐

# 创建并切换
git checkout -b feature-login
git switch -c feature-login

# 基于特定提交/分支创建
git checkout -b hotfix origin/main
git checkout -b feature abc123

# 重命名分支
git branch -m old-name new-name
git branch -m new-name  # 重命名当前分支

# 删除分支
git branch -d feature-login     # 安全删除（已合并）
git branch -D feature-login     # 强制删除

# 删除远程分支
git push origin --delete feature-login
git push origin :feature-login
```

### 4.2 合并分支

```bash
# 合并分支到当前分支
git merge feature-login

# 合并时创建合并提交（即使可以快进）
git merge --no-ff feature-login

# 合并时压缩提交
git merge --squash feature-login
git commit -m "Merge feature-login"

# 中止合并
git merge --abort
```

**合并类型：**

```
快进合并（Fast-forward）：
main:    A---B
              \
feature:       C---D
合并后：
main:    A---B---C---D

三方合并（3-way merge）：
main:    A---B---E
              \   \
feature:       C---D
合并后：
main:    A---B---E---M（合并提交）
              \     /
feature:       C---D
```

### 4.3 解决冲突

当两个分支修改了同一文件的同一位置时，会产生冲突。

```bash
# 合并时出现冲突
git merge feature
# CONFLICT (content): Merge conflict in file.txt

# 查看冲突文件
git status

# 冲突标记
<<<<<<< HEAD
当前分支的内容
=======
要合并分支的内容
>>>>>>> feature

# 手动解决冲突后
git add file.txt
git commit -m "Resolve merge conflict"

# 使用工具解决冲突
git mergetool

# 选择保留某一方
git checkout --ours file.txt    # 保留当前分支
git checkout --theirs file.txt  # 保留合并分支
```

---

## 5. 远程仓库

### 5.1 远程仓库操作

```bash
# 查看远程仓库
git remote
git remote -v  # 显示 URL

# 添加远程仓库
git remote add origin https://github.com/user/repo.git
git remote add upstream https://github.com/original/repo.git

# 修改远程仓库 URL
git remote set-url origin https://github.com/user/new-repo.git

# 重命名远程仓库
git remote rename origin old-origin

# 删除远程仓库
git remote remove origin

# 查看远程仓库信息
git remote show origin
```

### 5.2 推送与拉取

```bash
# 推送到远程
git push origin main
git push -u origin main  # 设置上游分支（首次推送）
git push                 # 已设置上游后可省略

# 推送所有分支
git push --all origin

# 推送标签
git push origin v1.0.0
git push --tags

# 强制推送（危险！会覆盖远程）
git push -f origin main
git push --force-with-lease  # 更安全的强制推送

# 拉取远程更新
git fetch origin           # 只获取，不合并
git fetch --all            # 获取所有远程
git fetch --prune          # 清理已删除的远程分支

# 拉取并合并
git pull origin main
git pull                   # 已设置上游后可省略
git pull --rebase          # 使用变基而非合并

# 等价于
git fetch origin
git merge origin/main
```

### 5.3 跟踪分支

```bash
# 设置跟踪关系
git branch --set-upstream-to=origin/main main
git branch -u origin/main

# 查看跟踪关系
git branch -vv

# 创建跟踪分支
git checkout --track origin/feature
git checkout -b feature origin/feature
```

### 5.4 Fork 工作流

```bash
# 1. Fork 原仓库到自己账号

# 2. 克隆自己的仓库
git clone git@github.com:your-name/repo.git

# 3. 添加上游仓库
git remote add upstream git@github.com:original/repo.git

# 4. 同步上游更新
git fetch upstream
git checkout main
git merge upstream/main

# 5. 推送到自己的仓库
git push origin main

# 6. 创建 Pull Request
```

---

## 6. 标签管理

标签用于标记重要的版本节点，如发布版本。

```bash
# 查看标签
git tag
git tag -l "v1.*"  # 筛选

# 创建轻量标签
git tag v1.0.0

# 创建附注标签（推荐）
git tag -a v1.0.0 -m "Release version 1.0.0"

# 给历史提交打标签
git tag -a v0.9.0 abc123 -m "Beta release"

# 查看标签信息
git show v1.0.0

# 推送标签
git push origin v1.0.0
git push origin --tags  # 推送所有标签

# 删除标签
git tag -d v1.0.0              # 删除本地
git push origin --delete v1.0.0  # 删除远程
git push origin :refs/tags/v1.0.0

# 检出标签
git checkout v1.0.0            # 分离头指针状态
git checkout -b release-1.0 v1.0.0  # 基于标签创建分支
```

---

## 7. 撤销与回退

### 7.1 撤销工作区修改

```bash
# 撤销单个文件的修改
git checkout -- file.txt
git restore file.txt  # Git 2.23+ 推荐

# 撤销所有修改
git checkout -- .
git restore .

# 撤销删除的文件
git checkout -- deleted_file.txt
git restore deleted_file.txt
```

### 7.2 撤销暂存

```bash
# 取消暂存（保留修改）
git reset HEAD file.txt
git restore --staged file.txt  # Git 2.23+ 推荐

# 取消所有暂存
git reset HEAD
git restore --staged .
```

### 7.3 撤销提交

```bash
# 修改最后一次提交
git commit --amend -m "新信息"

# 撤销提交（保留修改在工作区）
git reset --soft HEAD~1

# 撤销提交（保留修改在暂存区）
git reset --mixed HEAD~1  # 默认

# 撤销提交（丢弃修改）
git reset --hard HEAD~1

# 回退到指定提交
git reset --hard abc123

# 创建新提交来撤销（安全，不改变历史）
git revert HEAD
git revert abc123
git revert HEAD~3..HEAD  # 撤销多个提交
```

**reset 三种模式对比：**

| 模式 | HEAD | 暂存区 | 工作区 |
|------|------|--------|--------|
| --soft | ✅ 移动 | ❌ 不变 | ❌ 不变 |
| --mixed | ✅ 移动 | ✅ 重置 | ❌ 不变 |
| --hard | ✅ 移动 | ✅ 重置 | ✅ 重置 |

### 7.4 恢复丢失的提交

```bash
# 查看所有操作记录（包括已删除的提交）
git reflog

# 恢复到某个状态
git reset --hard HEAD@{2}
git checkout -b recovery HEAD@{2}

# 找回删除的分支
git reflog
git checkout -b recovered-branch abc123
```

---

## 8. 暂存与清理

### 8.1 Stash 暂存

当你需要临时切换分支但不想提交当前修改时，可以使用 stash。

```bash
# 暂存当前修改
git stash
git stash save "描述信息"
git stash push -m "描述信息"

# 暂存包括未跟踪文件
git stash -u
git stash --include-untracked

# 暂存所有文件（包括忽略的）
git stash -a
git stash --all

# 查看暂存列表
git stash list

# 恢复暂存
git stash pop              # 恢复并删除
git stash apply            # 恢复但保留
git stash apply stash@{2}  # 恢复指定暂存

# 查看暂存内容
git stash show
git stash show -p          # 详细差异
git stash show stash@{1}

# 删除暂存
git stash drop             # 删除最新
git stash drop stash@{2}   # 删除指定
git stash clear            # 清空所有

# 从暂存创建分支
git stash branch new-branch
```

### 8.2 清理工作区

```bash
# 查看将被清理的文件
git clean -n
git clean --dry-run

# 清理未跟踪文件
git clean -f

# 清理未跟踪文件和目录
git clean -fd

# 清理包括忽略的文件
git clean -fdx

# 交互式清理
git clean -i
```

---

## 9. 变基操作

### 9.1 基本变基

变基（Rebase）可以让提交历史更加线性、整洁。

```bash
# 将当前分支变基到 main
git rebase main

# 变基过程中解决冲突
# 1. 解决冲突
# 2. git add .
# 3. git rebase --continue

# 跳过当前提交
git rebase --skip

# 中止变基
git rebase --abort
```

**Merge vs Rebase：**

```
Merge（合并）：
main:    A---B---C---M
              \     /
feature:       D---E

Rebase（变基）：
main:    A---B---C
                  \
feature:           D'---E'
```

### 9.2 交互式变基

交互式变基可以修改、合并、删除、重排提交。

```bash
# 交互式变基最近 3 个提交
git rebase -i HEAD~3

# 变基到某个提交
git rebase -i abc123
```

**交互式变基命令：**
```
pick   - 保留提交
reword - 修改提交信息
edit   - 修改提交内容
squash - 合并到前一个提交
fixup  - 合并到前一个提交（丢弃信息）
drop   - 删除提交
```

```bash
# 示例：合并最近 3 个提交
git rebase -i HEAD~3

# 编辑器中：
pick abc123 First commit
squash def456 Second commit
squash ghi789 Third commit

# 保存后编辑合并后的提交信息
```

### 9.3 变基注意事项

```bash
# ⚠️ 黄金法则：不要变基已推送的公共分支！

# 如果已经推送，需要强制推送
git push --force-with-lease

# 团队协作时，其他人需要：
git fetch origin
git reset --hard origin/branch
```

---

## 10. 子模块

子模块允许你将一个 Git 仓库作为另一个仓库的子目录。

```bash
# 添加子模块
git submodule add https://github.com/user/repo.git path/to/submodule

# 克隆包含子模块的仓库
git clone --recursive https://github.com/user/repo.git
# 或
git clone https://github.com/user/repo.git
git submodule init
git submodule update

# 更新子模块
git submodule update --remote
git submodule update --remote --merge

# 查看子模块状态
git submodule status

# 遍历所有子模块执行命令
git submodule foreach 'git pull origin main'

# 删除子模块
git submodule deinit path/to/submodule
git rm path/to/submodule
rm -rf .git/modules/path/to/submodule
```

---

## 11. 工作流

### 11.1 Git Flow

适合有计划发布周期的项目。

```
main        ─────●─────────────●─────────────●─────
                 │             │             │
hotfix      ─────┼─────●───────┼─────────────┼─────
                 │     │       │             │
release     ─────┼─────┼───●───┼─────────────┼─────
                 │     │   │   │             │
develop     ─────●─────●───●───●─────●───────●─────
                 │         │         │       │
feature     ─────●─────────●─────────●───────┼─────
```

```bash
# 安装 git-flow
# Mac: brew install git-flow
# Windows: 包含在 Git for Windows 中

# 初始化
git flow init

# 功能分支
git flow feature start login
git flow feature finish login

# 发布分支
git flow release start 1.0.0
git flow release finish 1.0.0

# 热修复分支
git flow hotfix start fix-bug
git flow hotfix finish fix-bug
```

### 11.2 GitHub Flow

更简单的工作流，适合持续部署。

```bash
# 1. 从 main 创建分支
git checkout -b feature-xxx

# 2. 开发并提交
git add .
git commit -m "Add feature"

# 3. 推送分支
git push -u origin feature-xxx

# 4. 创建 Pull Request

# 5. 代码审查

# 6. 合并到 main

# 7. 删除分支
git branch -d feature-xxx
git push origin --delete feature-xxx
```

### 11.3 Trunk Based Development

所有开发者都在主干（main/trunk）上工作。

```bash
# 特点：
# - 短生命周期的功能分支（< 1天）
# - 频繁集成到主干
# - 使用功能开关控制未完成功能
# - 适合持续集成/持续部署
```

---

## 12. 高级技巧

### 12.1 Cherry-pick

选择性地将某个提交应用到当前分支。

```bash
# 应用单个提交
git cherry-pick abc123

# 应用多个提交
git cherry-pick abc123 def456

# 应用一系列提交
git cherry-pick abc123..def456

# 不自动提交
git cherry-pick -n abc123

# 解决冲突后继续
git cherry-pick --continue

# 中止
git cherry-pick --abort
```

### 12.2 Bisect 二分查找

用于快速定位引入 bug 的提交。

```bash
# 开始二分查找
git bisect start

# 标记当前版本有问题
git bisect bad

# 标记某个版本正常
git bisect good v1.0.0

# Git 会自动切换到中间提交
# 测试后标记
git bisect good  # 或 git bisect bad

# 重复直到找到问题提交

# 结束查找
git bisect reset

# 自动化测试
git bisect run npm test
```

### 12.3 Blame 追溯

查看文件每一行的最后修改者。

```bash
# 查看文件每行的修改信息
git blame file.txt

# 查看指定行范围
git blame -L 10,20 file.txt

# 忽略空白变化
git blame -w file.txt

# 显示原始提交（跟踪代码移动）
git blame -C file.txt
```

### 12.4 Worktree 工作树

同时在多个分支上工作，无需切换。

```bash
# 创建新工作树
git worktree add ../project-feature feature-branch
git worktree add ../project-hotfix -b hotfix

# 查看工作树
git worktree list

# 删除工作树
git worktree remove ../project-feature

# 清理
git worktree prune
```

### 12.5 搜索

```bash
# 搜索提交信息
git log --grep="bug fix"

# 搜索代码变更
git log -S "function_name"  # 添加或删除了该字符串
git log -G "regex"          # 正则匹配

# 搜索文件内容
git grep "pattern"
git grep -n "pattern"       # 显示行号
git grep -c "pattern"       # 统计次数
git grep "pattern" v1.0.0   # 在特定版本搜索
```

---

## 13. Git Hooks

Git Hooks 是在特定事件发生时自动执行的脚本。

### 13.1 常用 Hooks

```bash
# 客户端 Hooks（.git/hooks/）
pre-commit      # 提交前执行
prepare-commit-msg  # 准备提交信息
commit-msg      # 验证提交信息
post-commit     # 提交后执行
pre-push        # 推送前执行

# 服务端 Hooks
pre-receive     # 接收推送前
update          # 更新引用前
post-receive    # 接收推送后
```

### 13.2 Hook 示例

```bash
# .git/hooks/pre-commit
#!/bin/sh

# 运行代码检查
npm run lint
if [ $? -ne 0 ]; then
    echo "Lint failed. Commit aborted."
    exit 1
fi

# 运行测试
npm test
if [ $? -ne 0 ]; then
    echo "Tests failed. Commit aborted."
    exit 1
fi

exit 0
```

```bash
# .git/hooks/commit-msg
#!/bin/sh

# 验证提交信息格式
commit_msg=$(cat "$1")
pattern="^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?: .{1,50}"

if ! echo "$commit_msg" | grep -qE "$pattern"; then
    echo "Invalid commit message format!"
    echo "Format: type(scope): message"
    echo "Types: feat, fix, docs, style, refactor, test, chore"
    exit 1
fi

exit 0
```

### 13.3 使用 Husky（推荐）

```bash
# 安装 Husky
npm install husky -D
npx husky install

# 添加 hook
npx husky add .husky/pre-commit "npm run lint"
npx husky add .husky/commit-msg 'npx commitlint --edit "$1"'

# package.json
{
  "scripts": {
    "prepare": "husky install"
  }
}
```

---

## 14. 最佳实践

### 14.1 提交信息规范

```bash
# Conventional Commits 格式
<type>(<scope>): <subject>

<body>

<footer>

# 类型
feat:     新功能
fix:      修复 bug
docs:     文档更新
style:    代码格式（不影响功能）
refactor: 重构
test:     测试相关
chore:    构建/工具相关
perf:     性能优化
ci:       CI 配置

# 示例
feat(auth): add login functionality

Implement user login with JWT authentication.
- Add login API endpoint
- Add JWT token generation
- Add password hashing

Closes #123
```

### 14.2 分支命名规范

```bash
# 功能分支
feature/user-login
feature/JIRA-123-payment

# 修复分支
fix/login-bug
bugfix/JIRA-456-crash

# 热修复
hotfix/security-patch

# 发布分支
release/1.0.0
release/2024-01

# 个人分支
user/john/experiment
```

### 14.3 其他最佳实践

```bash
# 1. 频繁提交，小步快跑
# 每个提交只做一件事

# 2. 写好提交信息
# 说明为什么改，而不只是改了什么

# 3. 保持分支整洁
# 及时删除已合并的分支

# 4. 使用 .gitignore
# 不要提交生成的文件、依赖、敏感信息

# 5. 代码审查
# 使用 Pull Request 进行代码审查

# 6. 保护主分支
# 禁止直接推送到 main/master

# 7. 使用标签标记版本
git tag -a v1.0.0 -m "Release 1.0.0"
```

---

## 15. 常见错误与解决方案

### 15.1 提交相关错误

**错误：提交信息写错了**
```bash
# 修改最后一次提交信息
git commit --amend -m "正确的信息"

# 修改更早的提交信息
git rebase -i HEAD~3
# 将 pick 改为 reword
```

**错误：提交了不该提交的文件**
```bash
# 从最后一次提交中移除文件（保留文件）
git reset --soft HEAD~1
git reset HEAD unwanted_file.txt
git commit -m "提交信息"

# 从历史中完全删除文件（如密码）
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch path/to/file' \
  --prune-empty --tag-name-filter cat -- --all

# 或使用 BFG（更快）
bfg --delete-files password.txt
```

**错误：提交到了错误的分支**
```bash
# 方法一：cherry-pick
git checkout correct-branch
git cherry-pick abc123
git checkout wrong-branch
git reset --hard HEAD~1

# 方法二：如果还没推送
git reset --soft HEAD~1
git stash
git checkout correct-branch
git stash pop
git commit -m "提交信息"
```

### 15.2 分支相关错误

**错误：删除了还需要的分支**
```bash
# 查找分支最后的提交
git reflog

# 恢复分支
git checkout -b recovered-branch abc123
```

**错误：在错误的分支上工作了**
```bash
# 还没提交
git stash
git checkout correct-branch
git stash pop

# 已经提交
git checkout correct-branch
git cherry-pick abc123
git checkout wrong-branch
git reset --hard HEAD~1
```

### 15.3 合并相关错误

**错误：合并后发现有问题**
```bash
# 还没推送，撤销合并
git reset --hard HEAD~1
# 或
git reset --hard ORIG_HEAD

# 已经推送，创建反向提交
git revert -m 1 HEAD
```

**错误：合并冲突太多，想放弃**
```bash
git merge --abort
git rebase --abort
```

### 15.4 远程相关错误

**错误：推送被拒绝（non-fast-forward）**
```bash
# 原因：远程有新提交

# 方法一：先拉取再推送
git pull --rebase origin main
git push origin main

# 方法二：强制推送（危险！）
git push -f origin main
```

**错误：拉取时有冲突**
```bash
# 方法一：解决冲突
git pull origin main
# 解决冲突
git add .
git commit -m "Resolve conflicts"

# 方法二：使用变基
git pull --rebase origin main
# 解决冲突
git add .
git rebase --continue
```

**错误：克隆太慢/失败**
```bash
# 浅克隆
git clone --depth 1 https://github.com/user/repo.git

# 只克隆单个分支
git clone --single-branch --branch main https://github.com/user/repo.git

# 使用 SSH 代替 HTTPS
git clone git@github.com:user/repo.git
```

### 15.5 其他常见错误

**错误：fatal: not a git repository**
```bash
# 原因：当前目录不是 Git 仓库
# 解决：初始化或进入正确目录
git init
# 或
cd /path/to/repo
```

**错误：Permission denied (publickey)**
```bash
# 原因：SSH 密钥未配置或未添加到 GitHub

# 检查 SSH 密钥
ls -la ~/.ssh

# 生成新密钥
ssh-keygen -t ed25519 -C "email@example.com"

# 添加到 ssh-agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# 将公钥添加到 GitHub
cat ~/.ssh/id_ed25519.pub
```

**错误：fatal: refusing to merge unrelated histories**
```bash
# 原因：两个仓库没有共同祖先
git pull origin main --allow-unrelated-histories
```

**错误：error: Your local changes would be overwritten**
```bash
# 原因：本地有未提交的修改

# 方法一：暂存修改
git stash
git pull
git stash pop

# 方法二：提交修改
git add .
git commit -m "WIP"
git pull

# 方法三：放弃修改
git checkout -- .
git pull
```

**错误：detached HEAD**
```bash
# 原因：检出了特定提交而非分支

# 查看当前状态
git status

# 创建新分支保存工作
git checkout -b new-branch

# 或回到分支
git checkout main
```

---

## 附录：命令速查表

```bash
# ========== 配置 ==========
git config --global user.name "name"
git config --global user.email "email"

# ========== 基本操作 ==========
git init                    # 初始化
git clone <url>             # 克隆
git add <file>              # 添加到暂存区
git commit -m "msg"         # 提交
git status                  # 查看状态
git log --oneline           # 查看历史

# ========== 分支 ==========
git branch                  # 查看分支
git branch <name>           # 创建分支
git checkout <branch>       # 切换分支
git checkout -b <branch>    # 创建并切换
git merge <branch>          # 合并分支
git branch -d <branch>      # 删除分支

# ========== 远程 ==========
git remote -v               # 查看远程
git fetch                   # 获取远程
git pull                    # 拉取并合并
git push                    # 推送

# ========== 撤销 ==========
git restore <file>          # 撤销修改
git restore --staged <file> # 取消暂存
git reset --soft HEAD~1     # 撤销提交（保留修改）
git reset --hard HEAD~1     # 撤销提交（丢弃修改）
git revert <commit>         # 创建反向提交

# ========== 暂存 ==========
git stash                   # 暂存
git stash pop               # 恢复
git stash list              # 列表

# ========== 标签 ==========
git tag                     # 查看标签
git tag -a v1.0 -m "msg"    # 创建标签
git push --tags             # 推送标签
```

---

> 💡 **学习建议**：
> 1. 先掌握基本操作：add、commit、push、pull
> 2. 理解分支概念，多练习分支操作
> 3. 学会解决冲突，这是必备技能
> 4. 了解工作流，选择适合团队的方式
> 5. 遇到问题先 `git status`，再 `git reflog`
