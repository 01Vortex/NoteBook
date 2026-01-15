
> Android 是 Google 开发的移动操作系统，基于 Linux 内核
> 本笔记基于 Android Studio Hedgehog / Kotlin 1.9+ / Jetpack Compose

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [项目结构](#3-项目结构)
4. [Activity 与生命周期](#4-activity-与生命周期)
5. [布局与视图](#5-布局与视图)
6. [Jetpack Compose](#6-jetpack-compose)
7. [导航与路由](#7-导航与路由)
8. [数据存储](#8-数据存储)
9. [网络请求](#9-网络请求)
10. [依赖注入](#10-依赖注入)
11. [异步编程](#11-异步编程)
12. [权限管理](#12-权限管理)
13. [服务与广播](#13-服务与广播)
14. [性能优化](#14-性能优化)
15. [打包发布](#15-打包发布)
16. [常见错误与解决方案](#16-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Android？

Android 是一个基于 Linux 内核的开源移动操作系统，主要用于触屏设备如智能手机和平板电脑。它由 Google 主导开发，是目前全球市场份额最大的移动操作系统。

**Android 开发的特点**：
- **开源免费**：任何人都可以查看和修改源代码
- **Java/Kotlin**：主要使用 Kotlin（推荐）或 Java 开发
- **丰富的 API**：提供大量系统级 API
- **Google Play**：全球最大的应用商店之一
- **碎片化**：需要适配多种设备和系统版本

### 1.2 Android 架构

```
┌─────────────────────────────────────────────┐
│              应用层 (Applications)           │
│    电话、短信、浏览器、相机、你的应用...        │
├─────────────────────────────────────────────┤
│           应用框架层 (Application Framework)  │
│  Activity Manager、Window Manager、          │
│  Content Providers、View System...           │
├─────────────────────────────────────────────┤
│              系统运行库层 (Libraries)         │
│  Android Runtime (ART)、SQLite、OpenGL...    │
├─────────────────────────────────────────────┤
│           硬件抽象层 (HAL)                    │
│  Audio、Bluetooth、Camera、Sensors...        │
├─────────────────────────────────────────────┤
│              Linux 内核 (Kernel)             │
│  驱动程序、电源管理、内存管理...               │
└─────────────────────────────────────────────┘
```

### 1.3 四大组件

Android 应用由四大核心组件构成：

| 组件 | 说明 | 用途 |
|------|------|------|
| Activity | 用户界面 | 一个屏幕/页面 |
| Service | 后台服务 | 后台任务、音乐播放 |
| BroadcastReceiver | 广播接收器 | 接收系统/应用广播 |
| ContentProvider | 内容提供者 | 应用间数据共享 |

### 1.4 Kotlin vs Java

Google 在 2019 年宣布 Kotlin 为 Android 开发的首选语言：

| 特性 | Kotlin | Java |
|------|--------|------|
| 空安全 | 内置支持 | 需要手动处理 |
| 代码量 | 更简洁 | 较冗长 |
| 协程 | 原生支持 | 需要第三方库 |
| 扩展函数 | 支持 | 不支持 |
| 数据类 | `data class` | 需要手写 |
| 学习曲线 | 较平缓 | 较陡峭 |

**Kotlin 示例**：
```kotlin
// 数据类
data class User(val name: String, val age: Int)

// 空安全
val name: String? = null
val length = name?.length ?: 0

// 扩展函数
fun String.addExclamation() = "$this!"
println("Hello".addExclamation()) // Hello!

// Lambda 表达式
val numbers = listOf(1, 2, 3, 4, 5)
val doubled = numbers.map { it * 2 }
```

---

## 2. 环境搭建

### 2.1 安装 Android Studio

1. 下载 Android Studio：https://developer.android.com/studio
2. 运行安装程序，按照向导完成安装
3. 首次启动时会下载 Android SDK

**系统要求**：
- Windows：64 位 Windows 8/10/11，8GB RAM（推荐 16GB）
- macOS：macOS 10.14+，8GB RAM（推荐 16GB）
- Linux：64 位 Linux，8GB RAM（推荐 16GB）

### 2.2 配置 SDK

打开 Android Studio → Settings → Languages & Frameworks → Android SDK

**必装组件**：
- Android SDK Platform（最新版本 + 目标版本）
- Android SDK Build-Tools
- Android Emulator
- Android SDK Platform-Tools

**环境变量配置**：
```bash
# macOS/Linux (~/.zshrc 或 ~/.bashrc)
export ANDROID_HOME=$HOME/Library/Android/sdk
export PATH=$PATH:$ANDROID_HOME/emulator
export PATH=$PATH:$ANDROID_HOME/platform-tools
export PATH=$PATH:$ANDROID_HOME/tools
export PATH=$PATH:$ANDROID_HOME/tools/bin

# Windows (系统环境变量)
ANDROID_HOME=C:\Users\你的用户名\AppData\Local\Android\Sdk
Path 添加:
%ANDROID_HOME%\emulator
%ANDROID_HOME%\platform-tools
%ANDROID_HOME%\tools
%ANDROID_HOME%\tools\bin
```

### 2.3 创建模拟器

1. Tools → Device Manager → Create Device
2. 选择设备类型（推荐 Pixel 系列）
3. 选择系统镜像（推荐最新稳定版）
4. 配置模拟器参数
5. 点击 Finish 完成创建

**常用 ADB 命令**：
```bash
# 查看连接的设备
adb devices

# 安装 APK
adb install app.apk

# 卸载应用
adb uninstall com.example.app

# 查看日志
adb logcat

# 进入设备 shell
adb shell

# 截图
adb exec-out screencap -p > screenshot.png

# 录屏
adb shell screenrecord /sdcard/video.mp4
```

### 2.4 创建第一个项目

1. File → New → New Project
2. 选择模板（推荐 Empty Activity）
3. 配置项目：
   - Name：应用名称
   - Package name：包名（如 com.example.myapp）
   - Save location：项目路径
   - Language：Kotlin
   - Minimum SDK：最低支持版本（推荐 API 24）
4. 点击 Finish

---

## 3. 项目结构

### 3.1 目录结构

```
MyApp/
├── app/
│   ├── build.gradle.kts          # 模块级构建配置
│   ├── proguard-rules.pro        # 混淆规则
│   └── src/
│       ├── main/
│       │   ├── java/             # Kotlin/Java 源代码
│       │   │   └── com/example/myapp/
│       │   │       ├── MainActivity.kt
│       │   │       ├── ui/       # UI 相关
│       │   │       ├── data/     # 数据层
│       │   │       ├── domain/   # 业务逻辑
│       │   │       └── di/       # 依赖注入
│       │   ├── res/              # 资源文件
│       │   │   ├── drawable/     # 图片资源
│       │   │   ├── layout/       # 布局文件
│       │   │   ├── values/       # 值资源
│       │   │   │   ├── colors.xml
│       │   │   │   ├── strings.xml
│       │   │   │   └── themes.xml
│       │   │   └── mipmap/       # 应用图标
│       │   └── AndroidManifest.xml  # 应用清单
│       ├── test/                 # 单元测试
│       └── androidTest/          # 仪器测试
├── build.gradle.kts              # 项目级构建配置
├── settings.gradle.kts           # 项目设置
├── gradle.properties             # Gradle 属性
└── local.properties              # 本地配置（SDK 路径）
```

### 3.2 Gradle 配置

**项目级 build.gradle.kts**：
```kotlin
// build.gradle.kts (Project)
plugins {
    id("com.android.application") version "8.2.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.20" apply false
    id("com.google.dagger.hilt.android") version "2.48" apply false
}
```

**模块级 build.gradle.kts**：
```kotlin
// app/build.gradle.kts
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.google.dagger.hilt.android")
    kotlin("kapt")
}

android {
    namespace = "com.example.myapp"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.myapp"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        debug {
            isDebuggable = true
            applicationIdSuffix = ".debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        viewBinding = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.4"
    }
}

dependencies {
    // AndroidX Core
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.6.2")
    implementation("androidx.activity:activity-compose:1.8.1")

    // Jetpack Compose
    implementation(platform("androidx.compose:compose-bom:2023.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")

    // Navigation
    implementation("androidx.navigation:navigation-compose:2.7.5")

    // Hilt
    implementation("com.google.dagger:hilt-android:2.48")
    kapt("com.google.dagger:hilt-compiler:2.48")
    implementation("androidx.hilt:hilt-navigation-compose:1.1.0")

    // Retrofit
    implementation("com.squareup.retrofit2:retrofit:2.9.0")
    implementation("com.squareup.retrofit2:converter-gson:2.9.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")

    // Room
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    kapt("androidx.room:room-compiler:2.6.1")

    // Coil (图片加载)
    implementation("io.coil-kt:coil-compose:2.5.0")

    // Testing
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
```

### 3.3 AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <!-- 权限声明 -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" 
        android:maxSdkVersion="32" />

    <application
        android:name=".MyApplication"
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.MyApp"
        android:usesCleartextTraffic="true"
        tools:targetApi="31">

        <!-- 主 Activity -->
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:theme="@style/Theme.MyApp">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- 其他 Activity -->
        <activity android:name=".DetailActivity" />

        <!-- Service -->
        <service android:name=".MyService" />

        <!-- BroadcastReceiver -->
        <receiver android:name=".MyReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <!-- ContentProvider -->
        <provider
            android:name=".MyContentProvider"
            android:authorities="com.example.myapp.provider"
            android:exported="false" />

    </application>

</manifest>
```

---

## 4. Activity 与生命周期

### 4.1 Activity 基础

Activity 是 Android 应用的基本构建块，代表一个用户界面屏幕。

```kotlin
// MainActivity.kt
class MainActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 使用 Jetpack Compose
        setContent {
            MyAppTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen()
                }
            }
        }
        
        // 或使用传统 View
        // setContentView(R.layout.activity_main)
    }
}
```

### 4.2 生命周期

```
┌─────────────────────────────────────────────────────────┐
│                    Activity 启动                         │
│                         ↓                               │
│                    onCreate()                           │
│                         ↓                               │
│                    onStart()                            │
│                         ↓                               │
│                    onResume()  ←──────────┐             │
│                         ↓                 │             │
│                   [Activity 运行中]        │             │
│                         ↓                 │             │
│                    onPause()  ────────────┘             │
│                         ↓                               │
│                    onStop()   ←──────────┐              │
│                         ↓                 │              │
│                   onRestart() ────────────┘              │
│                         ↓                               │
│                    onDestroy()                          │
│                         ↓                               │
│                   Activity 销毁                          │
└─────────────────────────────────────────────────────────┘
```

```kotlin
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.d("Lifecycle", "onCreate - Activity 创建")
        // 初始化 UI、绑定数据、恢复状态
    }

    override fun onStart() {
        super.onStart()
        Log.d("Lifecycle", "onStart - Activity 可见")
        // 注册广播接收器、开始动画
    }

    override fun onResume() {
        super.onResume()
        Log.d("Lifecycle", "onResume - Activity 获得焦点")
        // 恢复暂停的操作、开始传感器监听
    }

    override fun onPause() {
        super.onPause()
        Log.d("Lifecycle", "onPause - Activity 失去焦点")
        // 暂停动画、保存数据、释放相机等资源
    }

    override fun onStop() {
        super.onStop()
        Log.d("Lifecycle", "onStop - Activity 不可见")
        // 注销广播接收器、释放资源
    }

    override fun onRestart() {
        super.onRestart()
        Log.d("Lifecycle", "onRestart - Activity 重新启动")
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d("Lifecycle", "onDestroy - Activity 销毁")
        // 清理所有资源
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        // 保存临时状态（如屏幕旋转时）
        outState.putString("key", "value")
    }

    override fun onRestoreInstanceState(savedInstanceState: Bundle) {
        super.onRestoreInstanceState(savedInstanceState)
        // 恢复状态
        val value = savedInstanceState.getString("key")
    }
}
```

### 4.3 Activity 间通信

```kotlin
// 启动另一个 Activity
class MainActivity : ComponentActivity() {
    
    // 方式一：简单启动
    private fun startDetailActivity() {
        val intent = Intent(this, DetailActivity::class.java)
        startActivity(intent)
    }

    // 方式二：传递数据
    private fun startDetailWithData() {
        val intent = Intent(this, DetailActivity::class.java).apply {
            putExtra("USER_ID", 123)
            putExtra("USER_NAME", "John")
            putExtra("USER_DATA", User("John", 25)) // 需要实现 Parcelable
        }
        startActivity(intent)
    }

    // 方式三：获取返回结果（新 API）
    private val launcher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val data = result.data?.getStringExtra("result")
            Log.d("Result", "返回数据: $data")
        }
    }

    private fun startForResult() {
        val intent = Intent(this, DetailActivity::class.java)
        launcher.launch(intent)
    }
}

// 接收数据的 Activity
class DetailActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 获取传递的数据
        val userId = intent.getIntExtra("USER_ID", -1)
        val userName = intent.getStringExtra("USER_NAME")
        val userData = intent.getParcelableExtra<User>("USER_DATA")
    }

    // 返回结果
    private fun returnResult() {
        val resultIntent = Intent().apply {
            putExtra("result", "操作成功")
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }
}

// Parcelable 数据类
@Parcelize
data class User(
    val name: String,
    val age: Int
) : Parcelable
```

### 4.4 ViewModel 与状态管理

```kotlin
// ViewModel
class MainViewModel : ViewModel() {
    
    // 使用 StateFlow
    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    // 使用 LiveData
    private val _users = MutableLiveData<List<User>>()
    val users: LiveData<List<User>> = _users

    fun loadUsers() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            try {
                val result = repository.getUsers()
                _uiState.update { it.copy(users = result, isLoading = false) }
            } catch (e: Exception) {
                _uiState.update { it.copy(error = e.message, isLoading = false) }
            }
        }
    }
}

data class MainUiState(
    val users: List<User> = emptyList(),
    val isLoading: Boolean = false,
    val error: String? = null
)

// 在 Activity 中使用
class MainActivity : ComponentActivity() {
    
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContent {
            val uiState by viewModel.uiState.collectAsState()
            
            MainScreen(
                uiState = uiState,
                onRefresh = { viewModel.loadUsers() }
            )
        }
    }
}
```

---

## 5. 布局与视图

### 5.1 传统 XML 布局

虽然 Jetpack Compose 是现代推荐方式，但了解 XML 布局仍然重要：

**LinearLayout（线性布局）**：
```xml
<!-- res/layout/activity_main.xml -->
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp">

    <TextView
        android:id="@+id/titleText"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="标题"
        android:textSize="24sp"
        android:textStyle="bold" />

    <EditText
        android:id="@+id/inputField"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="请输入内容"
        android:layout_marginTop="16dp" />

    <Button
        android:id="@+id/submitButton"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="提交"
        android:layout_marginTop="16dp" />

</LinearLayout>
```

**ConstraintLayout（约束布局）**：
```xml
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:padding="16dp">

    <ImageView
        android:id="@+id/avatar"
        android:layout_width="80dp"
        android:layout_height="80dp"
        android:src="@drawable/ic_avatar"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent" />

    <TextView
        android:id="@+id/nameText"
        android:layout_width="0dp"
        android:layout_height="wrap_content"
        android:text="用户名"
        android:textSize="18sp"
        android:layout_marginStart="16dp"
        app:layout_constraintStart_toEndOf="@id/avatar"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintTop_toTopOf="@id/avatar" />

    <TextView
        android:id="@+id/emailText"
        android:layout_width="0dp"
        android:layout_height="wrap_content"
        android:text="email@example.com"
        android:textColor="#666666"
        android:layout_marginStart="16dp"
        app:layout_constraintStart_toEndOf="@id/avatar"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintTop_toBottomOf="@id/nameText"
        app:layout_constraintBottom_toBottomOf="@id/avatar" />

</androidx.constraintlayout.widget.ConstraintLayout>
```

### 5.2 View Binding

View Binding 是访问 XML 布局中视图的类型安全方式：

```kotlin
// 启用 View Binding (build.gradle.kts)
android {
    buildFeatures {
        viewBinding = true
    }
}

// 使用 View Binding
class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // 直接访问视图，无需 findViewById
        binding.titleText.text = "Hello World"
        binding.submitButton.setOnClickListener {
            val input = binding.inputField.text.toString()
            Toast.makeText(this, input, Toast.LENGTH_SHORT).show()
        }
    }
}

// Fragment 中使用
class MainFragment : Fragment() {
    
    private var _binding: FragmentMainBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentMainBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.titleText.text = "Fragment"
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null // 避免内存泄漏
    }
}
```

### 5.3 RecyclerView

RecyclerView 是显示列表数据的高效组件：

```kotlin
// 数据类
data class Item(
    val id: Int,
    val title: String,
    val description: String
)

// ViewHolder
class ItemViewHolder(
    private val binding: ItemLayoutBinding
) : RecyclerView.ViewHolder(binding.root) {
    
    fun bind(item: Item, onItemClick: (Item) -> Unit) {
        binding.titleText.text = item.title
        binding.descriptionText.text = item.description
        binding.root.setOnClickListener { onItemClick(item) }
    }
}

// Adapter
class ItemAdapter(
    private val onItemClick: (Item) -> Unit
) : ListAdapter<Item, ItemViewHolder>(ItemDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ItemViewHolder {
        val binding = ItemLayoutBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return ItemViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ItemViewHolder, position: Int) {
        holder.bind(getItem(position), onItemClick)
    }
}

// DiffUtil
class ItemDiffCallback : DiffUtil.ItemCallback<Item>() {
    override fun areItemsTheSame(oldItem: Item, newItem: Item): Boolean {
        return oldItem.id == newItem.id
    }

    override fun areContentsTheSame(oldItem: Item, newItem: Item): Boolean {
        return oldItem == newItem
    }
}

// 在 Activity 中使用
class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: ItemAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        adapter = ItemAdapter { item ->
            Toast.makeText(this, "点击: ${item.title}", Toast.LENGTH_SHORT).show()
        }

        binding.recyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = this@MainActivity.adapter
            addItemDecoration(DividerItemDecoration(context, DividerItemDecoration.VERTICAL))
        }

        // 提交数据
        adapter.submitList(listOf(
            Item(1, "标题1", "描述1"),
            Item(2, "标题2", "描述2"),
            Item(3, "标题3", "描述3")
        ))
    }
}
```

---

## 6. Jetpack Compose

### 6.1 Compose 基础

Jetpack Compose 是 Android 的现代声明式 UI 工具包：

```kotlin
// 基础 Composable
@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello, $name!",
        modifier = modifier,
        style = MaterialTheme.typography.headlineMedium
    )
}

// 预览
@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    MyAppTheme {
        Greeting("Android")
    }
}

// 带状态的 Composable
@Composable
fun Counter() {
    var count by remember { mutableStateOf(0) }

    Column(
        modifier = Modifier.padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Count: $count",
            style = MaterialTheme.typography.headlineLarge
        )
        Spacer(modifier = Modifier.height(16.dp))
        Row {
            Button(onClick = { count-- }) {
                Text("-")
            }
            Spacer(modifier = Modifier.width(16.dp))
            Button(onClick = { count++ }) {
                Text("+")
            }
        }
    }
}
```

### 6.2 常用组件

```kotlin
@Composable
fun ComponentsDemo() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        // 文本
        Text(
            text = "标题",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary
        )

        Spacer(modifier = Modifier.height(16.dp))

        // 输入框
        var text by remember { mutableStateOf("") }
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text("输入内容") },
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(16.dp))

        // 按钮
        Button(
            onClick = { /* 处理点击 */ },
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.Send, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("提交")
        }

        // 文本按钮
        TextButton(onClick = { }) {
            Text("文本按钮")
        }

        // 轮廓按钮
        OutlinedButton(onClick = { }) {
            Text("轮廓按钮")
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 卡片
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("卡片标题", style = MaterialTheme.typography.titleMedium)
                Text("卡片内容", style = MaterialTheme.typography.bodyMedium)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 图片
        AsyncImage(
            model = "https://example.com/image.jpg",
            contentDescription = "图片描述",
            modifier = Modifier
                .size(100.dp)
                .clip(CircleShape),
            contentScale = ContentScale.Crop
        )

        Spacer(modifier = Modifier.height(16.dp))

        // 开关
        var checked by remember { mutableStateOf(false) }
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("开关")
            Spacer(modifier = Modifier.weight(1f))
            Switch(
                checked = checked,
                onCheckedChange = { checked = it }
            )
        }

        // 复选框
        var isChecked by remember { mutableStateOf(false) }
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(
                checked = isChecked,
                onCheckedChange = { isChecked = it }
            )
            Text("同意条款")
        }
    }
}
```

### 6.3 布局组件

```kotlin
@Composable
fun LayoutDemo() {
    // Column - 垂直排列
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Item 1")
        Text("Item 2")
        Text("Item 3")
    }

    // Row - 水平排列
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text("Left")
        Text("Center")
        Text("Right")
    }

    // Box - 堆叠布局
    Box(
        modifier = Modifier.size(200.dp),
        contentAlignment = Alignment.Center
    ) {
        Image(
            painter = painterResource(R.drawable.background),
            contentDescription = null,
            modifier = Modifier.fillMaxSize()
        )
        Text(
            "覆盖文字",
            color = Color.White,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(8.dp)
        )
    }

    // LazyColumn - 懒加载列表
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(100) { index ->
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Item $index",
                    modifier = Modifier.padding(16.dp)
                )
            }
        }
    }

    // LazyRow - 水平懒加载列表
    LazyRow(
        contentPadding = PaddingValues(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(20) { index ->
            Card(
                modifier = Modifier.size(100.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text("$index")
                }
            }
        }
    }

    // LazyVerticalGrid - 网格布局
    LazyVerticalGrid(
        columns = GridCells.Fixed(2),
        contentPadding = PaddingValues(16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(20) { index ->
            Card(
                modifier = Modifier.aspectRatio(1f)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text("Item $index")
                }
            }
        }
    }
}
```

### 6.4 Modifier 修饰符

```kotlin
@Composable
fun ModifierDemo() {
    Box(
        modifier = Modifier
            // 尺寸
            .fillMaxWidth()
            .height(200.dp)
            // .size(100.dp)
            // .wrapContentSize()
            
            // 内边距
            .padding(16.dp)
            
            // 背景
            .background(
                color = Color.Blue,
                shape = RoundedCornerShape(8.dp)
            )
            
            // 边框
            .border(
                width = 2.dp,
                color = Color.Red,
                shape = RoundedCornerShape(8.dp)
            )
            
            // 裁剪
            .clip(RoundedCornerShape(8.dp))
            
            // 阴影
            .shadow(
                elevation = 4.dp,
                shape = RoundedCornerShape(8.dp)
            )
            
            // 点击
            .clickable { /* 处理点击 */ }
            
            // 滚动
            .verticalScroll(rememberScrollState())
            
            // 权重（在 Row/Column 中）
            // .weight(1f)
            
            // 偏移
            .offset(x = 10.dp, y = 5.dp)
            
            // 旋转
            .rotate(45f)
            
            // 缩放
            .scale(1.5f)
            
            // 透明度
            .alpha(0.8f)
    ) {
        Text("内容")
    }
}
```

### 6.5 状态管理

```kotlin
// 简单状态
@Composable
fun SimpleState() {
    var count by remember { mutableStateOf(0) }
    
    Button(onClick = { count++ }) {
        Text("Count: $count")
    }
}

// 状态提升
@Composable
fun StatefulCounter() {
    var count by remember { mutableStateOf(0) }
    
    StatelessCounter(
        count = count,
        onIncrement = { count++ },
        onDecrement = { count-- }
    )
}

@Composable
fun StatelessCounter(
    count: Int,
    onIncrement: () -> Unit,
    onDecrement: () -> Unit
) {
    Row {
        Button(onClick = onDecrement) { Text("-") }
        Text("$count", modifier = Modifier.padding(horizontal = 16.dp))
        Button(onClick = onIncrement) { Text("+") }
    }
}

// 使用 ViewModel
@Composable
fun CounterScreen(
    viewModel: CounterViewModel = hiltViewModel()
) {
    val count by viewModel.count.collectAsState()
    
    Column {
        Text("Count: $count")
        Button(onClick = { viewModel.increment() }) {
            Text("Increment")
        }
    }
}

@HiltViewModel
class CounterViewModel @Inject constructor() : ViewModel() {
    private val _count = MutableStateFlow(0)
    val count: StateFlow<Int> = _count.asStateFlow()
    
    fun increment() {
        _count.value++
    }
}

// 记住可变状态
@Composable
fun RememberExample() {
    // 基本类型
    var text by remember { mutableStateOf("") }
    
    // 列表
    val items = remember { mutableStateListOf<String>() }
    
    // 对象
    var user by remember { mutableStateOf(User("", 0)) }
    
    // 派生状态
    val isValid by remember(text) {
        derivedStateOf { text.length >= 3 }
    }
    
    // 保存状态（配置变更后恢复）
    var savedText by rememberSaveable { mutableStateOf("") }
}
```

### 6.6 副作用

```kotlin
@Composable
fun SideEffectsDemo() {
    // LaunchedEffect - 在 Composable 进入组合时启动协程
    LaunchedEffect(Unit) {
        // 只执行一次
        delay(1000)
        Log.d("Effect", "LaunchedEffect executed")
    }
    
    // LaunchedEffect 带 key - key 变化时重新执行
    var userId by remember { mutableStateOf(1) }
    LaunchedEffect(userId) {
        // userId 变化时重新执行
        val user = fetchUser(userId)
    }
    
    // DisposableEffect - 需要清理的副作用
    DisposableEffect(Unit) {
        val listener = object : SomeListener {
            override fun onEvent() { }
        }
        registerListener(listener)
        
        onDispose {
            // 清理
            unregisterListener(listener)
        }
    }
    
    // SideEffect - 每次重组都执行
    SideEffect {
        Log.d("Effect", "Recomposition happened")
    }
    
    // rememberCoroutineScope - 获取协程作用域
    val scope = rememberCoroutineScope()
    
    Button(onClick = {
        scope.launch {
            // 在点击事件中启动协程
            delay(1000)
            Log.d("Effect", "Coroutine completed")
        }
    }) {
        Text("Click")
    }
    
    // produceState - 将非 Compose 状态转换为 State
    val data by produceState<List<Item>>(initialValue = emptyList()) {
        value = fetchItems()
    }
    
    // snapshotFlow - 将 Compose State 转换为 Flow
    val listState = rememberLazyListState()
    
    LaunchedEffect(listState) {
        snapshotFlow { listState.firstVisibleItemIndex }
            .collect { index ->
                Log.d("Scroll", "First visible: $index")
            }
    }
}
```

---

## 7. 导航与路由

### 7.1 Navigation Compose

```kotlin
// 定义路由
sealed class Screen(val route: String) {
    object Home : Screen("home")
    object Detail : Screen("detail/{itemId}") {
        fun createRoute(itemId: Int) = "detail/$itemId"
    }
    object Settings : Screen("settings")
    object Profile : Screen("profile?userId={userId}") {
        fun createRoute(userId: String? = null) = 
            if (userId != null) "profile?userId=$userId" else "profile"
    }
}

// NavHost 设置
@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    
    NavHost(
        navController = navController,
        startDestination = Screen.Home.route
    ) {
        // 首页
        composable(Screen.Home.route) {
            HomeScreen(
                onNavigateToDetail = { itemId ->
                    navController.navigate(Screen.Detail.createRoute(itemId))
                },
                onNavigateToSettings = {
                    navController.navigate(Screen.Settings.route)
                }
            )
        }
        
        // 详情页（带参数）
        composable(
            route = Screen.Detail.route,
            arguments = listOf(
                navArgument("itemId") { type = NavType.IntType }
            )
        ) { backStackEntry ->
            val itemId = backStackEntry.arguments?.getInt("itemId") ?: 0
            DetailScreen(
                itemId = itemId,
                onBack = { navController.popBackStack() }
            )
        }
        
        // 设置页
        composable(Screen.Settings.route) {
            SettingsScreen(
                onBack = { navController.popBackStack() }
            )
        }
        
        // 个人页（可选参数）
        composable(
            route = Screen.Profile.route,
            arguments = listOf(
                navArgument("userId") {
                    type = NavType.StringType
                    nullable = true
                    defaultValue = null
                }
            )
        ) { backStackEntry ->
            val userId = backStackEntry.arguments?.getString("userId")
            ProfileScreen(userId = userId)
        }
    }
}

// 页面组件
@Composable
fun HomeScreen(
    onNavigateToDetail: (Int) -> Unit,
    onNavigateToSettings: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text("首页", style = MaterialTheme.typography.headlineMedium)
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(onClick = { onNavigateToDetail(123) }) {
            Text("查看详情")
        }
        
        Button(onClick = onNavigateToSettings) {
            Text("设置")
        }
    }
}

@Composable
fun DetailScreen(
    itemId: Int,
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.Default.ArrowBack, contentDescription = "返回")
        }
        
        Text("详情页", style = MaterialTheme.typography.headlineMedium)
        Text("Item ID: $itemId")
    }
}
```

### 7.2 底部导航

```kotlin
@Composable
fun MainScreen() {
    val navController = rememberNavController()
    
    Scaffold(
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route
                
                BottomNavItem.entries.forEach { item ->
                    NavigationBarItem(
                        icon = { Icon(item.icon, contentDescription = item.label) },
                        label = { Text(item.label) },
                        selected = currentRoute == item.route,
                        onClick = {
                            navController.navigate(item.route) {
                                popUpTo(navController.graph.startDestinationId) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { paddingValues ->
        NavHost(
            navController = navController,
            startDestination = BottomNavItem.Home.route,
            modifier = Modifier.padding(paddingValues)
        ) {
            composable(BottomNavItem.Home.route) { HomeTab() }
            composable(BottomNavItem.Search.route) { SearchTab() }
            composable(BottomNavItem.Profile.route) { ProfileTab() }
        }
    }
}

enum class BottomNavItem(
    val route: String,
    val icon: ImageVector,
    val label: String
) {
    Home("home", Icons.Default.Home, "首页"),
    Search("search", Icons.Default.Search, "搜索"),
    Profile("profile", Icons.Default.Person, "我的")
}
```

---

## 8. 数据存储

### 8.1 SharedPreferences / DataStore

**DataStore（推荐）**：
```kotlin
// 依赖
// implementation("androidx.datastore:datastore-preferences:1.0.0")

// 创建 DataStore
val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

// 定义 Key
object PreferencesKeys {
    val USERNAME = stringPreferencesKey("username")
    val IS_LOGGED_IN = booleanPreferencesKey("is_logged_in")
    val THEME_MODE = intPreferencesKey("theme_mode")
}

// Repository
class SettingsRepository(private val dataStore: DataStore<Preferences>) {
    
    // 读取数据
    val username: Flow<String> = dataStore.data
        .map { preferences ->
            preferences[PreferencesKeys.USERNAME] ?: ""
        }
    
    val isLoggedIn: Flow<Boolean> = dataStore.data
        .map { preferences ->
            preferences[PreferencesKeys.IS_LOGGED_IN] ?: false
        }
    
    // 写入数据
    suspend fun saveUsername(username: String) {
        dataStore.edit { preferences ->
            preferences[PreferencesKeys.USERNAME] = username
        }
    }
    
    suspend fun setLoggedIn(isLoggedIn: Boolean) {
        dataStore.edit { preferences ->
            preferences[PreferencesKeys.IS_LOGGED_IN] = isLoggedIn
        }
    }
    
    // 清除数据
    suspend fun clear() {
        dataStore.edit { preferences ->
            preferences.clear()
        }
    }
}

// 在 Compose 中使用
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val username by viewModel.username.collectAsState(initial = "")
    
    Column {
        Text("用户名: $username")
        Button(onClick = { viewModel.saveUsername("NewName") }) {
            Text("修改用户名")
        }
    }
}
```

### 8.2 Room 数据库

```kotlin
// 实体
@Entity(tableName = "users")
data class UserEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    
    @ColumnInfo(name = "user_name")
    val name: String,
    
    val email: String,
    
    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis()
)

// DAO
@Dao
interface UserDao {
    
    @Query("SELECT * FROM users ORDER BY created_at DESC")
    fun getAllUsers(): Flow<List<UserEntity>>
    
    @Query("SELECT * FROM users WHERE id = :userId")
    suspend fun getUserById(userId: Int): UserEntity?
    
    @Query("SELECT * FROM users WHERE user_name LIKE :query")
    fun searchUsers(query: String): Flow<List<UserEntity>>
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertUser(user: UserEntity): Long
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertUsers(users: List<UserEntity>)
    
    @Update
    suspend fun updateUser(user: UserEntity)
    
    @Delete
    suspend fun deleteUser(user: UserEntity)
    
    @Query("DELETE FROM users WHERE id = :userId")
    suspend fun deleteUserById(userId: Int)
    
    @Query("DELETE FROM users")
    suspend fun deleteAllUsers()
}

// 数据库
@Database(
    entities = [UserEntity::class],
    version = 1,
    exportSchema = true
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
}

// 类型转换器
class Converters {
    @TypeConverter
    fun fromTimestamp(value: Long?): Date? {
        return value?.let { Date(it) }
    }

    @TypeConverter
    fun dateToTimestamp(date: Date?): Long? {
        return date?.time
    }
}

// Hilt 模块
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {
    
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase {
        return Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "app_database"
        )
        .fallbackToDestructiveMigration()
        .build()
    }
    
    @Provides
    fun provideUserDao(database: AppDatabase): UserDao {
        return database.userDao()
    }
}

// Repository
class UserRepository @Inject constructor(
    private val userDao: UserDao
) {
    val allUsers: Flow<List<UserEntity>> = userDao.getAllUsers()
    
    suspend fun insertUser(user: UserEntity) = userDao.insertUser(user)
    
    suspend fun deleteUser(user: UserEntity) = userDao.deleteUser(user)
    
    suspend fun getUserById(id: Int) = userDao.getUserById(id)
}

// ViewModel
@HiltViewModel
class UserViewModel @Inject constructor(
    private val repository: UserRepository
) : ViewModel() {
    
    val users: StateFlow<List<UserEntity>> = repository.allUsers
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )
    
    fun addUser(name: String, email: String) {
        viewModelScope.launch {
            repository.insertUser(UserEntity(name = name, email = email))
        }
    }
    
    fun deleteUser(user: UserEntity) {
        viewModelScope.launch {
            repository.deleteUser(user)
        }
    }
}
```

---

## 9. 网络请求

### 9.1 Retrofit 配置

```kotlin
// API 接口
interface ApiService {
    
    @GET("users")
    suspend fun getUsers(): List<UserDto>
    
    @GET("users/{id}")
    suspend fun getUserById(@Path("id") userId: Int): UserDto
    
    @GET("users")
    suspend fun searchUsers(
        @Query("q") query: String,
        @Query("page") page: Int = 1,
        @Query("limit") limit: Int = 20
    ): List<UserDto>
    
    @POST("users")
    suspend fun createUser(@Body user: CreateUserRequest): UserDto
    
    @PUT("users/{id}")
    suspend fun updateUser(
        @Path("id") userId: Int,
        @Body user: UpdateUserRequest
    ): UserDto
    
    @DELETE("users/{id}")
    suspend fun deleteUser(@Path("id") userId: Int)
    
    @Multipart
    @POST("upload")
    suspend fun uploadFile(
        @Part file: MultipartBody.Part,
        @Part("description") description: RequestBody
    ): UploadResponse
    
    @Headers("Cache-Control: max-age=3600")
    @GET("config")
    suspend fun getConfig(): ConfigDto
}

// 数据类
data class UserDto(
    val id: Int,
    val name: String,
    val email: String,
    @SerializedName("created_at")
    val createdAt: String
)

data class CreateUserRequest(
    val name: String,
    val email: String
)
```

```kotlin
// Hilt 网络模块
@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {
    
    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .addInterceptor(HttpLoggingInterceptor().apply {
                level = if (BuildConfig.DEBUG) {
                    HttpLoggingInterceptor.Level.BODY
                } else {
                    HttpLoggingInterceptor.Level.NONE
                }
            })
            .addInterceptor { chain ->
                val request = chain.request().newBuilder()
                    .addHeader("Authorization", "Bearer ${getToken()}")
                    .addHeader("Content-Type", "application/json")
                    .build()
                chain.proceed(request)
            }
            .build()
    }
    
    @Provides
    @Singleton
    fun provideRetrofit(okHttpClient: OkHttpClient): Retrofit {
        return Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }
    
    @Provides
    @Singleton
    fun provideApiService(retrofit: Retrofit): ApiService {
        return retrofit.create(ApiService::class.java)
    }
}

// Repository
class UserRepository @Inject constructor(
    private val apiService: ApiService,
    private val userDao: UserDao
) {
    suspend fun getUsers(): Result<List<User>> {
        return try {
            val users = apiService.getUsers()
            // 缓存到本地数据库
            userDao.insertUsers(users.map { it.toEntity() })
            Result.success(users.map { it.toDomain() })
        } catch (e: Exception) {
            // 网络失败时从本地获取
            val localUsers = userDao.getAllUsers().first()
            if (localUsers.isNotEmpty()) {
                Result.success(localUsers.map { it.toDomain() })
            } else {
                Result.failure(e)
            }
        }
    }
}

// 封装网络结果
sealed class NetworkResult<out T> {
    data class Success<T>(val data: T) : NetworkResult<T>()
    data class Error(val message: String, val code: Int? = null) : NetworkResult<Nothing>()
    object Loading : NetworkResult<Nothing>()
}

// 扩展函数
suspend fun <T> safeApiCall(apiCall: suspend () -> T): NetworkResult<T> {
    return try {
        NetworkResult.Success(apiCall())
    } catch (e: HttpException) {
        NetworkResult.Error(e.message(), e.code())
    } catch (e: IOException) {
        NetworkResult.Error("网络连接失败")
    } catch (e: Exception) {
        NetworkResult.Error(e.message ?: "未知错误")
    }
}
```

### 9.2 在 ViewModel 中使用

```kotlin
@HiltViewModel
class UserListViewModel @Inject constructor(
    private val repository: UserRepository
) : ViewModel() {
    
    private val _uiState = MutableStateFlow<UserListUiState>(UserListUiState.Loading)
    val uiState: StateFlow<UserListUiState> = _uiState.asStateFlow()
    
    init {
        loadUsers()
    }
    
    fun loadUsers() {
        viewModelScope.launch {
            _uiState.value = UserListUiState.Loading
            
            repository.getUsers()
                .onSuccess { users ->
                    _uiState.value = UserListUiState.Success(users)
                }
                .onFailure { error ->
                    _uiState.value = UserListUiState.Error(error.message ?: "加载失败")
                }
        }
    }
    
    fun refresh() {
        loadUsers()
    }
}

sealed class UserListUiState {
    object Loading : UserListUiState()
    data class Success(val users: List<User>) : UserListUiState()
    data class Error(val message: String) : UserListUiState()
}

// UI
@Composable
fun UserListScreen(
    viewModel: UserListViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    
    when (val state = uiState) {
        is UserListUiState.Loading -> {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
        }
        is UserListUiState.Success -> {
            LazyColumn {
                items(state.users) { user ->
                    UserItem(user = user)
                }
            }
        }
        is UserListUiState.Error -> {
            Column(
                modifier = Modifier.fillMaxSize(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(state.message)
                Button(onClick = { viewModel.refresh() }) {
                    Text("重试")
                }
            }
        }
    }
}
```

---

## 10. 依赖注入

### 10.1 Hilt 配置

```kotlin
// Application
@HiltAndroidApp
class MyApplication : Application()

// Activity
@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    
    @Inject
    lateinit var analytics: Analytics
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // ...
    }
}

// ViewModel
@HiltViewModel
class MainViewModel @Inject constructor(
    private val repository: UserRepository,
    private val savedStateHandle: SavedStateHandle
) : ViewModel() {
    // ...
}

// Composable
@Composable
fun MainScreen(
    viewModel: MainViewModel = hiltViewModel()
) {
    // ...
}
```

### 10.2 Hilt 模块

```kotlin
// 单例模块
@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    
    @Provides
    @Singleton
    fun provideAnalytics(@ApplicationContext context: Context): Analytics {
        return Analytics(context)
    }
}

// 绑定接口
@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {
    
    @Binds
    @Singleton
    abstract fun bindUserRepository(
        impl: UserRepositoryImpl
    ): UserRepository
}

// 实现类
class UserRepositoryImpl @Inject constructor(
    private val apiService: ApiService,
    private val userDao: UserDao
) : UserRepository {
    // 实现方法
}

// 限定符
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class IoDispatcher

@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class MainDispatcher

@Module
@InstallIn(SingletonComponent::class)
object DispatcherModule {
    
    @Provides
    @IoDispatcher
    fun provideIoDispatcher(): CoroutineDispatcher = Dispatchers.IO
    
    @Provides
    @MainDispatcher
    fun provideMainDispatcher(): CoroutineDispatcher = Dispatchers.Main
}

// 使用限定符
class UserRepository @Inject constructor(
    private val apiService: ApiService,
    @IoDispatcher private val ioDispatcher: CoroutineDispatcher
) {
    suspend fun getUsers() = withContext(ioDispatcher) {
        apiService.getUsers()
    }
}
```

---

## 11. 异步编程

### 11.1 Kotlin 协程

```kotlin
// 基础协程
class MyViewModel : ViewModel() {
    
    fun loadData() {
        // viewModelScope 会在 ViewModel 销毁时自动取消
        viewModelScope.launch {
            try {
                val result = fetchData()
                // 更新 UI
            } catch (e: Exception) {
                // 处理错误
            }
        }
    }
    
    // 切换线程
    fun loadDataWithContext() {
        viewModelScope.launch {
            // 在 IO 线程执行
            val data = withContext(Dispatchers.IO) {
                repository.fetchData()
            }
            // 回到主线程更新 UI
            _uiState.value = data
        }
    }
    
    // 并行请求
    fun loadMultipleData() {
        viewModelScope.launch {
            val deferred1 = async { repository.getData1() }
            val deferred2 = async { repository.getData2() }
            
            // 等待所有结果
            val result1 = deferred1.await()
            val result2 = deferred2.await()
            
            // 或使用 awaitAll
            val results = awaitAll(deferred1, deferred2)
        }
    }
    
    // 超时处理
    fun loadWithTimeout() {
        viewModelScope.launch {
            try {
                val result = withTimeout(5000) {
                    repository.fetchData()
                }
            } catch (e: TimeoutCancellationException) {
                // 超时处理
            }
        }
    }
}

// 协程调度器
// Dispatchers.Main - 主线程，UI 操作
// Dispatchers.IO - IO 操作，网络请求、文件读写
// Dispatchers.Default - CPU 密集型操作
// Dispatchers.Unconfined - 不限制线程
```

### 11.2 Flow

```kotlin
// 基础 Flow
class UserRepository @Inject constructor(
    private val userDao: UserDao
) {
    // 从数据库获取 Flow
    fun getUsers(): Flow<List<User>> = userDao.getAllUsers()
        .map { entities -> entities.map { it.toDomain() } }
    
    // 创建 Flow
    fun fetchUsers(): Flow<List<User>> = flow {
        val users = apiService.getUsers()
        emit(users)
    }.flowOn(Dispatchers.IO)
    
    // 带重试的 Flow
    fun fetchUsersWithRetry(): Flow<List<User>> = flow {
        emit(apiService.getUsers())
    }
    .retry(3) { e ->
        e is IOException
    }
    .flowOn(Dispatchers.IO)
}

// 在 ViewModel 中使用
@HiltViewModel
class UserViewModel @Inject constructor(
    private val repository: UserRepository
) : ViewModel() {
    
    // 转换为 StateFlow
    val users: StateFlow<List<User>> = repository.getUsers()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )
    
    // 搜索（带防抖）
    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()
    
    val searchResults: StateFlow<List<User>> = _searchQuery
        .debounce(300) // 防抖 300ms
        .filter { it.isNotBlank() }
        .flatMapLatest { query ->
            repository.searchUsers(query)
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )
    
    fun updateSearchQuery(query: String) {
        _searchQuery.value = query
    }
}

// 在 Compose 中收集
@Composable
fun UserListScreen(viewModel: UserViewModel = hiltViewModel()) {
    val users by viewModel.users.collectAsState()
    
    // 或使用 collectAsStateWithLifecycle（推荐）
    val users by viewModel.users.collectAsStateWithLifecycle()
    
    LazyColumn {
        items(users) { user ->
            UserItem(user)
        }
    }
}

// Flow 操作符
fun flowOperators() {
    val flow = flowOf(1, 2, 3, 4, 5)
    
    viewModelScope.launch {
        flow
            .map { it * 2 }           // 转换
            .filter { it > 4 }        // 过滤
            .take(3)                  // 取前 3 个
            .onEach { Log.d("Flow", "$it") }  // 副作用
            .catch { e -> Log.e("Flow", "Error", e) }  // 错误处理
            .onCompletion { Log.d("Flow", "Completed") }  // 完成回调
            .collect { value ->
                // 收集值
            }
    }
    
    // 合并多个 Flow
    val flow1 = flowOf(1, 2, 3)
    val flow2 = flowOf("a", "b", "c")
    
    viewModelScope.launch {
        // zip - 一一对应
        flow1.zip(flow2) { num, str -> "$num$str" }
            .collect { } // "1a", "2b", "3c"
        
        // combine - 任一变化都发射
        combine(flow1, flow2) { num, str -> "$num$str" }
            .collect { }
        
        // merge - 合并
        merge(flow1.map { it.toString() }, flow2)
            .collect { }
    }
}
```

---

## 12. 权限管理

### 12.1 运行时权限

```kotlin
// 单个权限
@Composable
fun CameraPermissionScreen() {
    val context = LocalContext.current
    
    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            // 权限已授予
            openCamera()
        } else {
            // 权限被拒绝
            Toast.makeText(context, "需要相机权限", Toast.LENGTH_SHORT).show()
        }
    }
    
    Button(onClick = {
        when {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED -> {
                // 已有权限
                openCamera()
            }
            else -> {
                // 请求权限
                cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
        }
    }) {
        Text("打开相机")
    }
}

// 多个权限
@Composable
fun MultiplePermissionsScreen() {
    val context = LocalContext.current
    
    val permissions = arrayOf(
        Manifest.permission.CAMERA,
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.ACCESS_FINE_LOCATION
    )
    
    val permissionsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { permissionsMap ->
        val allGranted = permissionsMap.values.all { it }
        if (allGranted) {
            // 所有权限已授予
        } else {
            // 部分权限被拒绝
            val deniedPermissions = permissionsMap.filter { !it.value }.keys
            Toast.makeText(
                context,
                "以下权限被拒绝: ${deniedPermissions.joinToString()}",
                Toast.LENGTH_LONG
            ).show()
        }
    }
    
    Button(onClick = {
        permissionsLauncher.launch(permissions)
    }) {
        Text("请求权限")
    }
}
```

### 12.2 使用 Accompanist Permissions

```kotlin
// 依赖
// implementation("com.google.accompanist:accompanist-permissions:0.32.0")

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun PermissionScreen() {
    // 单个权限
    val cameraPermissionState = rememberPermissionState(
        Manifest.permission.CAMERA
    )
    
    when {
        cameraPermissionState.status.isGranted -> {
            Text("相机权限已授予")
        }
        cameraPermissionState.status.shouldShowRationale -> {
            Column {
                Text("需要相机权限来拍照")
                Button(onClick = { cameraPermissionState.launchPermissionRequest() }) {
                    Text("授予权限")
                }
            }
        }
        else -> {
            Button(onClick = { cameraPermissionState.launchPermissionRequest() }) {
                Text("请求相机权限")
            }
        }
    }
    
    // 多个权限
    val multiplePermissionsState = rememberMultiplePermissionsState(
        listOf(
            Manifest.permission.CAMERA,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    )
    
    if (multiplePermissionsState.allPermissionsGranted) {
        Text("所有权限已授予")
    } else {
        Column {
            Text("需要以下权限:")
            multiplePermissionsState.permissions.forEach { perm ->
                Text("- ${perm.permission}: ${if (perm.status.isGranted) "已授予" else "未授予"}")
            }
            Button(onClick = { multiplePermissionsState.launchMultiplePermissionRequest() }) {
                Text("请求权限")
            }
        }
    }
}
```

---

## 13. 服务与广播

### 13.1 Service

```kotlin
// 前台服务
class MusicService : Service() {
    
    private val binder = MusicBinder()
    
    inner class MusicBinder : Binder() {
        fun getService(): MusicService = this@MusicService
    }
    
    override fun onBind(intent: Intent): IBinder = binder
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = createNotification()
        startForeground(NOTIFICATION_ID, notification)
        
        // 处理音乐播放逻辑
        
        return START_STICKY
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Music Playback",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("正在播放")
            .setContentText("歌曲名称")
            .setSmallIcon(R.drawable.ic_music)
            .build()
    }
    
    companion object {
        const val CHANNEL_ID = "music_channel"
        const val NOTIFICATION_ID = 1
    }
}

// 启动服务
class MainActivity : ComponentActivity() {
    
    private var musicService: MusicService? = null
    
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as MusicService.MusicBinder
            musicService = binder.getService()
        }
        
        override fun onServiceDisconnected(name: ComponentName?) {
            musicService = null
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 启动前台服务
        val intent = Intent(this, MusicService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        
        // 绑定服务
        bindService(intent, connection, Context.BIND_AUTO_CREATE)
    }
    
    override fun onDestroy() {
        super.onDestroy()
        unbindService(connection)
    }
}
```

### 13.2 BroadcastReceiver

```kotlin
// 静态注册（AndroidManifest.xml）
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            // 设备启动完成
            Log.d("BootReceiver", "Device booted")
        }
    }
}

// 动态注册
class MainActivity : ComponentActivity() {
    
    private val networkReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
            val network = connectivityManager.activeNetwork
            val isConnected = network != null
            
            Log.d("NetworkReceiver", "Network connected: $isConnected")
        }
    }
    
    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkReceiver, filter)
    }
    
    override fun onStop() {
        super.onStop()
        unregisterReceiver(networkReceiver)
    }
}

// 发送广播
fun sendCustomBroadcast(context: Context) {
    val intent = Intent("com.example.MY_ACTION").apply {
        putExtra("data", "Hello")
    }
    context.sendBroadcast(intent)
}
```

### 13.3 WorkManager

```kotlin
// 依赖
// implementation("androidx.work:work-runtime-ktx:2.9.0")

// 定义 Worker
class SyncWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {
    
    override suspend fun doWork(): Result {
        return try {
            // 执行后台任务
            val data = inputData.getString("key")
            syncData()
            
            // 返回结果
            val outputData = workDataOf("result" to "success")
            Result.success(outputData)
        } catch (e: Exception) {
            if (runAttemptCount < 3) {
                Result.retry()
            } else {
                Result.failure()
            }
        }
    }
    
    private suspend fun syncData() {
        // 同步逻辑
    }
}

// 调度任务
class WorkScheduler @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val workManager = WorkManager.getInstance(context)
    
    // 一次性任务
    fun scheduleOneTimeWork() {
        val inputData = workDataOf("key" to "value")
        
        val request = OneTimeWorkRequestBuilder<SyncWorker>()
            .setInputData(inputData)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                10, TimeUnit.SECONDS
            )
            .build()
        
        workManager.enqueue(request)
    }
    
    // 周期性任务
    fun schedulePeriodicWork() {
        val request = PeriodicWorkRequestBuilder<SyncWorker>(
            15, TimeUnit.MINUTES
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .build()
        
        workManager.enqueueUniquePeriodicWork(
            "sync_work",
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }
    
    // 链式任务
    fun scheduleChainedWork() {
        val work1 = OneTimeWorkRequestBuilder<Worker1>().build()
        val work2 = OneTimeWorkRequestBuilder<Worker2>().build()
        val work3 = OneTimeWorkRequestBuilder<Worker3>().build()
        
        workManager
            .beginWith(work1)
            .then(work2)
            .then(work3)
            .enqueue()
    }
    
    // 观察任务状态
    fun observeWork(workId: UUID): Flow<WorkInfo?> {
        return workManager.getWorkInfoByIdFlow(workId)
    }
}
```

---

## 14. 性能优化

### 14.1 Compose 性能优化

```kotlin
// 1. 使用 remember 缓存计算结果
@Composable
fun ExpensiveCalculation(items: List<Item>) {
    // ❌ 每次重组都会计算
    val sortedItems = items.sortedBy { it.name }
    
    // ✅ 只在 items 变化时计算
    val sortedItems = remember(items) {
        items.sortedBy { it.name }
    }
}

// 2. 使用 key 帮助 Compose 识别列表项
@Composable
fun ItemList(items: List<Item>) {
    LazyColumn {
        items(
            items = items,
            key = { item -> item.id }  // 使用唯一 key
        ) { item ->
            ItemRow(item)
        }
    }
}

// 3. 使用 derivedStateOf 减少重组
@Composable
fun FilteredList(items: List<Item>, query: String) {
    // ❌ query 每次变化都会触发重组
    val filteredItems = items.filter { it.name.contains(query) }
    
    // ✅ 只在过滤结果变化时重组
    val filteredItems by remember(items, query) {
        derivedStateOf {
            items.filter { it.name.contains(query) }
        }
    }
}

// 4. 避免在 Composable 中创建对象
@Composable
fun BadExample() {
    // ❌ 每次重组都创建新对象
    Button(
        onClick = { },
        modifier = Modifier.padding(16.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color.Blue
        )
    ) { }
}

@Composable
fun GoodExample() {
    // ✅ 使用 remember 缓存
    val buttonColors = remember {
        ButtonDefaults.buttonColors(containerColor = Color.Blue)
    }
    
    Button(
        onClick = { },
        modifier = Modifier.padding(16.dp),
        colors = buttonColors
    ) { }
}

// 5. 使用 Stable 注解
@Stable
data class UserState(
    val name: String,
    val email: String
)

// 6. 延迟读取状态
@Composable
fun ScrollingList() {
    val listState = rememberLazyListState()
    
    // ❌ 每次滚动都重组整个 Composable
    val isScrolled = listState.firstVisibleItemIndex > 0
    
    // ✅ 使用 lambda 延迟读取
    LazyColumn(state = listState) {
        // ...
    }
    
    AnimatedVisibility(
        visible = { listState.firstVisibleItemIndex > 0 }  // lambda
    ) {
        FloatingActionButton(onClick = { }) {
            Icon(Icons.Default.ArrowUpward, null)
        }
    }
}
```

### 14.2 内存优化

```kotlin
// 1. 避免内存泄漏
class MyViewModel : ViewModel() {
    // ❌ 持有 Activity 引用
    private var activity: Activity? = null
    
    // ✅ 使用 Application Context
    @Inject
    @ApplicationContext
    lateinit var context: Context
}

// 2. 及时释放资源
class CameraViewModel : ViewModel() {
    private var camera: Camera? = null
    
    override fun onCleared() {
        super.onCleared()
        camera?.release()
        camera = null
    }
}

// 3. 使用弱引用
class MyCallback(activity: Activity) {
    private val activityRef = WeakReference(activity)
    
    fun onResult() {
        activityRef.get()?.let { activity ->
            // 使用 activity
        }
    }
}

// 4. 图片加载优化
@Composable
fun OptimizedImage(url: String) {
    AsyncImage(
        model = ImageRequest.Builder(LocalContext.current)
            .data(url)
            .crossfade(true)
            .size(Size.ORIGINAL)  // 或指定尺寸
            .memoryCachePolicy(CachePolicy.ENABLED)
            .diskCachePolicy(CachePolicy.ENABLED)
            .build(),
        contentDescription = null,
        modifier = Modifier.size(100.dp)
    )
}
```

### 14.3 启动优化

```kotlin
// 1. 使用 App Startup 库
// 依赖: implementation("androidx.startup:startup-runtime:1.1.1")

class MyInitializer : Initializer<MyDependency> {
    override fun create(context: Context): MyDependency {
        // 初始化逻辑
        return MyDependency()
    }
    
    override fun dependencies(): List<Class<out Initializer<*>>> {
        // 依赖的其他初始化器
        return emptyList()
    }
}

// AndroidManifest.xml
// <provider
//     android:name="androidx.startup.InitializationProvider"
//     android:authorities="${applicationId}.androidx-startup"
//     android:exported="false"
//     tools:node="merge">
//     <meta-data
//         android:name="com.example.MyInitializer"
//         android:value="androidx.startup" />
// </provider>

// 2. 延迟初始化
class MyApplication : Application() {
    
    // ❌ 在 onCreate 中初始化所有内容
    override fun onCreate() {
        super.onCreate()
        initAnalytics()
        initCrashReporting()
        initDatabase()
    }
    
    // ✅ 延迟非必要初始化
    val analytics by lazy { Analytics.init(this) }
    
    override fun onCreate() {
        super.onCreate()
        // 只初始化必要的
        initCrashReporting()
    }
}

// 3. 使用 Baseline Profiles
// 在 app/src/main/baseline-prof.txt 中定义
```

---

## 15. 打包发布

### 15.1 签名配置

```kotlin
// app/build.gradle.kts
android {
    signingConfigs {
        create("release") {
            storeFile = file("keystore/release.keystore")
            storePassword = System.getenv("KEYSTORE_PASSWORD") ?: ""
            keyAlias = System.getenv("KEY_ALIAS") ?: ""
            keyPassword = System.getenv("KEY_PASSWORD") ?: ""
        }
    }
    
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

### 15.2 生成签名密钥

```bash
# 生成密钥
keytool -genkey -v -keystore release.keystore -alias my-key-alias -keyalg RSA -keysize 2048 -validity 10000

# 查看密钥信息
keytool -list -v -keystore release.keystore
```

### 15.3 构建 APK/AAB

```bash
# 构建 Debug APK
./gradlew assembleDebug

# 构建 Release APK
./gradlew assembleRelease

# 构建 AAB（上架 Google Play）
./gradlew bundleRelease

# 输出位置
# APK: app/build/outputs/apk/
# AAB: app/build/outputs/bundle/
```

### 15.4 ProGuard 配置

```pro
# proguard-rules.pro

# 保留 Kotlin 元数据
-keep class kotlin.Metadata { *; }

# 保留数据类
-keep class com.example.myapp.data.** { *; }

# Retrofit
-keepattributes Signature
-keepattributes *Annotation*
-keep class retrofit2.** { *; }
-keepclasseswithmembers class * {
    @retrofit2.http.* <methods>;
}

# Gson
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *

# Hilt
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class * extends dagger.hilt.android.internal.managers.ComponentSupplier { *; }

# 保留行号（用于崩溃日志）
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
```

### 15.5 版本管理

```kotlin
// app/build.gradle.kts
android {
    defaultConfig {
        versionCode = 1
        versionName = "1.0.0"
    }
    
    // 或使用自动版本号
    defaultConfig {
        versionCode = getVersionCode()
        versionName = getVersionName()
    }
}

fun getVersionCode(): Int {
    // 基于 Git 提交数
    return "git rev-list --count HEAD".execute().toInt()
}

fun getVersionName(): String {
    // 基于 Git 标签
    return "git describe --tags --abbrev=0".execute()
}

fun String.execute(): String {
    val process = Runtime.getRuntime().exec(this)
    return process.inputStream.bufferedReader().readText().trim()
}
```

---

## 16. 常见错误与解决方案

### 16.1 Gradle 构建错误

#### Could not resolve dependency

**错误信息**：
```
Could not resolve com.example:library:1.0.0
```

**解决方案**：
```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

// 或检查网络代理设置
// gradle.properties
systemProp.http.proxyHost=proxy.example.com
systemProp.http.proxyPort=8080
```

#### Duplicate class found

**错误信息**：
```
Duplicate class xxx found in modules yyy and zzz
```

**解决方案**：
```kotlin
// 排除重复依赖
implementation("com.example:library:1.0.0") {
    exclude(group = "com.google.code.gson", module = "gson")
}

// 或强制使用特定版本
configurations.all {
    resolutionStrategy {
        force("com.google.code.gson:gson:2.10.1")
    }
}
```

#### SDK version mismatch

**错误信息**：
```
The minSdk version should not be declared in the android manifest file
```

**解决方案**：
```xml
<!-- 从 AndroidManifest.xml 中移除 -->
<!-- <uses-sdk android:minSdkVersion="24" /> -->

<!-- 在 build.gradle.kts 中配置 -->
android {
    defaultConfig {
        minSdk = 24
        targetSdk = 34
    }
}
```

### 16.2 运行时错误

#### NetworkOnMainThreadException

**错误信息**：
```
android.os.NetworkOnMainThreadException
```

**原因**：在主线程执行网络请求

**解决方案**：
```kotlin
// ❌ 错误
fun fetchData() {
    val response = api.getData() // 主线程
}

// ✅ 使用协程
fun fetchData() {
    viewModelScope.launch {
        val response = withContext(Dispatchers.IO) {
            api.getData()
        }
    }
}
```

#### IllegalStateException: Fragment not attached

**错误信息**：
```
java.lang.IllegalStateException: Fragment not attached to a context
```

**解决方案**：
```kotlin
// ❌ 错误
class MyFragment : Fragment() {
    fun updateUI() {
        requireContext() // Fragment 可能已分离
    }
}

// ✅ 检查状态
class MyFragment : Fragment() {
    fun updateUI() {
        if (isAdded && context != null) {
            // 安全操作
        }
    }
}

// ✅ 使用 viewLifecycleOwner
viewLifecycleOwner.lifecycleScope.launch {
    // 自动在 Fragment 销毁时取消
}
```

#### OutOfMemoryError

**错误信息**：
```
java.lang.OutOfMemoryError: Failed to allocate
```

**解决方案**：
```kotlin
// 1. 优化图片加载
AsyncImage(
    model = ImageRequest.Builder(LocalContext.current)
        .data(url)
        .size(200, 200)  // 限制尺寸
        .build(),
    contentDescription = null
)

// 2. 及时释放资源
override fun onDestroy() {
    super.onDestroy()
    bitmap?.recycle()
    bitmap = null
}

// 3. 使用 largeHeap（不推荐）
// AndroidManifest.xml
// android:largeHeap="true"
```

### 16.3 Compose 错误

#### @Composable invocations can only happen from the context of a @Composable function

**原因**：在非 Composable 函数中调用 Composable

**解决方案**：
```kotlin
// ❌ 错误
fun showDialog() {
    AlertDialog(...) // 不能在普通函数中调用
}

// ✅ 使用状态控制
@Composable
fun MyScreen() {
    var showDialog by remember { mutableStateOf(false) }
    
    Button(onClick = { showDialog = true }) {
        Text("显示对话框")
    }
    
    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            // ...
        )
    }
}
```

#### Recomposition loop detected

**原因**：状态更新导致无限重组

**解决方案**：
```kotlin
// ❌ 错误 - 在 Composable 中直接修改状态
@Composable
fun BadExample() {
    var count by remember { mutableStateOf(0) }
    count++ // 导致无限重组
}

// ✅ 在事件回调中修改状态
@Composable
fun GoodExample() {
    var count by remember { mutableStateOf(0) }
    
    LaunchedEffect(Unit) {
        count++ // 只执行一次
    }
    
    Button(onClick = { count++ }) {
        Text("Count: $count")
    }
}
```

### 16.4 Hilt 错误

#### Hilt Activity must be attached to an @HiltAndroidApp Application

**解决方案**：
```kotlin
// 确保 Application 类添加了注解
@HiltAndroidApp
class MyApplication : Application()

// AndroidManifest.xml 中指定
<application
    android:name=".MyApplication"
    ...>
```

#### Cannot create an instance of ViewModel

**错误信息**：
```
Cannot create an instance of class MyViewModel
```

**解决方案**：
```kotlin
// 1. 确保 ViewModel 添加了注解
@HiltViewModel
class MyViewModel @Inject constructor(
    private val repository: Repository
) : ViewModel()

// 2. 确保 Activity/Fragment 添加了注解
@AndroidEntryPoint
class MainActivity : ComponentActivity()

// 3. 使用正确的方式获取 ViewModel
// Compose
val viewModel: MyViewModel = hiltViewModel()

// Activity
val viewModel: MyViewModel by viewModels()
```

### 16.5 Room 错误

#### Cannot figure out how to save this field into database

**解决方案**：
```kotlin
// 添加类型转换器
class Converters {
    @TypeConverter
    fun fromList(list: List<String>): String {
        return Gson().toJson(list)
    }
    
    @TypeConverter
    fun toList(json: String): List<String> {
        return Gson().fromJson(json, object : TypeToken<List<String>>() {}.type)
    }
}

// 在数据库中注册
@Database(entities = [User::class], version = 1)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase()
```

#### Room schema export directory is not provided

**解决方案**：
```kotlin
// app/build.gradle.kts
android {
    defaultConfig {
        kapt {
            arguments {
                arg("room.schemaLocation", "$projectDir/schemas")
            }
        }
    }
}
```

### 16.6 网络错误

#### java.net.UnknownHostException

**解决方案**：
```xml
<!-- 1. 添加网络权限 -->
<uses-permission android:name="android.permission.INTERNET" />

<!-- 2. 允许明文传输（开发环境） -->
<application
    android:usesCleartextTraffic="true">
```

#### javax.net.ssl.SSLHandshakeException

**解决方案**：
```kotlin
// 开发环境信任所有证书（不推荐生产使用）
val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
})

val sslContext = SSLContext.getInstance("SSL")
sslContext.init(null, trustAllCerts, SecureRandom())

val okHttpClient = OkHttpClient.Builder()
    .sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as X509TrustManager)
    .hostnameVerifier { _, _ -> true }
    .build()
```

---

## 快速参考

### 常用 Gradle 命令

| 命令 | 说明 |
|------|------|
| `./gradlew assembleDebug` | 构建 Debug APK |
| `./gradlew assembleRelease` | 构建 Release APK |
| `./gradlew bundleRelease` | 构建 AAB |
| `./gradlew clean` | 清理构建 |
| `./gradlew dependencies` | 查看依赖树 |
| `./gradlew lint` | 运行 Lint 检查 |
| `./gradlew test` | 运行单元测试 |
| `./gradlew connectedAndroidTest` | 运行仪器测试 |

### 常用 ADB 命令

| 命令 | 说明 |
|------|------|
| `adb devices` | 列出设备 |
| `adb install app.apk` | 安装 APK |
| `adb uninstall com.example.app` | 卸载应用 |
| `adb logcat` | 查看日志 |
| `adb shell` | 进入设备 Shell |
| `adb pull /path/file` | 从设备拉取文件 |
| `adb push file /path/` | 推送文件到设备 |

### 推荐库

| 类别 | 库名 | 说明 |
|------|------|------|
| UI | Jetpack Compose | 声明式 UI |
| 导航 | Navigation Compose | 导航组件 |
| 网络 | Retrofit + OkHttp | 网络请求 |
| 数据库 | Room | 本地数据库 |
| 依赖注入 | Hilt | DI 框架 |
| 图片 | Coil | 图片加载 |
| 异步 | Kotlin Coroutines | 协程 |
| 序列化 | Kotlin Serialization | JSON 序列化 |

---

> 💡 **小贴士**：Android 开发生态丰富，建议关注 Android Developers 官方博客和 Jetpack 更新。使用 Android Studio 的 Profiler 工具可以帮助发现性能问题。
