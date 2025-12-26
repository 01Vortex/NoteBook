

> Android 是基于 Linux 内核的开源移动操作系统，由 Google 主导开发
> 本笔记涵盖 Android 开发从入门到进阶的完整知识体系，基于 Kotlin + Jetpack

---

## 目录

1. [基础概念](#1-基础概念)
2. [开发环境搭建](#2-开发环境搭建)
3. [项目结构](#3-项目结构)
4. [四大组件](#4-四大组件)
5. [UI 开发](#5-ui-开发)
6. [Jetpack Compose](#6-jetpack-compose)
7. [数据存储](#7-数据存储)
8. [网络请求](#8-网络请求)
9. [Jetpack 组件](#9-jetpack-组件)
10. [依赖注入](#10-依赖注入)
11. [多线程与协程](#11-多线程与协程)
12. [权限管理](#12-权限管理)
13. [性能优化](#13-性能优化)
14. [调试与测试](#14-调试与测试)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Android？

Android 是 Google 开发的移动操作系统，基于 Linux 内核。它是目前全球市场份额最大的移动操作系统，广泛应用于手机、平板、电视、汽车等设备。

**Android 发展历程：**
- 2008年：Android 1.0 发布
- 2014年：Android 5.0 (Lollipop) - Material Design
- 2017年：Kotlin 成为官方开发语言
- 2021年：Jetpack Compose 1.0 发布
- 2023年：Android 14 发布

**Android 版本与 API Level：**

| Android 版本 | API Level | 代号 |
|-------------|-----------|------|
| Android 14 | 34 | Upside Down Cake |
| Android 13 | 33 | Tiramisu |
| Android 12 | 31-32 | Snow Cone |
| Android 11 | 30 | Red Velvet Cake |
| Android 10 | 29 | Quince Tart |
| Android 9 | 28 | Pie |
| Android 8 | 26-27 | Oreo |

### 1.2 Android 架构

```
┌─────────────────────────────────────────────────────┐
│                   应用层 (Applications)              │
│        电话、短信、浏览器、相机、你的 App...          │
├─────────────────────────────────────────────────────┤
│               应用框架层 (Application Framework)     │
│   Activity Manager, Window Manager, Content Provider │
│   View System, Package Manager, Resource Manager     │
├─────────────────────────────────────────────────────┤
│                   系统运行库层                        │
│  ┌─────────────────┐  ┌─────────────────────────┐   │
│  │  Android Runtime │  │    Native Libraries     │   │
│  │  (ART/Dalvik)   │  │  SQLite, OpenGL, WebKit │   │
│  └─────────────────┘  └─────────────────────────┘   │
├─────────────────────────────────────────────────────┤
│              硬件抽象层 (HAL)                         │
├─────────────────────────────────────────────────────┤
│              Linux 内核 (Kernel)                     │
│     驱动程序、电源管理、内存管理、进程管理            │
└─────────────────────────────────────────────────────┘
```

### 1.3 开发语言选择

| 语言 | 说明 | 推荐度 |
|------|------|--------|
| Kotlin | Google 官方推荐，现代化语言 | ⭐⭐⭐⭐⭐ |
| Java | 传统开发语言，生态成熟 | ⭐⭐⭐⭐ |
| C/C++ | NDK 开发，性能敏感场景 | ⭐⭐⭐ |

---

## 2. 开发环境搭建

### 2.1 安装 Android Studio

```bash
# 下载地址
https://developer.android.com/studio

# 系统要求
# Windows: 64位，8GB+ RAM，8GB+ 磁盘空间
# macOS: macOS 10.14+，8GB+ RAM
# Linux: 64位，8GB+ RAM
```

### 2.2 SDK 配置

```
Android Studio → Settings → Appearance & Behavior 
→ System Settings → Android SDK

必装组件：
- Android SDK Platform (最新版本)
- Android SDK Build-Tools
- Android Emulator
- Android SDK Platform-Tools
- Intel x86 Emulator Accelerator (HAXM)
```

### 2.3 创建模拟器

```
Tools → Device Manager → Create Device

推荐配置：
- Device: Pixel 6
- System Image: API 34 (Android 14)
- RAM: 2048 MB
- VM Heap: 512 MB
```

### 2.4 Gradle 配置

```kotlin
// settings.gradle.kts
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // 阿里云镜像（国内加速）
        maven { url = uri("https://maven.aliyun.com/repository/google") }
        maven { url = uri("https://maven.aliyun.com/repository/central") }
    }
}
rootProject.name = "MyApp"
include(":app")
```

```kotlin
// build.gradle.kts (Project)
plugins {
    id("com.android.application") version "8.2.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.20" apply false
    id("com.google.dagger.hilt.android") version "2.48" apply false
}
```

```kotlin
// build.gradle.kts (Module: app)
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("kotlin-kapt")
    id("com.google.dagger.hilt.android")
}

android {
    namespace = "com.example.myapp"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.myapp"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
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
    // Core
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    
    // Compose
    implementation(platform("androidx.compose:compose-bom:2023.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.8.1")
    
    // Lifecycle
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.6.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.6.2")
    
    // Navigation
    implementation("androidx.navigation:navigation-compose:2.7.5")
    
    // Room
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    kapt("androidx.room:room-compiler:2.6.1")
    
    // Hilt
    implementation("com.google.dagger:hilt-android:2.48")
    kapt("com.google.dagger:hilt-compiler:2.48")
    
    // Retrofit
    implementation("com.squareup.retrofit2:retrofit:2.9.0")
    implementation("com.squareup.retrofit2:converter-gson:2.9.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    
    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    
    // Testing
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
```

---

## 3. 项目结构

### 3.1 标准项目结构

```
MyApp/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/com/example/myapp/
│   │   │   │   ├── data/           # 数据层
│   │   │   │   │   ├── local/      # 本地数据源
│   │   │   │   │   ├── remote/     # 远程数据源
│   │   │   │   │   └── repository/ # 仓库
│   │   │   │   ├── di/             # 依赖注入
│   │   │   │   ├── domain/         # 领域层
│   │   │   │   │   ├── model/      # 领域模型
│   │   │   │   │   └── usecase/    # 用例
│   │   │   │   ├── ui/             # UI 层
│   │   │   │   │   ├── screens/    # 页面
│   │   │   │   │   ├── components/ # 组件
│   │   │   │   │   └── theme/      # 主题
│   │   │   │   ├── util/           # 工具类
│   │   │   │   └── MyApplication.kt
│   │   │   ├── res/
│   │   │   │   ├── drawable/       # 图片资源
│   │   │   │   ├── layout/         # 布局文件
│   │   │   │   ├── values/         # 值资源
│   │   │   │   │   ├── colors.xml
│   │   │   │   │   ├── strings.xml
│   │   │   │   │   └── themes.xml
│   │   │   │   └── mipmap/         # 应用图标
│   │   │   └── AndroidManifest.xml
│   │   ├── test/                   # 单元测试
│   │   └── androidTest/            # 仪器测试
│   ├── build.gradle.kts
│   └── proguard-rules.pro
├── build.gradle.kts
├── settings.gradle.kts
└── gradle.properties
```

### 3.2 AndroidManifest.xml

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
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.MyApp"
        android:networkSecurityConfig="@xml/network_security_config"
        tools:targetApi="34">

        <!-- 主 Activity -->
        <activity
            android:name=".ui.MainActivity"
            android:exported="true"
            android:theme="@style/Theme.MyApp">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- 其他 Activity -->
        <activity android:name=".ui.DetailActivity" />

        <!-- Service -->
        <service
            android:name=".service.MyService"
            android:exported="false" />

        <!-- BroadcastReceiver -->
        <receiver
            android:name=".receiver.MyReceiver"
            android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <!-- ContentProvider -->
        <provider
            android:name=".provider.MyContentProvider"
            android:authorities="com.example.myapp.provider"
            android:exported="false" />

    </application>
</manifest>
```

---

## 4. 四大组件

### 4.1 Activity

Activity 是 Android 应用的基本构建块，代表一个屏幕界面。

```kotlin
// MainActivity.kt
class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        // 初始化 UI
        setupUI()
    }
    
    private fun setupUI() {
        binding.button.setOnClickListener {
            // 跳转到另一个 Activity
            val intent = Intent(this, DetailActivity::class.java).apply {
                putExtra("key", "value")
            }
            startActivity(intent)
        }
    }
    
    // 生命周期方法
    override fun onStart() {
        super.onStart()
        // Activity 可见
    }
    
    override fun onResume() {
        super.onResume()
        // Activity 获得焦点，可交互
    }
    
    override fun onPause() {
        super.onPause()
        // Activity 失去焦点
    }
    
    override fun onStop() {
        super.onStop()
        // Activity 不可见
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // Activity 销毁
    }
    
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        // 保存状态
        outState.putString("key", "value")
    }
    
    override fun onRestoreInstanceState(savedInstanceState: Bundle) {
        super.onRestoreInstanceState(savedInstanceState)
        // 恢复状态
        val value = savedInstanceState.getString("key")
    }
}
```

**Activity 生命周期：**
```
onCreate() → onStart() → onResume() → [运行中]
                                          ↓
                                      onPause()
                                          ↓
                                      onStop()
                                          ↓
                                     onDestroy()
```

### 4.2 Service

Service 用于在后台执行长时间运行的操作。

```kotlin
// 前台服务
class MyForegroundService : Service() {
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = createNotification()
        startForeground(NOTIFICATION_ID, notification)
        
        // 执行后台任务
        doBackgroundWork()
        
        return START_STICKY
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "My Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("服务运行中")
            .setContentText("正在处理...")
            .setSmallIcon(R.drawable.ic_notification)
            .build()
    }
    
    companion object {
        const val CHANNEL_ID = "my_service_channel"
        const val NOTIFICATION_ID = 1
    }
}

// 启动服务
val intent = Intent(context, MyForegroundService::class.java)
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
    context.startForegroundService(intent)
} else {
    context.startService(intent)
}
```

### 4.3 BroadcastReceiver

BroadcastReceiver 用于接收系统或应用发送的广播。

```kotlin
// 广播接收器
class MyReceiver : BroadcastReceiver() {
    
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> {
                // 开机完成
            }
            Intent.ACTION_BATTERY_LOW -> {
                // 电量低
            }
            "com.example.MY_ACTION" -> {
                // 自定义广播
                val data = intent.getStringExtra("data")
            }
        }
    }
}

// 动态注册广播
class MainActivity : AppCompatActivity() {
    
    private val receiver = MyReceiver()
    
    override fun onResume() {
        super.onResume()
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_BATTERY_LOW)
            addAction("com.example.MY_ACTION")
        }
        registerReceiver(receiver, filter)
    }
    
    override fun onPause() {
        super.onPause()
        unregisterReceiver(receiver)
    }
}

// 发送广播
val intent = Intent("com.example.MY_ACTION").apply {
    putExtra("data", "Hello")
}
sendBroadcast(intent)

// 发送有序广播
sendOrderedBroadcast(intent, null)

// 发送本地广播（已废弃，推荐使用 LiveData 或 Flow）
LocalBroadcastManager.getInstance(context).sendBroadcast(intent)
```

### 4.4 ContentProvider

ContentProvider 用于在应用之间共享数据。

```kotlin
class MyContentProvider : ContentProvider() {
    
    private lateinit var database: MyDatabase
    
    companion object {
        const val AUTHORITY = "com.example.myapp.provider"
        val CONTENT_URI: Uri = Uri.parse("content://$AUTHORITY/items")
        
        const val ITEMS = 1
        const val ITEM_ID = 2
        
        private val uriMatcher = UriMatcher(UriMatcher.NO_MATCH).apply {
            addURI(AUTHORITY, "items", ITEMS)
            addURI(AUTHORITY, "items/#", ITEM_ID)
        }
    }
    
    override fun onCreate(): Boolean {
        database = Room.databaseBuilder(
            context!!,
            MyDatabase::class.java,
            "my_database"
        ).build()
        return true
    }
    
    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? {
        return when (uriMatcher.match(uri)) {
            ITEMS -> database.itemDao().getAllAsCursor()
            ITEM_ID -> {
                val id = uri.lastPathSegment?.toLong() ?: return null
                database.itemDao().getByIdAsCursor(id)
            }
            else -> null
        }
    }
    
    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        // 实现插入逻辑
        return null
    }
    
    override fun update(uri: Uri, values: ContentValues?, 
                        selection: String?, selectionArgs: Array<out String>?): Int {
        return 0
    }
    
    override fun delete(uri: Uri, selection: String?, 
                        selectionArgs: Array<out String>?): Int {
        return 0
    }
    
    override fun getType(uri: Uri): String? {
        return when (uriMatcher.match(uri)) {
            ITEMS -> "vnd.android.cursor.dir/vnd.$AUTHORITY.items"
            ITEM_ID -> "vnd.android.cursor.item/vnd.$AUTHORITY.items"
            else -> null
        }
    }
}
```

---

## 5. UI 开发

### 5.1 传统 View 系统

```xml
<!-- activity_main.xml -->
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:padding="16dp">

    <TextView
        android:id="@+id/titleText"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Hello World"
        android:textSize="24sp"
        android:textStyle="bold"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintStart_toStartOf="parent" />

    <EditText
        android:id="@+id/inputField"
        android:layout_width="0dp"
        android:layout_height="wrap_content"
        android:hint="请输入内容"
        android:inputType="text"
        app:layout_constraintTop_toBottomOf="@id/titleText"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        android:layout_marginTop="16dp" />

    <Button
        android:id="@+id/submitButton"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="提交"
        app:layout_constraintTop_toBottomOf="@id/inputField"
        app:layout_constraintEnd_toEndOf="parent"
        android:layout_marginTop="16dp" />

    <androidx.recyclerview.widget.RecyclerView
        android:id="@+id/recyclerView"
        android:layout_width="0dp"
        android:layout_height="0dp"
        app:layout_constraintTop_toBottomOf="@id/submitButton"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        android:layout_marginTop="16dp" />

</androidx.constraintlayout.widget.ConstraintLayout>
```

### 5.2 ViewBinding

```kotlin
// 启用 ViewBinding
// build.gradle.kts
android {
    buildFeatures {
        viewBinding = true
    }
}

// 使用 ViewBinding
class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        // 直接访问视图
        binding.titleText.text = "Welcome"
        binding.submitButton.setOnClickListener {
            val input = binding.inputField.text.toString()
            // 处理输入
        }
    }
}
```

### 5.3 RecyclerView

```kotlin
// 数据类
data class Item(
    val id: Long,
    val title: String,
    val description: String
)

// Adapter
class ItemAdapter(
    private val onItemClick: (Item) -> Unit
) : ListAdapter<Item, ItemAdapter.ViewHolder>(ItemDiffCallback()) {
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemLayoutBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return ViewHolder(binding)
    }
    
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }
    
    inner class ViewHolder(
        private val binding: ItemLayoutBinding
    ) : RecyclerView.ViewHolder(binding.root) {
        
        init {
            binding.root.setOnClickListener {
                onItemClick(getItem(adapterPosition))
            }
        }
        
        fun bind(item: Item) {
            binding.titleText.text = item.title
            binding.descriptionText.text = item.description
        }
    }
    
    class ItemDiffCallback : DiffUtil.ItemCallback<Item>() {
        override fun areItemsTheSame(oldItem: Item, newItem: Item): Boolean {
            return oldItem.id == newItem.id
        }
        
        override fun areContentsTheSame(oldItem: Item, newItem: Item): Boolean {
            return oldItem == newItem
        }
    }
}

// 使用
class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: ItemAdapter
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupRecyclerView()
    }
    
    private fun setupRecyclerView() {
        adapter = ItemAdapter { item ->
            // 处理点击
            Toast.makeText(this, item.title, Toast.LENGTH_SHORT).show()
        }
        
        binding.recyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = this@MainActivity.adapter
            addItemDecoration(DividerItemDecoration(context, DividerItemDecoration.VERTICAL))
        }
        
        // 提交数据
        adapter.submitList(listOf(
            Item(1, "标题1", "描述1"),
            Item(2, "标题2", "描述2")
        ))
    }
}
```

---

## 6. Jetpack Compose

### 6.1 Compose 基础

Jetpack Compose 是 Android 的现代声明式 UI 工具包。

```kotlin
// MainActivity.kt
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
    }
}

// 基础组件
@Composable
fun MainScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // 文本
        Text(
            text = "Hello Compose",
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.primary
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // 输入框
        var text by remember { mutableStateOf("") }
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text("请输入") },
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // 按钮
        Button(
            onClick = { /* 处理点击 */ },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("提交")
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // 图片
        Image(
            painter = painterResource(id = R.drawable.ic_launcher),
            contentDescription = "Logo",
            modifier = Modifier.size(100.dp)
        )
    }
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
    MyAppTheme {
        MainScreen()
    }
}
```

### 6.2 状态管理

```kotlin
// 简单状态
@Composable
fun Counter() {
    var count by remember { mutableStateOf(0) }
    
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text("Count: $count", style = MaterialTheme.typography.headlineMedium)
        
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
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text("Count: $count")
        Row {
            Button(onClick = onDecrement) { Text("-") }
            Spacer(modifier = Modifier.width(16.dp))
            Button(onClick = onIncrement) { Text("+") }
        }
    }
}

// 使用 ViewModel
@HiltViewModel
class MainViewModel @Inject constructor(
    private val repository: ItemRepository
) : ViewModel() {
    
    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()
    
    fun loadItems() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            try {
                val items = repository.getItems()
                _uiState.update { it.copy(items = items, isLoading = false) }
            } catch (e: Exception) {
                _uiState.update { it.copy(error = e.message, isLoading = false) }
            }
        }
    }
}

data class MainUiState(
    val items: List<Item> = emptyList(),
    val isLoading: Boolean = false,
    val error: String? = null
)

@Composable
fun MainScreen(viewModel: MainViewModel = hiltViewModel()) {
    val uiState by viewModel.uiState.collectAsState()
    
    LaunchedEffect(Unit) {
        viewModel.loadItems()
    }
    
    when {
        uiState.isLoading -> LoadingScreen()
        uiState.error != null -> ErrorScreen(uiState.error!!)
        else -> ItemList(uiState.items)
    }
}
```

### 6.3 列表与导航

```kotlin
// LazyColumn 列表
@Composable
fun ItemList(items: List<Item>, onItemClick: (Item) -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(
            items = items,
            key = { it.id }
        ) { item ->
            ItemCard(item = item, onClick = { onItemClick(item) })
        }
    }
}

@Composable
fun ItemCard(item: Item, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = item.title,
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = item.description,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// Navigation Compose
@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    
    NavHost(
        navController = navController,
        startDestination = "home"
    ) {
        composable("home") {
            HomeScreen(
                onNavigateToDetail = { id ->
                    navController.navigate("detail/$id")
                }
            )
        }
        
        composable(
            route = "detail/{itemId}",
            arguments = listOf(navArgument("itemId") { type = NavType.LongType })
        ) { backStackEntry ->
            val itemId = backStackEntry.arguments?.getLong("itemId") ?: 0L
            DetailScreen(
                itemId = itemId,
                onNavigateBack = { navController.popBackStack() }
            )
        }
    }
}
```

---

## 7. 数据存储

### 7.1 SharedPreferences / DataStore

```kotlin
// DataStore（推荐）
// 依赖：implementation("androidx.datastore:datastore-preferences:1.0.0")

class PreferencesManager(private val context: Context) {
    
    private val Context.dataStore by preferencesDataStore(name = "settings")
    
    companion object {
        val DARK_MODE = booleanPreferencesKey("dark_mode")
        val USER_NAME = stringPreferencesKey("user_name")
        val USER_ID = longPreferencesKey("user_id")
    }
    
    val darkModeFlow: Flow<Boolean> = context.dataStore.data
        .map { preferences ->
            preferences[DARK_MODE] ?: false
        }
    
    suspend fun setDarkMode(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[DARK_MODE] = enabled
        }
    }
    
    suspend fun saveUser(id: Long, name: String) {
        context.dataStore.edit { preferences ->
            preferences[USER_ID] = id
            preferences[USER_NAME] = name
        }
    }
}

// 传统 SharedPreferences
class SharedPrefsManager(context: Context) {
    
    private val prefs = context.getSharedPreferences("my_prefs", Context.MODE_PRIVATE)
    
    var darkMode: Boolean
        get() = prefs.getBoolean("dark_mode", false)
        set(value) = prefs.edit().putBoolean("dark_mode", value).apply()
    
    var userName: String?
        get() = prefs.getString("user_name", null)
        set(value) = prefs.edit().putString("user_name", value).apply()
}
```

### 7.2 Room 数据库

```kotlin
// Entity
@Entity(tableName = "items")
data class ItemEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    
    @ColumnInfo(name = "title")
    val title: String,
    
    @ColumnInfo(name = "description")
    val description: String,
    
    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis()
)

// DAO
@Dao
interface ItemDao {
    
    @Query("SELECT * FROM items ORDER BY created_at DESC")
    fun getAll(): Flow<List<ItemEntity>>
    
    @Query("SELECT * FROM items WHERE id = :id")
    suspend fun getById(id: Long): ItemEntity?
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(item: ItemEntity): Long
    
    @Update
    suspend fun update(item: ItemEntity)
    
    @Delete
    suspend fun delete(item: ItemEntity)
    
    @Query("DELETE FROM items")
    suspend fun deleteAll()
}

// Database
@Database(
    entities = [ItemEntity::class],
    version = 1,
    exportSchema = true
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    
    abstract fun itemDao(): ItemDao
    
    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null
        
        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "app_database"
                )
                .fallbackToDestructiveMigration()
                .build()
                .also { INSTANCE = it }
            }
        }
    }
}

// TypeConverters
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

// Repository
class ItemRepository(private val itemDao: ItemDao) {
    
    val allItems: Flow<List<ItemEntity>> = itemDao.getAll()
    
    suspend fun insert(item: ItemEntity) = itemDao.insert(item)
    
    suspend fun update(item: ItemEntity) = itemDao.update(item)
    
    suspend fun delete(item: ItemEntity) = itemDao.delete(item)
}
```

---

## 8. 网络请求

### 8.1 Retrofit

```kotlin
// API 接口
interface ApiService {
    
    @GET("users")
    suspend fun getUsers(): List<User>
    
    @GET("users/{id}")
    suspend fun getUser(@Path("id") id: Long): User
    
    @POST("users")
    suspend fun createUser(@Body user: User): User
    
    @PUT("users/{id}")
    suspend fun updateUser(@Path("id") id: Long, @Body user: User): User
    
    @DELETE("users/{id}")
    suspend fun deleteUser(@Path("id") id: Long)
    
    @GET("search")
    suspend fun search(
        @Query("q") query: String,
        @Query("page") page: Int = 1
    ): SearchResult
    
    @Multipart
    @POST("upload")
    suspend fun uploadFile(
        @Part file: MultipartBody.Part
    ): UploadResponse
}

// 数据类
data class User(
    val id: Long,
    val name: String,
    val email: String
)

// Retrofit 配置
object RetrofitClient {
    
    private const val BASE_URL = "https://api.example.com/"
    
    private val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BODY
        })
        .addInterceptor { chain ->
            val request = chain.request().newBuilder()
                .addHeader("Authorization", "Bearer ${getToken()}")
                .build()
            chain.proceed(request)
        }
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()
    
    val apiService: ApiService = Retrofit.Builder()
        .baseUrl(BASE_URL)
        .client(okHttpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(ApiService::class.java)
}

// Repository
class UserRepository(private val apiService: ApiService) {
    
    suspend fun getUsers(): Result<List<User>> {
        return try {
            Result.success(apiService.getUsers())
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun getUser(id: Long): Result<User> {
        return try {
            Result.success(apiService.getUser(id))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

// ViewModel 中使用
@HiltViewModel
class UserViewModel @Inject constructor(
    private val repository: UserRepository
) : ViewModel() {
    
    private val _users = MutableStateFlow<List<User>>(emptyList())
    val users: StateFlow<List<User>> = _users.asStateFlow()
    
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()
    
    fun loadUsers() {
        viewModelScope.launch {
            _isLoading.value = true
            repository.getUsers()
                .onSuccess { _users.value = it }
                .onFailure { /* 处理错误 */ }
            _isLoading.value = false
        }
    }
}
```

### 8.2 网络状态监听

```kotlin
class NetworkMonitor(context: Context) {
    
    private val connectivityManager = 
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    val isConnected: Flow<Boolean> = callbackFlow {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                trySend(true)
            }
            
            override fun onLost(network: Network) {
                trySend(false)
            }
        }
        
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        
        connectivityManager.registerNetworkCallback(request, callback)
        
        // 初始状态
        val currentNetwork = connectivityManager.activeNetwork
        trySend(currentNetwork != null)
        
        awaitClose {
            connectivityManager.unregisterNetworkCallback(callback)
        }
    }
}
```

---

## 9. Jetpack 组件

### 9.1 ViewModel

```kotlin
// 基础 ViewModel
class MainViewModel : ViewModel() {
    
    private val _count = MutableLiveData(0)
    val count: LiveData<Int> = _count
    
    fun increment() {
        _count.value = (_count.value ?: 0) + 1
    }
}

// 带参数的 ViewModel
class DetailViewModel(
    private val itemId: Long,
    private val repository: ItemRepository
) : ViewModel() {
    
    private val _item = MutableStateFlow<Item?>(null)
    val item: StateFlow<Item?> = _item.asStateFlow()
    
    init {
        loadItem()
    }
    
    private fun loadItem() {
        viewModelScope.launch {
            _item.value = repository.getItem(itemId)
        }
    }
    
    class Factory(
        private val itemId: Long,
        private val repository: ItemRepository
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return DetailViewModel(itemId, repository) as T
        }
    }
}

// SavedStateHandle
class SearchViewModel(
    private val savedStateHandle: SavedStateHandle
) : ViewModel() {
    
    val query = savedStateHandle.getStateFlow("query", "")
    
    fun setQuery(query: String) {
        savedStateHandle["query"] = query
    }
}
```

### 9.2 LiveData

```kotlin
// 基础使用
class MyViewModel : ViewModel() {
    
    private val _data = MutableLiveData<String>()
    val data: LiveData<String> = _data
    
    fun updateData(value: String) {
        _data.value = value  // 主线程
        _data.postValue(value)  // 任意线程
    }
}

// 观察 LiveData
viewModel.data.observe(viewLifecycleOwner) { value ->
    binding.textView.text = value
}

// 转换
val userName: LiveData<String> = Transformations.map(userLiveData) { user ->
    user.name
}

val userDetails: LiveData<UserDetails> = Transformations.switchMap(userId) { id ->
    repository.getUserDetails(id)
}

// 合并多个 LiveData
class CombinedLiveData<T, K, S>(
    source1: LiveData<T>,
    source2: LiveData<K>,
    private val combine: (T?, K?) -> S
) : MediatorLiveData<S>() {
    
    init {
        addSource(source1) { value = combine(it, source2.value) }
        addSource(source2) { value = combine(source1.value, it) }
    }
}
```

### 9.3 WorkManager

```kotlin
// 定义 Worker
class SyncWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {
    
    override suspend fun doWork(): Result {
        return try {
            // 执行后台任务
            syncData()
            Result.success()
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
class WorkScheduler(private val context: Context) {
    
    private val workManager = WorkManager.getInstance(context)
    
    // 一次性任务
    fun scheduleOneTimeSync() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .setRequiresBatteryNotLow(true)
            .build()
        
        val request = OneTimeWorkRequestBuilder<SyncWorker>()
            .setConstraints(constraints)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                10, TimeUnit.SECONDS
            )
            .setInputData(workDataOf("key" to "value"))
            .build()
        
        workManager.enqueueUniqueWork(
            "sync_work",
            ExistingWorkPolicy.REPLACE,
            request
        )
    }
    
    // 周期性任务
    fun schedulePeriodicSync() {
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
            "periodic_sync",
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }
    
    // 观察任务状态
    fun observeWork(workId: UUID): LiveData<WorkInfo> {
        return workManager.getWorkInfoByIdLiveData(workId)
    }
}
```

---

## 10. 依赖注入

### 10.1 Hilt

```kotlin
// Application
@HiltAndroidApp
class MyApplication : Application()

// Activity
@AndroidEntryPoint
class MainActivity : AppCompatActivity() {
    
    @Inject
    lateinit var repository: UserRepository
}

// ViewModel
@HiltViewModel
class MainViewModel @Inject constructor(
    private val repository: UserRepository,
    private val savedStateHandle: SavedStateHandle
) : ViewModel()

// Module
@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase {
        return Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "app_database"
        ).build()
    }
    
    @Provides
    @Singleton
    fun provideApiService(): ApiService {
        return Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(ApiService::class.java)
    }
    
    @Provides
    fun provideUserDao(database: AppDatabase): UserDao {
        return database.userDao()
    }
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {
    
    @Binds
    @Singleton
    abstract fun bindUserRepository(
        impl: UserRepositoryImpl
    ): UserRepository
}

// Repository 实现
class UserRepositoryImpl @Inject constructor(
    private val apiService: ApiService,
    private val userDao: UserDao
) : UserRepository {
    
    override suspend fun getUsers(): List<User> {
        return apiService.getUsers()
    }
}
```

---

## 11. 多线程与协程

### 11.1 协程基础

```kotlin
// 在 ViewModel 中使用
class MyViewModel : ViewModel() {
    
    fun loadData() {
        viewModelScope.launch {
            // 在 IO 线程执行
            val result = withContext(Dispatchers.IO) {
                repository.fetchData()
            }
            // 回到主线程更新 UI
            _data.value = result
        }
    }
    
    // 并行请求
    fun loadMultipleData() {
        viewModelScope.launch {
            val deferred1 = async { repository.getData1() }
            val deferred2 = async { repository.getData2() }
            
            val result1 = deferred1.await()
            val result2 = deferred2.await()
            
            _combinedData.value = CombinedData(result1, result2)
        }
    }
    
    // 异常处理
    fun loadDataSafely() {
        viewModelScope.launch {
            try {
                val result = repository.fetchData()
                _data.value = result
            } catch (e: Exception) {
                _error.value = e.message
            }
        }
    }
}

// Flow
class UserRepository {
    
    fun getUsers(): Flow<List<User>> = flow {
        while (true) {
            val users = apiService.getUsers()
            emit(users)
            delay(30_000) // 每 30 秒刷新
        }
    }.flowOn(Dispatchers.IO)
}

// 在 Compose 中收集 Flow
@Composable
fun UserList(viewModel: UserViewModel = hiltViewModel()) {
    val users by viewModel.users.collectAsState(initial = emptyList())
    
    LazyColumn {
        items(users) { user ->
            UserItem(user)
        }
    }
}
```

---

## 12. 权限管理

### 12.1 运行时权限

```kotlin
// Activity 中请求权限
class MainActivity : AppCompatActivity() {
    
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            // 权限已授予
            openCamera()
        } else {
            // 权限被拒绝
            showPermissionDeniedDialog()
        }
    }
    
    private val requestMultiplePermissionsLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.entries.all { it.value }
        if (allGranted) {
            // 所有权限已授予
        } else {
            // 部分权限被拒绝
        }
    }
    
    private fun checkCameraPermission() {
        when {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED -> {
                openCamera()
            }
            shouldShowRequestPermissionRationale(Manifest.permission.CAMERA) -> {
                // 显示解释对话框
                showRationaleDialog()
            }
            else -> {
                requestPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
        }
    }
    
    private fun requestLocationPermissions() {
        requestMultiplePermissionsLauncher.launch(
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            )
        )
    }
}

// Compose 中请求权限
@Composable
fun CameraScreen() {
    val context = LocalContext.current
    
    val cameraPermissionState = rememberPermissionState(
        Manifest.permission.CAMERA
    )
    
    when {
        cameraPermissionState.status.isGranted -> {
            CameraPreview()
        }
        cameraPermissionState.status.shouldShowRationale -> {
            RationaleDialog(
                onConfirm = { cameraPermissionState.launchPermissionRequest() }
            )
        }
        else -> {
            Button(onClick = { cameraPermissionState.launchPermissionRequest() }) {
                Text("请求相机权限")
            }
        }
    }
}
```

---

## 13. 性能优化

### 13.1 内存优化

```kotlin
// 避免内存泄漏
class MyActivity : AppCompatActivity() {
    
    // ❌ 错误：静态持有 Activity 引用
    companion object {
        var activity: MyActivity? = null
    }
    
    // ✅ 正确：使用 WeakReference
    companion object {
        var activityRef: WeakReference<MyActivity>? = null
    }
    
    // ❌ 错误：匿名内部类持有外部引用
    private val handler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            // 持有 Activity 引用
        }
    }
    
    // ✅ 正确：使用静态内部类 + WeakReference
    private class SafeHandler(activity: MyActivity) : Handler(Looper.getMainLooper()) {
        private val activityRef = WeakReference(activity)
        
        override fun handleMessage(msg: Message) {
            activityRef.get()?.handleMessage(msg)
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // 清理资源
        handler.removeCallbacksAndMessages(null)
    }
}

// 图片加载优化
// 使用 Coil
@Composable
fun UserAvatar(imageUrl: String) {
    AsyncImage(
        model = ImageRequest.Builder(LocalContext.current)
            .data(imageUrl)
            .crossfade(true)
            .size(Size.ORIGINAL)
            .build(),
        contentDescription = "Avatar",
        modifier = Modifier
            .size(48.dp)
            .clip(CircleShape),
        contentScale = ContentScale.Crop
    )
}
```

### 13.2 布局优化

```kotlin
// Compose 性能优化
@Composable
fun OptimizedList(items: List<Item>) {
    LazyColumn {
        items(
            items = items,
            key = { it.id }  // 使用稳定的 key
        ) { item ->
            // 使用 remember 缓存计算结果
            val formattedDate = remember(item.date) {
                formatDate(item.date)
            }
            
            ItemRow(item, formattedDate)
        }
    }
}

// 避免不必要的重组
@Composable
fun StableItem(
    item: Item,
    onClick: () -> Unit
) {
    // 使用 remember 包装 lambda
    val stableOnClick = remember(item.id) { onClick }
    
    Card(onClick = stableOnClick) {
        Text(item.title)
    }
}

// 使用 derivedStateOf
@Composable
fun FilteredList(items: List<Item>, query: String) {
    val filteredItems by remember(items, query) {
        derivedStateOf {
            items.filter { it.title.contains(query, ignoreCase = true) }
        }
    }
    
    LazyColumn {
        items(filteredItems) { item ->
            ItemRow(item)
        }
    }
}
```

### 13.3 启动优化

```kotlin
// Application 中延迟初始化
@HiltAndroidApp
class MyApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // 异步初始化非必要组件
        GlobalScope.launch(Dispatchers.Default) {
            initAnalytics()
            initCrashReporting()
        }
    }
}

// 使用 App Startup
class AnalyticsInitializer : Initializer<Analytics> {
    
    override fun create(context: Context): Analytics {
        return Analytics.init(context)
    }
    
    override fun dependencies(): List<Class<out Initializer<*>>> {
        return emptyList()
    }
}
```


---

## 14. 调试与测试

调试和测试是保证应用质量的关键环节。Android 提供了丰富的工具和框架来帮助开发者发现和修复问题。

### 14.1 Android Studio 调试工具

Android Studio 内置了强大的调试功能，熟练使用这些工具可以大大提高开发效率。

**断点调试：**

```kotlin
// 在代码行左侧点击设置断点
fun processData(data: String): Result {
    val parsed = parseData(data)  // 在这里设置断点
    val validated = validate(parsed)
    return Result(validated)
}

// 条件断点：右键断点 → 设置条件
// 例如：data.length > 100

// 日志断点：不暂停程序，只打印日志
// 右键断点 → 取消勾选 "Suspend" → 勾选 "Log message to console"
```

**Logcat 日志：**

```kotlin
// 日志级别（从低到高）
Log.v("TAG", "Verbose: 详细日志，开发调试用")
Log.d("TAG", "Debug: 调试信息")
Log.i("TAG", "Info: 一般信息")
Log.w("TAG", "Warn: 警告信息")
Log.e("TAG", "Error: 错误信息")
Log.wtf("TAG", "Assert: 严重错误，不应该发生")

// 推荐：使用 Timber 库（更优雅的日志方案）
// 依赖：implementation("com.jakewharton.timber:timber:5.0.1")

// Application 中初始化
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        } else {
            // 生产环境可以上报到 Crashlytics
            Timber.plant(CrashReportingTree())
        }
    }
}

// 使用 Timber
Timber.d("User clicked button")
Timber.i("Loading data for user: %s", userId)
Timber.e(exception, "Failed to load data")

// 自定义 Tree 用于生产环境
class CrashReportingTree : Timber.Tree() {
    override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
        if (priority >= Log.ERROR) {
            // 上报到 Firebase Crashlytics
            FirebaseCrashlytics.getInstance().log(message)
            t?.let { FirebaseCrashlytics.getInstance().recordException(it) }
        }
    }
}
```

### 14.2 性能分析工具

**Android Profiler：**

Android Profiler 是 Android Studio 内置的性能分析工具，可以实时监控 CPU、内存、网络和电量使用情况。

```
打开方式：View → Tool Windows → Profiler

主要功能：
1. CPU Profiler - 分析方法执行时间，找出性能瓶颈
2. Memory Profiler - 检测内存泄漏，分析内存分配
3. Network Profiler - 监控网络请求，分析数据传输
4. Energy Profiler - 分析电量消耗
```

**内存泄漏检测 - LeakCanary：**

```kotlin
// 依赖（仅在 debug 版本）
// debugImplementation("com.squareup.leakcanary:leakcanary-android:2.12")

// LeakCanary 会自动检测以下泄漏：
// - Activity 泄漏
// - Fragment 泄漏
// - ViewModel 泄漏
// - Service 泄漏

// 无需额外配置，添加依赖后自动工作
// 检测到泄漏时会显示通知，点击查看详细堆栈
```

**StrictMode 严格模式：**

```kotlin
// 在 Application 或 Activity 中启用
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        if (BuildConfig.DEBUG) {
            // 线程策略：检测主线程上的耗时操作
            StrictMode.setThreadPolicy(
                StrictMode.ThreadPolicy.Builder()
                    .detectDiskReads()      // 检测磁盘读取
                    .detectDiskWrites()     // 检测磁盘写入
                    .detectNetwork()        // 检测网络操作
                    .detectCustomSlowCalls() // 检测自定义慢调用
                    .penaltyLog()           // 违规时打印日志
                    .penaltyFlashScreen()   // 违规时闪烁屏幕
                    .build()
            )
            
            // VM 策略：检测内存泄漏等问题
            StrictMode.setVmPolicy(
                StrictMode.VmPolicy.Builder()
                    .detectLeakedSqlLiteObjects()  // 检测 SQLite 对象泄漏
                    .detectLeakedClosableObjects() // 检测未关闭的 Closeable
                    .detectActivityLeaks()         // 检测 Activity 泄漏
                    .penaltyLog()
                    .build()
            )
        }
    }
}
```

### 14.3 单元测试

单元测试用于测试独立的代码单元（如函数、类），不依赖 Android 框架。

```kotlin
// 测试依赖
// testImplementation("junit:junit:4.13.2")
// testImplementation("org.mockito.kotlin:mockito-kotlin:5.1.0")
// testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
// testImplementation("app.cash.turbine:turbine:1.0.0")

// 基础单元测试
class CalculatorTest {
    
    private lateinit var calculator: Calculator
    
    @Before
    fun setup() {
        calculator = Calculator()
    }
    
    @Test
    fun `addition should return correct sum`() {
        val result = calculator.add(2, 3)
        assertEquals(5, result)
    }
    
    @Test
    fun `division by zero should throw exception`() {
        assertThrows(ArithmeticException::class.java) {
            calculator.divide(10, 0)
        }
    }
    
    @After
    fun tearDown() {
        // 清理资源
    }
}

// 使用 Mock 测试
class UserRepositoryTest {
    
    @Mock
    private lateinit var apiService: ApiService
    
    @Mock
    private lateinit var userDao: UserDao
    
    private lateinit var repository: UserRepository
    
    @Before
    fun setup() {
        MockitoAnnotations.openMocks(this)
        repository = UserRepository(apiService, userDao)
    }
    
    @Test
    fun `getUser should return user from api`() = runTest {
        // Given
        val expectedUser = User(1, "John", "john@example.com")
        whenever(apiService.getUser(1)).thenReturn(expectedUser)
        
        // When
        val result = repository.getUser(1)
        
        // Then
        assertEquals(expectedUser, result)
        verify(apiService).getUser(1)
    }
    
    @Test
    fun `getUser should return cached user when offline`() = runTest {
        // Given
        val cachedUser = User(1, "John", "john@example.com")
        whenever(apiService.getUser(1)).thenThrow(IOException())
        whenever(userDao.getById(1)).thenReturn(cachedUser)
        
        // When
        val result = repository.getUser(1)
        
        // Then
        assertEquals(cachedUser, result)
    }
}

// ViewModel 测试
@OptIn(ExperimentalCoroutinesApi::class)
class MainViewModelTest {
    
    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()
    
    @Mock
    private lateinit var repository: UserRepository
    
    private lateinit var viewModel: MainViewModel
    
    @Before
    fun setup() {
        MockitoAnnotations.openMocks(this)
        viewModel = MainViewModel(repository)
    }
    
    @Test
    fun `loadUsers should update state with users`() = runTest {
        // Given
        val users = listOf(User(1, "John", "john@example.com"))
        whenever(repository.getUsers()).thenReturn(users)
        
        // When
        viewModel.loadUsers()
        
        // Then
        assertEquals(users, viewModel.uiState.value.users)
        assertFalse(viewModel.uiState.value.isLoading)
    }
    
    @Test
    fun `loadUsers should set error on failure`() = runTest {
        // Given
        whenever(repository.getUsers()).thenThrow(RuntimeException("Network error"))
        
        // When
        viewModel.loadUsers()
        
        // Then
        assertNotNull(viewModel.uiState.value.error)
    }
}

// 测试 Dispatcher 规则
class MainDispatcherRule(
    private val dispatcher: TestDispatcher = UnconfinedTestDispatcher()
) : TestWatcher() {
    
    override fun starting(description: Description) {
        Dispatchers.setMain(dispatcher)
    }
    
    override fun finished(description: Description) {
        Dispatchers.resetMain()
    }
}
```

### 14.4 UI 测试（仪器测试）

UI 测试需要在真机或模拟器上运行，用于测试用户界面交互。

```kotlin
// 测试依赖
// androidTestImplementation("androidx.test.ext:junit:1.1.5")
// androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
// androidTestImplementation("androidx.compose.ui:ui-test-junit4")

// Espresso UI 测试（传统 View）
@RunWith(AndroidJUnit4::class)
class MainActivityTest {
    
    @get:Rule
    val activityRule = ActivityScenarioRule(MainActivity::class.java)
    
    @Test
    fun clickButton_shouldShowMessage() {
        // 点击按钮
        onView(withId(R.id.submitButton))
            .perform(click())
        
        // 验证文本显示
        onView(withId(R.id.messageText))
            .check(matches(withText("Hello World")))
    }
    
    @Test
    fun typeText_shouldUpdateInput() {
        // 输入文本
        onView(withId(R.id.inputField))
            .perform(typeText("Test Input"), closeSoftKeyboard())
        
        // 验证输入
        onView(withId(R.id.inputField))
            .check(matches(withText("Test Input")))
    }
    
    @Test
    fun scrollToItem_shouldBeVisible() {
        // 滚动到指定项
        onView(withId(R.id.recyclerView))
            .perform(
                RecyclerViewActions.scrollToPosition<RecyclerView.ViewHolder>(10)
            )
        
        // 验证项可见
        onView(withText("Item 10"))
            .check(matches(isDisplayed()))
    }
}

// Compose UI 测试
@RunWith(AndroidJUnit4::class)
class ComposeScreenTest {
    
    @get:Rule
    val composeTestRule = createComposeRule()
    
    @Test
    fun counter_incrementsOnClick() {
        // 设置 Compose 内容
        composeTestRule.setContent {
            MyAppTheme {
                CounterScreen()
            }
        }
        
        // 验证初始值
        composeTestRule
            .onNodeWithText("Count: 0")
            .assertIsDisplayed()
        
        // 点击增加按钮
        composeTestRule
            .onNodeWithText("+")
            .performClick()
        
        // 验证更新后的值
        composeTestRule
            .onNodeWithText("Count: 1")
            .assertIsDisplayed()
    }
    
    @Test
    fun textField_updatesOnInput() {
        composeTestRule.setContent {
            MyAppTheme {
                SearchScreen()
            }
        }
        
        // 输入文本
        composeTestRule
            .onNodeWithTag("search_field")
            .performTextInput("Hello")
        
        // 验证输入
        composeTestRule
            .onNodeWithTag("search_field")
            .assertTextEquals("Hello")
    }
    
    @Test
    fun list_scrollsToItem() {
        composeTestRule.setContent {
            MyAppTheme {
                ItemListScreen(items = (1..100).map { Item(it.toLong(), "Item $it") })
            }
        }
        
        // 滚动到指定项
        composeTestRule
            .onNodeWithTag("item_list")
            .performScrollToIndex(50)
        
        // 验证项可见
        composeTestRule
            .onNodeWithText("Item 51")
            .assertIsDisplayed()
    }
}
```

### 14.5 测试最佳实践

```kotlin
// 1. 使用 AAA 模式（Arrange-Act-Assert）
@Test
fun `user login should succeed with valid credentials`() {
    // Arrange（准备）
    val email = "test@example.com"
    val password = "password123"
    whenever(authService.login(email, password)).thenReturn(Result.success(user))
    
    // Act（执行）
    val result = viewModel.login(email, password)
    
    // Assert（断言）
    assertTrue(result.isSuccess)
    assertEquals(user, result.getOrNull())
}

// 2. 测试命名规范
// 格式：方法名_条件_预期结果
@Test
fun `getUser_whenUserExists_returnsUser`() { }

@Test
fun `getUser_whenUserNotFound_throwsException`() { }

// 3. 使用 Fake 替代 Mock（更真实的测试）
class FakeUserRepository : UserRepository {
    private val users = mutableListOf<User>()
    
    override suspend fun getUsers(): List<User> = users
    
    override suspend fun addUser(user: User) {
        users.add(user)
    }
    
    fun clear() = users.clear()
}

// 4. 测试边界条件
@Test
fun `pagination_firstPage_shouldNotHavePreviousPage`() { }

@Test
fun `pagination_lastPage_shouldNotHaveNextPage`() { }

@Test
fun `emptyList_shouldShowEmptyState`() { }
```


---

## 15. 常见错误与解决方案

这一节汇总了 Android 开发中最常见的错误和问题，以及对应的解决方案。遇到问题时可以先在这里查找。

### 15.1 编译错误

**错误 1：Gradle 同步失败**

```
错误信息：
Could not resolve com.android.tools.build:gradle:8.2.0

原因：
- 网络问题无法下载依赖
- Gradle 版本与 Android Studio 不兼容
- 仓库配置错误

解决方案：
```

```kotlin
// 1. 配置国内镜像（settings.gradle.kts）
dependencyResolutionManagement {
    repositories {
        // 阿里云镜像
        maven { url = uri("https://maven.aliyun.com/repository/google") }
        maven { url = uri("https://maven.aliyun.com/repository/central") }
        maven { url = uri("https://maven.aliyun.com/repository/gradle-plugin") }
        google()
        mavenCentral()
    }
}

// 2. 检查 Gradle 版本兼容性
// gradle-wrapper.properties
distributionUrl=https\://services.gradle.org/distributions/gradle-8.4-bin.zip

// 3. 清理缓存重新同步
// 终端执行：
// ./gradlew clean
// ./gradlew --refresh-dependencies
```

**错误 2：Kotlin 版本冲突**

```
错误信息：
Module was compiled with an incompatible version of Kotlin

原因：
项目中使用的 Kotlin 版本与依赖库编译时使用的版本不一致

解决方案：
```

```kotlin
// build.gradle.kts (Project)
plugins {
    id("org.jetbrains.kotlin.android") version "1.9.20" apply false
}

// 确保所有模块使用相同的 Kotlin 版本
// 检查 Compose 编译器版本兼容性
// Kotlin 1.9.20 → Compose Compiler 1.5.4
android {
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.4"
    }
}
```

**错误 3：重复类冲突**

```
错误信息：
Duplicate class found in modules

原因：
多个依赖包含相同的类

解决方案：
```

```kotlin
// 1. 查找冲突来源
// 终端执行：./gradlew app:dependencies

// 2. 排除冲突依赖
implementation("com.example:library:1.0") {
    exclude(group = "com.google.code.gson", module = "gson")
}

// 3. 强制使用特定版本
configurations.all {
    resolutionStrategy {
        force("com.google.code.gson:gson:2.10.1")
    }
}
```

### 15.2 运行时错误

**错误 4：NullPointerException / KotlinNullPointerException**

```
错误信息：
java.lang.NullPointerException: Attempt to invoke method on null object

原因：
访问了空对象的属性或方法

解决方案：
```

```kotlin
// ❌ 错误写法
val name = user.name  // user 可能为 null

// ✅ 正确写法
// 1. 安全调用
val name = user?.name

// 2. Elvis 操作符
val name = user?.name ?: "Unknown"

// 3. 非空断言（确定不为空时使用）
val name = user!!.name

// 4. let 作用域函数
user?.let { 
    println(it.name)
}

// 5. 使用 requireNotNull
val name = requireNotNull(user?.name) { "User name cannot be null" }

// 6. lateinit 检查
if (::binding.isInitialized) {
    binding.textView.text = "Hello"
}
```

**错误 5：NetworkOnMainThreadException**

```
错误信息：
android.os.NetworkOnMainThreadException

原因：
在主线程执行网络请求（Android 不允许）

解决方案：
```

```kotlin
// ❌ 错误写法
fun loadData() {
    val response = apiService.getData()  // 主线程网络请求
}

// ✅ 正确写法：使用协程
fun loadData() {
    viewModelScope.launch {
        val response = withContext(Dispatchers.IO) {
            apiService.getData()
        }
        // 回到主线程更新 UI
        _data.value = response
    }
}
```

**错误 6：IllegalStateException - Fragment not attached**

```
错误信息：
java.lang.IllegalStateException: Fragment not attached to a context

原因：
在 Fragment 销毁后尝试访问 Context 或执行 UI 操作

解决方案：
```

```kotlin
// ❌ 错误写法
class MyFragment : Fragment() {
    fun loadData() {
        viewModel.data.observe(viewLifecycleOwner) { data ->
            // Fragment 可能已销毁
            requireContext().showToast(data)
        }
    }
}

// ✅ 正确写法
class MyFragment : Fragment() {
    fun loadData() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.data.collect { data ->
                // 自动在生命周期结束时取消
                context?.showToast(data)
            }
        }
    }
    
    // 或者检查 isAdded
    private fun safeOperation() {
        if (isAdded && context != null) {
            // 安全执行操作
        }
    }
}
```

**错误 7：OutOfMemoryError**

```
错误信息：
java.lang.OutOfMemoryError: Failed to allocate memory

原因：
- 加载过大的图片
- 内存泄漏
- 创建过多对象

解决方案：
```

```kotlin
// 1. 图片加载优化
// 使用 Coil 或 Glide，自动处理图片缩放
AsyncImage(
    model = ImageRequest.Builder(LocalContext.current)
        .data(imageUrl)
        .size(Size(200, 200))  // 指定目标尺寸
        .build(),
    contentDescription = null
)

// 2. 手动加载 Bitmap 时压缩
fun decodeSampledBitmap(path: String, reqWidth: Int, reqHeight: Int): Bitmap {
    val options = BitmapFactory.Options().apply {
        inJustDecodeBounds = true
    }
    BitmapFactory.decodeFile(path, options)
    
    options.inSampleSize = calculateInSampleSize(options, reqWidth, reqHeight)
    options.inJustDecodeBounds = false
    
    return BitmapFactory.decodeFile(path, options)
}

// 3. 及时释放资源
override fun onDestroy() {
    super.onDestroy()
    bitmap?.recycle()
    bitmap = null
}
```

**错误 8：ANR (Application Not Responding)**

```
错误信息：
应用无响应弹窗

原因：
- 主线程执行耗时操作超过 5 秒
- BroadcastReceiver 处理超过 10 秒
- Service 前台操作超过 20 秒

解决方案：
```

```kotlin
// ❌ 错误写法：主线程耗时操作
fun processLargeData() {
    val result = heavyComputation()  // 阻塞主线程
    updateUI(result)
}

// ✅ 正确写法：移到后台线程
fun processLargeData() {
    viewModelScope.launch {
        val result = withContext(Dispatchers.Default) {
            heavyComputation()
        }
        updateUI(result)
    }
}

// 使用 StrictMode 检测主线程耗时操作
if (BuildConfig.DEBUG) {
    StrictMode.setThreadPolicy(
        StrictMode.ThreadPolicy.Builder()
            .detectAll()
            .penaltyLog()
            .build()
    )
}
```

### 15.3 权限相关错误

**错误 9：SecurityException - Permission Denial**

```
错误信息：
java.lang.SecurityException: Permission Denial

原因：
- 未在 Manifest 中声明权限
- 未请求运行时权限
- 权限被用户拒绝

解决方案：
```

```kotlin
// 1. 在 AndroidManifest.xml 中声明权限
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" 
    android:maxSdkVersion="32" />

// 2. 运行时请求权限
private val requestPermissionLauncher = registerForActivityResult(
    ActivityResultContracts.RequestPermission()
) { isGranted ->
    if (isGranted) {
        // 权限已授予，执行操作
        openCamera()
    } else {
        // 权限被拒绝，显示说明
        showPermissionRationale()
    }
}

fun checkAndRequestPermission() {
    when {
        ContextCompat.checkSelfPermission(
            this, Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED -> {
            openCamera()
        }
        shouldShowRequestPermissionRationale(Manifest.permission.CAMERA) -> {
            // 显示为什么需要这个权限
            showRationaleDialog {
                requestPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
        }
        else -> {
            requestPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }
}

// 3. 处理永久拒绝的情况
private fun showSettingsDialog() {
    AlertDialog.Builder(this)
        .setTitle("需要权限")
        .setMessage("请在设置中开启相机权限")
        .setPositiveButton("去设置") { _, _ ->
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.fromParts("package", packageName, null)
            }
            startActivity(intent)
        }
        .setNegativeButton("取消", null)
        .show()
}
```

### 15.4 网络相关错误

**错误 10：UnknownHostException / SocketTimeoutException**

```
错误信息：
java.net.UnknownHostException: Unable to resolve host
java.net.SocketTimeoutException: connect timed out

原因：
- 无网络连接
- DNS 解析失败
- 服务器响应超时

解决方案：
```

```kotlin
// 1. 检查网络状态
class NetworkUtils(private val context: Context) {
    
    fun isNetworkAvailable(): Boolean {
        val connectivityManager = context.getSystemService(
            Context.CONNECTIVITY_SERVICE
        ) as ConnectivityManager
        
        val network = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return false
        
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }
}

// 2. 配置超时时间
val okHttpClient = OkHttpClient.Builder()
    .connectTimeout(30, TimeUnit.SECONDS)
    .readTimeout(30, TimeUnit.SECONDS)
    .writeTimeout(30, TimeUnit.SECONDS)
    .retryOnConnectionFailure(true)
    .build()

// 3. 统一错误处理
sealed class NetworkResult<T> {
    data class Success<T>(val data: T) : NetworkResult<T>()
    data class Error<T>(val message: String, val code: Int? = null) : NetworkResult<T>()
    class Loading<T> : NetworkResult<T>()
}

suspend fun <T> safeApiCall(apiCall: suspend () -> T): NetworkResult<T> {
    return try {
        NetworkResult.Success(apiCall())
    } catch (e: UnknownHostException) {
        NetworkResult.Error("无网络连接，请检查网络设置")
    } catch (e: SocketTimeoutException) {
        NetworkResult.Error("连接超时，请稍后重试")
    } catch (e: HttpException) {
        NetworkResult.Error("服务器错误: ${e.code()}", e.code())
    } catch (e: Exception) {
        NetworkResult.Error("未知错误: ${e.message}")
    }
}
```

**错误 11：ClearText HTTP 不允许**

```
错误信息：
CLEARTEXT communication not permitted

原因：
Android 9+ 默认禁止明文 HTTP 请求

解决方案：
```

```xml
<!-- 方案 1：允许特定域名（推荐） -->
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">example.com</domain>
        <domain includeSubdomains="true">10.0.2.2</domain> <!-- 模拟器本地 -->
    </domain-config>
</network-security-config>

<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config">
</application>

<!-- 方案 2：允许所有明文（不推荐，仅开发用） -->
<application
    android:usesCleartextTraffic="true">
</application>
```

**错误 12：SSL 证书错误**

```
错误信息：
javax.net.ssl.SSLHandshakeException: Certificate not trusted

原因：
- 使用自签名证书
- 证书过期
- 证书链不完整

解决方案：
```

```kotlin
// 开发环境：信任所有证书（仅调试用，生产环境禁止！）
fun getUnsafeOkHttpClient(): OkHttpClient {
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })
    
    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, SecureRandom())
    
    return OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as X509TrustManager)
        .hostnameVerifier { _, _ -> true }
        .build()
}

// 生产环境：使用证书固定
val certificatePinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

### 15.5 Compose 相关错误

**错误 13：Compose 重组问题**

```
问题：
UI 不更新或频繁重组导致性能问题

原因：
- 状态管理不当
- 未使用 remember
- 不稳定的参数

解决方案：
```

```kotlin
// ❌ 错误：每次重组都创建新对象
@Composable
fun BadExample() {
    val list = listOf(1, 2, 3)  // 每次重组都创建新列表
    ItemList(items = list)
}

// ✅ 正确：使用 remember 缓存
@Composable
fun GoodExample() {
    val list = remember { listOf(1, 2, 3) }
    ItemList(items = list)
}

// ❌ 错误：lambda 导致重组
@Composable
fun BadButton(viewModel: MyViewModel) {
    Button(onClick = { viewModel.doSomething() }) {  // 每次创建新 lambda
        Text("Click")
    }
}

// ✅ 正确：使用 remember 包装 lambda
@Composable
fun GoodButton(viewModel: MyViewModel) {
    val onClick = remember { { viewModel.doSomething() } }
    Button(onClick = onClick) {
        Text("Click")
    }
}

// ❌ 错误：在 Composable 中直接修改状态
@Composable
fun BadCounter() {
    var count = 0  // 不会触发重组
    Button(onClick = { count++ }) {
        Text("Count: $count")
    }
}

// ✅ 正确：使用 mutableStateOf
@Composable
fun GoodCounter() {
    var count by remember { mutableStateOf(0) }
    Button(onClick = { count++ }) {
        Text("Count: $count")
    }
}
```

**错误 14：LaunchedEffect 使用不当**

```kotlin
// ❌ 错误：key 为 Unit，只执行一次
@Composable
fun BadEffect(userId: String) {
    LaunchedEffect(Unit) {
        viewModel.loadUser(userId)  // userId 变化时不会重新加载
    }
}

// ✅ 正确：使用正确的 key
@Composable
fun GoodEffect(userId: String) {
    LaunchedEffect(userId) {
        viewModel.loadUser(userId)  // userId 变化时重新执行
    }
}

// ❌ 错误：在 LaunchedEffect 外收集 Flow
@Composable
fun BadFlowCollection(viewModel: MyViewModel) {
    viewModel.data.collect { }  // 错误！会阻塞组合
}

// ✅ 正确：使用 collectAsState
@Composable
fun GoodFlowCollection(viewModel: MyViewModel) {
    val data by viewModel.data.collectAsState(initial = emptyList())
}
```

### 15.6 Room 数据库错误

**错误 15：Room 迁移失败**

```
错误信息：
Room cannot verify the data integrity

原因：
数据库 schema 变更但未提供迁移策略

解决方案：
```

```kotlin
// 方案 1：破坏性迁移（开发阶段）
Room.databaseBuilder(context, AppDatabase::class.java, "app_db")
    .fallbackToDestructiveMigration()  // 数据会丢失！
    .build()

// 方案 2：提供迁移策略（生产环境）
val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(database: SupportSQLiteDatabase) {
        // 添加新列
        database.execSQL("ALTER TABLE users ADD COLUMN age INTEGER DEFAULT 0 NOT NULL")
    }
}

val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(database: SupportSQLiteDatabase) {
        // 创建新表
        database.execSQL("""
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                title TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
    }
}

Room.databaseBuilder(context, AppDatabase::class.java, "app_db")
    .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
    .build()
```

**错误 16：Room 主线程查询**

```
错误信息：
Cannot access database on the main thread

解决方案：
```

```kotlin
// ❌ 错误：主线程查询
fun getUser(id: Long): User {
    return userDao.getById(id)  // 阻塞主线程
}

// ✅ 正确：使用 suspend 函数
@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE id = :id")
    suspend fun getById(id: Long): User?
}

// 在协程中调用
viewModelScope.launch {
    val user = userDao.getById(1)
}

// 或使用 Flow 响应式查询
@Dao
interface UserDao {
    @Query("SELECT * FROM users")
    fun getAll(): Flow<List<User>>
}
```

### 15.7 Hilt 依赖注入错误

**错误 17：Hilt 注入失败**

```
错误信息：
Cannot create an instance of ViewModel

原因：
- 未添加 @HiltViewModel 注解
- 未在 Activity/Fragment 添加 @AndroidEntryPoint
- 缺少 @Inject 构造函数

解决方案：
```

```kotlin
// 1. Application 必须添加 @HiltAndroidApp
@HiltAndroidApp
class MyApplication : Application()

// 2. Activity/Fragment 必须添加 @AndroidEntryPoint
@AndroidEntryPoint
class MainActivity : AppCompatActivity()

// 3. ViewModel 必须添加 @HiltViewModel 和 @Inject
@HiltViewModel
class MainViewModel @Inject constructor(
    private val repository: UserRepository
) : ViewModel()

// 4. 提供依赖的 Module
@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    
    @Provides
    @Singleton
    fun provideUserRepository(
        apiService: ApiService,
        userDao: UserDao
    ): UserRepository {
        return UserRepositoryImpl(apiService, userDao)
    }
}

// 5. 接口绑定
@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {
    
    @Binds
    abstract fun bindUserRepository(
        impl: UserRepositoryImpl
    ): UserRepository
}
```

### 15.8 ProGuard/R8 混淆错误

**错误 18：混淆后崩溃**

```
错误信息：
ClassNotFoundException 或 NoSuchMethodException

原因：
混淆移除或重命名了需要反射访问的类

解决方案：
```

```proguard
# proguard-rules.pro

# 保留数据类（用于 JSON 序列化）
-keep class com.example.myapp.data.model.** { *; }

# 保留 Retrofit 接口
-keep,allowobfuscation interface * {
    @retrofit2.http.* <methods>;
}

# 保留 Room 实体
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *

# 保留枚举
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# 保留 Parcelable
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# 保留 Serializable
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# Gson 特定规则
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.google.gson.** { *; }
```

### 15.9 生命周期相关错误

**错误 19：配置变更导致数据丢失**

```
问题：
屏幕旋转后数据丢失

原因：
Activity 在配置变更时会重建

解决方案：
```

```kotlin
// 方案 1：使用 ViewModel（推荐）
class MainViewModel : ViewModel() {
    private val _data = MutableStateFlow<List<Item>>(emptyList())
    val data: StateFlow<List<Item>> = _data.asStateFlow()
    
    // ViewModel 在配置变更时保留
}

// 方案 2：使用 SavedStateHandle
class MainViewModel(
    private val savedStateHandle: SavedStateHandle
) : ViewModel() {
    
    var searchQuery: String
        get() = savedStateHandle["query"] ?: ""
        set(value) { savedStateHandle["query"] = value }
}

// 方案 3：onSaveInstanceState（简单数据）
override fun onSaveInstanceState(outState: Bundle) {
    super.onSaveInstanceState(outState)
    outState.putString("key", value)
}

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val value = savedInstanceState?.getString("key")
}

// 方案 4：禁止配置变更重建（不推荐）
// AndroidManifest.xml
<activity
    android:name=".MainActivity"
    android:configChanges="orientation|screenSize|keyboardHidden" />
```

**错误 20：内存泄漏**

```
问题：
Activity/Fragment 无法被回收

常见原因：
- 静态变量持有 Context
- 匿名内部类持有外部引用
- Handler 消息未清理
- 未取消的监听器/回调

解决方案：
```

```kotlin
// ❌ 错误：静态持有 Activity
companion object {
    var activity: MainActivity? = null  // 内存泄漏！
}

// ✅ 正确：使用 WeakReference
companion object {
    var activityRef: WeakReference<MainActivity>? = null
}

// ❌ 错误：匿名内部类
val callback = object : Callback {
    override fun onResult() {
        // 持有外部 Activity 引用
        updateUI()
    }
}

// ✅ 正确：使用静态内部类 + WeakReference
class SafeCallback(activity: MainActivity) : Callback {
    private val activityRef = WeakReference(activity)
    
    override fun onResult() {
        activityRef.get()?.updateUI()
    }
}

// ❌ 错误：Handler 未清理
private val handler = Handler(Looper.getMainLooper())

fun startTask() {
    handler.postDelayed({ doSomething() }, 10000)
}

// ✅ 正确：在 onDestroy 中清理
override fun onDestroy() {
    super.onDestroy()
    handler.removeCallbacksAndMessages(null)
}

// ✅ 最佳实践：使用 lifecycleScope
lifecycleScope.launch {
    delay(10000)
    doSomething()  // 自动在生命周期结束时取消
}
```

### 15.10 常用调试技巧

```kotlin
// 1. 打印调用堆栈
fun debugMethod() {
    Log.d("DEBUG", "Called from: ${Thread.currentThread().stackTrace.joinToString("\n")}")
}

// 2. 检查当前线程
fun checkThread() {
    if (Looper.myLooper() == Looper.getMainLooper()) {
        Log.d("DEBUG", "Running on main thread")
    } else {
        Log.d("DEBUG", "Running on background thread: ${Thread.currentThread().name}")
    }
}

// 3. 测量执行时间
inline fun <T> measureTimeAndLog(tag: String, block: () -> T): T {
    val start = System.currentTimeMillis()
    val result = block()
    val duration = System.currentTimeMillis() - start
    Log.d("PERFORMANCE", "$tag took ${duration}ms")
    return result
}

// 使用
val result = measureTimeAndLog("loadData") {
    repository.loadData()
}

// 4. Compose 重组追踪
@Composable
fun MyComposable() {
    SideEffect {
        Log.d("RECOMPOSITION", "MyComposable recomposed")
    }
    // ...
}

// 5. 网络请求日志
val loggingInterceptor = HttpLoggingInterceptor().apply {
    level = if (BuildConfig.DEBUG) {
        HttpLoggingInterceptor.Level.BODY
    } else {
        HttpLoggingInterceptor.Level.NONE
    }
}
```


---

## 16. 附录

### 16.1 常用 ADB 命令

```bash
# 设备管理
adb devices                          # 列出连接的设备
adb -s <device_id> shell             # 连接指定设备

# 应用管理
adb install app.apk                  # 安装应用
adb install -r app.apk               # 覆盖安装
adb uninstall com.example.app        # 卸载应用
adb shell pm list packages           # 列出所有包名
adb shell pm clear com.example.app   # 清除应用数据

# 文件操作
adb push local_file /sdcard/         # 推送文件到设备
adb pull /sdcard/file local_path     # 从设备拉取文件

# 日志
adb logcat                           # 查看日志
adb logcat -c                        # 清除日志
adb logcat *:E                       # 只显示错误
adb logcat -s TAG                    # 过滤指定 TAG

# 调试
adb shell am start -n com.example.app/.MainActivity  # 启动 Activity
adb shell am force-stop com.example.app              # 强制停止应用
adb shell dumpsys activity activities                # 查看 Activity 栈
adb shell dumpsys meminfo com.example.app            # 查看内存使用

# 截图和录屏
adb shell screencap /sdcard/screen.png               # 截图
adb shell screenrecord /sdcard/video.mp4             # 录屏

# 网络
adb reverse tcp:8080 tcp:8080        # 端口转发（设备访问电脑）
adb forward tcp:8080 tcp:8080        # 端口转发（电脑访问设备）
```

### 16.2 Gradle 常用命令

```bash
# 构建
./gradlew assembleDebug              # 构建 Debug 版本
./gradlew assembleRelease            # 构建 Release 版本
./gradlew bundleRelease              # 构建 AAB（上传 Play Store）

# 清理
./gradlew clean                      # 清理构建缓存
./gradlew cleanBuildCache            # 清理 Gradle 缓存

# 依赖
./gradlew app:dependencies           # 查看依赖树
./gradlew dependencyUpdates          # 检查依赖更新（需要插件）

# 测试
./gradlew test                       # 运行单元测试
./gradlew connectedAndroidTest       # 运行仪器测试

# 分析
./gradlew lint                       # 运行 Lint 检查
./gradlew signingReport              # 查看签名信息

# 其他
./gradlew --refresh-dependencies     # 强制刷新依赖
./gradlew --stop                     # 停止 Gradle 守护进程
./gradlew tasks                      # 列出所有可用任务
```

### 16.3 快捷键速查（Android Studio）

```
代码编辑：
Ctrl + Space          代码补全
Ctrl + Shift + Space  智能补全
Ctrl + P              参数提示
Ctrl + Q              快速文档
Ctrl + B              跳转到定义
Ctrl + Alt + B        跳转到实现
Ctrl + U              跳转到父类
Alt + Enter           快速修复
Ctrl + Alt + L        格式化代码
Ctrl + Alt + O        优化导入
Ctrl + D              复制行
Ctrl + Y              删除行
Ctrl + /              行注释
Ctrl + Shift + /      块注释

导航：
Ctrl + N              查找类
Ctrl + Shift + N      查找文件
Ctrl + Shift + F      全局搜索
Ctrl + E              最近文件
Ctrl + Tab            切换标签
Ctrl + F12            文件结构
Alt + 左/右           前进/后退

重构：
Shift + F6            重命名
Ctrl + Alt + M        提取方法
Ctrl + Alt + V        提取变量
Ctrl + Alt + F        提取字段
Ctrl + Alt + C        提取常量

调试：
F8                    单步跳过
F7                    单步进入
Shift + F8            单步跳出
F9                    继续执行
Ctrl + F8             切换断点
Ctrl + Shift + F8     查看所有断点

运行：
Shift + F10           运行
Shift + F9            调试
Ctrl + F2             停止
```

### 16.4 学习资源推荐

**官方资源：**
- [Android 开发者官网](https://developer.android.com/)
- [Android Jetpack](https://developer.android.com/jetpack)
- [Kotlin 官方文档](https://kotlinlang.org/docs/home.html)
- [Material Design](https://material.io/)

**开源项目学习：**
- [Now in Android](https://github.com/android/nowinandroid) - Google 官方示例
- [Jetpack Compose Samples](https://github.com/android/compose-samples)
- [Architecture Samples](https://github.com/android/architecture-samples)

**社区资源：**
- [Android Weekly](https://androidweekly.net/) - 每周 Android 开发资讯
- [ProAndroidDev](https://proandroiddev.com/) - Medium 上的 Android 开发博客
- [掘金 Android](https://juejin.cn/android) - 中文技术社区

---

## 总结

本笔记涵盖了 Android 开发的核心知识点，从基础概念到高级特性，从传统 View 到 Jetpack Compose，从本地存储到网络请求。

**学习路线建议：**

1. **入门阶段**：掌握 Kotlin 基础 → 理解四大组件 → 学会基本 UI 开发
2. **进阶阶段**：深入 Jetpack 组件 → 掌握 MVVM 架构 → 学习 Compose
3. **高级阶段**：性能优化 → 自动化测试 → 架构设计

**最佳实践总结：**

- 使用 Kotlin 作为主要开发语言
- 采用 MVVM + Clean Architecture 架构
- 使用 Jetpack Compose 构建 UI
- 使用 Hilt 进行依赖注入
- 使用协程处理异步操作
- 编写单元测试和 UI 测试
- 使用 LeakCanary 检测内存泄漏
- 遵循 Material Design 设计规范

持续学习，保持对新技术的关注，Android 开发生态在不断演进，掌握核心原理才能以不变应万变。
