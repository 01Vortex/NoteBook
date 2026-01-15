> React Native 是 Facebook 开发的跨平台移动应用框架
> 本笔记基于 React Native 0.72+ / Expo SDK 49+ / TypeScript

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [项目结构](#3-项目结构)
4. [核心组件](#4-核心组件)
5. [样式与布局](#5-样式与布局)
6. [导航系统](#6-导航系统)
7. [状态管理](#7-状态管理)
8. [网络请求](#8-网络请求)
9. [本地存储](#9-本地存储)
10. [原生模块](#10-原生模块)
11. [动画系统](#11-动画系统)
12. [性能优化](#12-性能优化)
13. [调试与测试](#13-调试与测试)
14. [打包发布](#14-打包发布)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 React Native？

React Native（简称 RN）是一个使用 JavaScript 和 React 构建原生移动应用的框架。与传统的混合应用（WebView）不同，RN 渲染的是真正的原生组件，因此性能更接近原生应用。

**核心特点**：
- **跨平台**：一套代码同时运行在 iOS 和 Android
- **原生渲染**：使用原生 UI 组件，非 WebView
- **热重载**：修改代码后即时预览，开发效率高
- **React 生态**：可复用 React 的知识和大量第三方库
- **原生扩展**：可以编写原生代码扩展功能

### 1.2 工作原理

```
JavaScript 代码
      ↓
  JS Bundle
      ↓
JavaScript 引擎（Hermes/JSC）
      ↓
   Bridge（桥接层）
      ↓
原生模块（iOS/Android）
      ↓
   原生 UI
```

**新架构（New Architecture）**：
React Native 0.68+ 引入了新架构，主要改进：
- **JSI（JavaScript Interface）**：替代 Bridge，直接调用原生方法
- **Fabric**：新的渲染系统，支持同步渲染
- **TurboModules**：按需加载原生模块，启动更快

### 1.3 Expo vs React Native CLI

| 特性 | Expo | React Native CLI |
|------|------|------------------|
| 上手难度 | 简单 | 较复杂 |
| 原生代码 | 受限（需 eject） | 完全控制 |
| 构建方式 | 云端构建 | 本地构建 |
| 包体积 | 较大 | 可优化 |
| 适用场景 | 快速原型、中小项目 | 大型项目、需要原生模块 |

**建议**：
- 新手或快速开发：使用 Expo
- 需要深度定制或原生模块：使用 React Native CLI

---

## 2. 环境搭建

### 2.1 Expo 方式（推荐新手）

```bash
# 安装 Expo CLI
npm install -g expo-cli

# 创建项目
npx create-expo-app MyApp --template expo-template-blank-typescript

# 进入项目
cd MyApp

# 启动开发服务器
npx expo start
```

**运行应用**：
- 手机安装 Expo Go App，扫描二维码
- 按 `i` 启动 iOS 模拟器（需要 Xcode）
- 按 `a` 启动 Android 模拟器（需要 Android Studio）

### 2.2 React Native CLI 方式

#### 环境要求

**macOS（开发 iOS + Android）**：
```bash
# 安装 Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装 Node.js
brew install node

# 安装 Watchman（文件监听）
brew install watchman

# 安装 CocoaPods（iOS 依赖管理）
sudo gem install cocoapods

# 安装 Xcode（App Store 下载）
# 安装 Xcode Command Line Tools
xcode-select --install

# 安装 JDK
brew install --cask zulu11

# 安装 Android Studio
# 下载地址：https://developer.android.com/studio
```

**Windows（仅开发 Android）**：
```powershell
# 安装 Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 安装 Node.js 和 JDK
choco install -y nodejs-lts microsoft-openjdk11

# 安装 Android Studio
# 下载地址：https://developer.android.com/studio
```

#### Android 环境配置

```bash
# 设置环境变量（macOS ~/.zshrc 或 ~/.bash_profile）
export ANDROID_HOME=$HOME/Library/Android/sdk
export PATH=$PATH:$ANDROID_HOME/emulator
export PATH=$PATH:$ANDROID_HOME/platform-tools

# Windows 设置系统环境变量
# ANDROID_HOME = C:\Users\你的用户名\AppData\Local\Android\Sdk
```

#### 创建项目

```bash
# 创建项目
npx react-native@latest init MyApp

# 进入项目
cd MyApp

# 运行 iOS（需要 macOS）
npx react-native run-ios

# 运行 Android
npx react-native run-android
```

### 2.3 TypeScript 配置

```bash
# Expo 项目（创建时选择 TypeScript 模板）
npx create-expo-app MyApp --template expo-template-blank-typescript

# RN CLI 项目（创建时自带 TypeScript）
npx react-native@latest init MyApp
```

**tsconfig.json**：
```json
{
  "extends": "expo/tsconfig.base",
  "compilerOptions": {
    "strict": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@components/*": ["src/components/*"],
      "@screens/*": ["src/screens/*"],
      "@hooks/*": ["src/hooks/*"],
      "@utils/*": ["src/utils/*"]
    }
  },
  "include": ["**/*.ts", "**/*.tsx"],
  "exclude": ["node_modules"]
}
```

---

## 3. 项目结构

### 3.1 推荐目录结构

```
MyApp/
├── src/
│   ├── components/          # 可复用组件
│   │   ├── common/          # 通用组件
│   │   │   ├── Button.tsx
│   │   │   ├── Input.tsx
│   │   │   └── index.ts
│   │   └── business/        # 业务组件
│   ├── screens/             # 页面/屏幕
│   │   ├── Home/
│   │   │   ├── index.tsx
│   │   │   └── styles.ts
│   │   ├── Profile/
│   │   └── Settings/
│   ├── navigation/          # 导航配置
│   │   ├── index.tsx
│   │   ├── MainNavigator.tsx
│   │   └── AuthNavigator.tsx
│   ├── hooks/               # 自定义 Hooks
│   ├── services/            # API 服务
│   ├── store/               # 状态管理
│   ├── utils/               # 工具函数
│   ├── constants/           # 常量
│   ├── types/               # TypeScript 类型
│   ├── assets/              # 静态资源
│   │   ├── images/
│   │   └── fonts/
│   └── theme/               # 主题配置
├── App.tsx                  # 入口文件
├── app.json                 # 应用配置
├── package.json
├── tsconfig.json
└── babel.config.js
```

### 3.2 入口文件

**App.tsx**：
```tsx
import React from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { NavigationContainer } from '@react-navigation/native';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import RootNavigator from './src/navigation';
import { ThemeProvider } from './src/theme';

const queryClient = new QueryClient();

export default function App() {
  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <QueryClientProvider client={queryClient}>
        <SafeAreaProvider>
          <ThemeProvider>
            <NavigationContainer>
              <RootNavigator />
            </NavigationContainer>
          </ThemeProvider>
        </SafeAreaProvider>
      </QueryClientProvider>
    </GestureHandlerRootView>
  );
}
```

---

## 4. 核心组件

### 4.1 基础组件

React Native 提供了一套跨平台的核心组件，它们会被渲染为对应平台的原生组件。

#### View - 容器组件

`View` 是最基础的容器组件，类似于 Web 中的 `div`：

```tsx
import React from 'react';
import { View, StyleSheet } from 'react-native';

const Container: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <View style={styles.container}>
      <View style={styles.header}>
        {/* 头部内容 */}
      </View>
      <View style={styles.content}>
        {children}
      </View>
      <View style={styles.footer}>
        {/* 底部内容 */}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
  },
  header: {
    height: 60,
    backgroundColor: '#007AFF',
    justifyContent: 'center',
    alignItems: 'center',
  },
  content: {
    flex: 1,
    padding: 16,
  },
  footer: {
    height: 50,
    borderTopWidth: 1,
    borderTopColor: '#eee',
  },
});

export default Container;
```

#### Text - 文本组件

所有文本必须放在 `Text` 组件内：

```tsx
import React from 'react';
import { Text, StyleSheet } from 'react-native';

// 基础用法
const BasicText = () => (
  <Text style={styles.text}>Hello React Native!</Text>
);

// 嵌套文本（继承样式）
const NestedText = () => (
  <Text style={styles.paragraph}>
    这是一段普通文本，
    <Text style={styles.bold}>这是加粗文本</Text>，
    <Text style={styles.link} onPress={() => console.log('点击了链接')}>
      这是可点击的链接
    </Text>
  </Text>
);

// 文本截断
const TruncatedText = () => (
  <Text numberOfLines={2} ellipsizeMode="tail" style={styles.text}>
    这是一段很长的文本，当超过两行时会显示省略号...
    这是一段很长的文本，当超过两行时会显示省略号...
  </Text>
);

// 可选择的文本
const SelectableText = () => (
  <Text selectable style={styles.text}>
    这段文本可以被选择和复制
  </Text>
);

const styles = StyleSheet.create({
  text: {
    fontSize: 16,
    color: '#333',
    lineHeight: 24,
  },
  paragraph: {
    fontSize: 14,
    color: '#666',
  },
  bold: {
    fontWeight: 'bold',
  },
  link: {
    color: '#007AFF',
    textDecorationLine: 'underline',
  },
});
```

#### Image - 图片组件

```tsx
import React from 'react';
import { Image, StyleSheet, View } from 'react-native';

const ImageExamples = () => {
  return (
    <View>
      {/* 本地图片 */}
      <Image
        source={require('./assets/logo.png')}
        style={styles.localImage}
      />

      {/* 网络图片（必须指定宽高） */}
      <Image
        source={{ uri: 'https://example.com/image.png' }}
        style={styles.networkImage}
        resizeMode="cover"
      />

      {/* Base64 图片 */}
      <Image
        source={{ uri: 'data:image/png;base64,iVBORw0KGgo...' }}
        style={styles.base64Image}
      />

      {/* 带加载状态的图片 */}
      <Image
        source={{ uri: 'https://example.com/image.png' }}
        style={styles.networkImage}
        onLoadStart={() => console.log('开始加载')}
        onLoad={() => console.log('加载完成')}
        onError={(e) => console.log('加载失败', e.nativeEvent.error)}
        defaultSource={require('./assets/placeholder.png')} // iOS only
      />
    </View>
  );
};

const styles = StyleSheet.create({
  localImage: {
    width: 100,
    height: 100,
  },
  networkImage: {
    width: 200,
    height: 150,
    borderRadius: 8,
  },
  base64Image: {
    width: 50,
    height: 50,
  },
});
```

**推荐使用 expo-image 或 react-native-fast-image**：
```tsx
import { Image } from 'expo-image';

const OptimizedImage = () => (
  <Image
    source={{ uri: 'https://example.com/image.png' }}
    style={{ width: 200, height: 200 }}
    contentFit="cover"
    placeholder={blurhash}
    transition={200}
  />
);
```

#### TextInput - 输入框

```tsx
import React, { useState, useRef } from 'react';
import { TextInput, View, StyleSheet, Platform } from 'react-native';

const InputExamples = () => {
  const [text, setText] = useState('');
  const [password, setPassword] = useState('');
  const passwordRef = useRef<TextInput>(null);

  return (
    <View style={styles.container}>
      {/* 基础输入框 */}
      <TextInput
        style={styles.input}
        value={text}
        onChangeText={setText}
        placeholder="请输入内容"
        placeholderTextColor="#999"
      />

      {/* 密码输入框 */}
      <TextInput
        ref={passwordRef}
        style={styles.input}
        value={password}
        onChangeText={setPassword}
        placeholder="请输入密码"
        secureTextEntry
        autoCapitalize="none"
        autoCorrect={false}
      />

      {/* 多行输入框 */}
      <TextInput
        style={[styles.input, styles.multiline]}
        multiline
        numberOfLines={4}
        textAlignVertical="top" // Android
        placeholder="请输入多行内容"
      />

      {/* 数字键盘 */}
      <TextInput
        style={styles.input}
        keyboardType="numeric"
        placeholder="请输入数字"
      />

      {/* 邮箱键盘 */}
      <TextInput
        style={styles.input}
        keyboardType="email-address"
        autoCapitalize="none"
        placeholder="请输入邮箱"
      />

      {/* 搜索框 */}
      <TextInput
        style={styles.input}
        returnKeyType="search"
        onSubmitEditing={() => console.log('搜索')}
        placeholder="搜索..."
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  input: {
    height: 48,
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    paddingHorizontal: 12,
    marginBottom: 12,
    fontSize: 16,
    backgroundColor: '#fff',
  },
  multiline: {
    height: 120,
    paddingTop: 12,
  },
});
```

#### ScrollView - 滚动视图

```tsx
import React from 'react';
import { ScrollView, View, Text, StyleSheet, RefreshControl } from 'react-native';

const ScrollViewExample = () => {
  const [refreshing, setRefreshing] = React.useState(false);

  const onRefresh = React.useCallback(() => {
    setRefreshing(true);
    // 模拟刷新
    setTimeout(() => setRefreshing(false), 2000);
  }, []);

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }
    >
      {Array.from({ length: 20 }).map((_, index) => (
        <View key={index} style={styles.item}>
          <Text>Item {index + 1}</Text>
        </View>
      ))}
    </ScrollView>
  );
};

// 水平滚动
const HorizontalScrollView = () => (
  <ScrollView
    horizontal
    showsHorizontalScrollIndicator={false}
    contentContainerStyle={styles.horizontalContent}
  >
    {Array.from({ length: 10 }).map((_, index) => (
      <View key={index} style={styles.horizontalItem}>
        <Text>Tab {index + 1}</Text>
      </View>
    ))}
  </ScrollView>
);

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  content: {
    padding: 16,
  },
  item: {
    height: 80,
    backgroundColor: '#f0f0f0',
    marginBottom: 12,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
  },
  horizontalContent: {
    paddingHorizontal: 16,
  },
  horizontalItem: {
    width: 100,
    height: 40,
    backgroundColor: '#007AFF',
    marginRight: 12,
    borderRadius: 20,
    justifyContent: 'center',
    alignItems: 'center',
  },
});
```

### 4.2 列表组件

#### FlatList - 高性能列表

`FlatList` 是 RN 中最常用的列表组件，支持懒加载和回收机制：

```tsx
import React, { useState, useCallback } from 'react';
import {
  FlatList,
  View,
  Text,
  StyleSheet,
  RefreshControl,
  ActivityIndicator,
} from 'react-native';

interface Item {
  id: string;
  title: string;
  description: string;
}

const FlatListExample = () => {
  const [data, setData] = useState<Item[]>(generateData(20));
  const [refreshing, setRefreshing] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  // 下拉刷新
  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    // 模拟请求
    await new Promise(resolve => setTimeout(resolve, 1500));
    setData(generateData(20));
    setRefreshing(false);
  }, []);

  // 上拉加载更多
  const onEndReached = useCallback(async () => {
    if (loadingMore) return;
    setLoadingMore(true);
    await new Promise(resolve => setTimeout(resolve, 1000));
    setData(prev => [...prev, ...generateData(10, prev.length)]);
    setLoadingMore(false);
  }, [loadingMore]);

  // 渲染列表项
  const renderItem = useCallback(({ item }: { item: Item }) => (
    <View style={styles.item}>
      <Text style={styles.title}>{item.title}</Text>
      <Text style={styles.description}>{item.description}</Text>
    </View>
  ), []);

  // 列表项 key
  const keyExtractor = useCallback((item: Item) => item.id, []);

  // 列表头部
  const ListHeader = () => (
    <View style={styles.header}>
      <Text style={styles.headerText}>列表头部</Text>
    </View>
  );

  // 列表尾部（加载更多指示器）
  const ListFooter = () => (
    loadingMore ? (
      <View style={styles.footer}>
        <ActivityIndicator size="small" color="#007AFF" />
        <Text style={styles.footerText}>加载中...</Text>
      </View>
    ) : null
  );

  // 空列表
  const ListEmpty = () => (
    <View style={styles.empty}>
      <Text>暂无数据</Text>
    </View>
  );

  // 分隔线
  const ItemSeparator = () => <View style={styles.separator} />;

  return (
    <FlatList
      data={data}
      renderItem={renderItem}
      keyExtractor={keyExtractor}
      ListHeaderComponent={ListHeader}
      ListFooterComponent={ListFooter}
      ListEmptyComponent={ListEmpty}
      ItemSeparatorComponent={ItemSeparator}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }
      onEndReached={onEndReached}
      onEndReachedThreshold={0.1}
      // 性能优化
      removeClippedSubviews={true}
      maxToRenderPerBatch={10}
      windowSize={5}
      initialNumToRender={10}
      getItemLayout={(data, index) => ({
        length: 80,
        offset: 80 * index,
        index,
      })}
    />
  );
};

function generateData(count: number, startIndex = 0): Item[] {
  return Array.from({ length: count }).map((_, index) => ({
    id: `item-${startIndex + index}`,
    title: `标题 ${startIndex + index + 1}`,
    description: `这是第 ${startIndex + index + 1} 项的描述`,
  }));
}

const styles = StyleSheet.create({
  item: {
    padding: 16,
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 4,
  },
  description: {
    fontSize: 14,
    color: '#666',
  },
  header: {
    padding: 16,
    backgroundColor: '#f5f5f5',
  },
  headerText: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  footer: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 16,
  },
  footerText: {
    marginLeft: 8,
    color: '#666',
  },
  empty: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 50,
  },
  separator: {
    height: 1,
    backgroundColor: '#eee',
  },
});
```

#### SectionList - 分组列表

```tsx
import React from 'react';
import { SectionList, View, Text, StyleSheet } from 'react-native';

interface Contact {
  id: string;
  name: string;
  phone: string;
}

interface Section {
  title: string;
  data: Contact[];
}

const SectionListExample = () => {
  const sections: Section[] = [
    {
      title: 'A',
      data: [
        { id: '1', name: 'Alice', phone: '123-456-7890' },
        { id: '2', name: 'Amy', phone: '123-456-7891' },
      ],
    },
    {
      title: 'B',
      data: [
        { id: '3', name: 'Bob', phone: '123-456-7892' },
        { id: '4', name: 'Ben', phone: '123-456-7893' },
      ],
    },
    // ...更多分组
  ];

  const renderItem = ({ item }: { item: Contact }) => (
    <View style={styles.item}>
      <Text style={styles.name}>{item.name}</Text>
      <Text style={styles.phone}>{item.phone}</Text>
    </View>
  );

  const renderSectionHeader = ({ section }: { section: Section }) => (
    <View style={styles.sectionHeader}>
      <Text style={styles.sectionTitle}>{section.title}</Text>
    </View>
  );

  return (
    <SectionList
      sections={sections}
      renderItem={renderItem}
      renderSectionHeader={renderSectionHeader}
      keyExtractor={(item) => item.id}
      stickySectionHeadersEnabled={true}
    />
  );
};

const styles = StyleSheet.create({
  item: {
    padding: 16,
    backgroundColor: '#fff',
  },
  name: {
    fontSize: 16,
    fontWeight: '500',
  },
  phone: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
  sectionHeader: {
    padding: 8,
    paddingHorizontal: 16,
    backgroundColor: '#f0f0f0',
  },
  sectionTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
  },
});
```

### 4.3 交互组件

#### TouchableOpacity - 可点击组件

```tsx
import React from 'react';
import { TouchableOpacity, Text, StyleSheet, View } from 'react-native';

const TouchableExample = () => {
  return (
    <View style={styles.container}>
      {/* 基础按钮 */}
      <TouchableOpacity
        style={styles.button}
        onPress={() => console.log('点击')}
        activeOpacity={0.7}
      >
        <Text style={styles.buttonText}>点击我</Text>
      </TouchableOpacity>

      {/* 禁用状态 */}
      <TouchableOpacity
        style={[styles.button, styles.disabled]}
        disabled={true}
      >
        <Text style={[styles.buttonText, styles.disabledText]}>禁用按钮</Text>
      </TouchableOpacity>

      {/* 长按 */}
      <TouchableOpacity
        style={styles.button}
        onLongPress={() => console.log('长按')}
        delayLongPress={500}
      >
        <Text style={styles.buttonText}>长按我</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  button: {
    backgroundColor: '#007AFF',
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderRadius: 8,
    marginBottom: 12,
    alignItems: 'center',
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  disabled: {
    backgroundColor: '#ccc',
  },
  disabledText: {
    color: '#999',
  },
});
```

#### Pressable - 更灵活的可点击组件（推荐）

```tsx
import React from 'react';
import { Pressable, Text, StyleSheet, View } from 'react-native';

const PressableExample = () => {
  return (
    <View style={styles.container}>
      {/* 动态样式 */}
      <Pressable
        style={({ pressed }) => [
          styles.button,
          pressed && styles.buttonPressed,
        ]}
        onPress={() => console.log('点击')}
      >
        {({ pressed }) => (
          <Text style={[styles.buttonText, pressed && styles.textPressed]}>
            {pressed ? '按下中...' : '点击我'}
          </Text>
        )}
      </Pressable>

      {/* 涟漪效果（Android） */}
      <Pressable
        style={styles.button}
        android_ripple={{ color: 'rgba(255,255,255,0.3)' }}
        onPress={() => console.log('点击')}
      >
        <Text style={styles.buttonText}>涟漪效果</Text>
      </Pressable>

      {/* 点击区域扩展 */}
      <Pressable
        style={styles.smallButton}
        hitSlop={{ top: 20, bottom: 20, left: 20, right: 20 }}
        onPress={() => console.log('点击')}
      >
        <Text style={styles.buttonText}>小按钮</Text>
      </Pressable>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  button: {
    backgroundColor: '#007AFF',
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderRadius: 8,
    marginBottom: 12,
    alignItems: 'center',
  },
  buttonPressed: {
    backgroundColor: '#0056b3',
    transform: [{ scale: 0.98 }],
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  textPressed: {
    opacity: 0.8,
  },
  smallButton: {
    backgroundColor: '#007AFF',
    padding: 8,
    borderRadius: 4,
    alignSelf: 'flex-start',
  },
});
```

#### Modal - 模态框

```tsx
import React, { useState } from 'react';
import { Modal, View, Text, Pressable, StyleSheet } from 'react-native';

const ModalExample = () => {
  const [visible, setVisible] = useState(false);

  return (
    <View style={styles.container}>
      <Pressable style={styles.button} onPress={() => setVisible(true)}>
        <Text style={styles.buttonText}>打开弹窗</Text>
      </Pressable>

      <Modal
        visible={visible}
        transparent={true}
        animationType="fade"
        onRequestClose={() => setVisible(false)}
      >
        <View style={styles.overlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>提示</Text>
            <Text style={styles.modalText}>这是一个模态框</Text>
            <View style={styles.modalButtons}>
              <Pressable
                style={[styles.modalButton, styles.cancelButton]}
                onPress={() => setVisible(false)}
              >
                <Text style={styles.cancelText}>取消</Text>
              </Pressable>
              <Pressable
                style={[styles.modalButton, styles.confirmButton]}
                onPress={() => {
                  console.log('确认');
                  setVisible(false);
                }}
              >
                <Text style={styles.confirmText}>确认</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  button: {
    backgroundColor: '#007AFF',
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderRadius: 8,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
  },
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  modalContent: {
    width: '80%',
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 20,
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 12,
  },
  modalText: {
    fontSize: 14,
    color: '#666',
    marginBottom: 20,
  },
  modalButtons: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
  },
  modalButton: {
    paddingVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 6,
    marginLeft: 12,
  },
  cancelButton: {
    backgroundColor: '#f0f0f0',
  },
  confirmButton: {
    backgroundColor: '#007AFF',
  },
  cancelText: {
    color: '#333',
  },
  confirmText: {
    color: '#fff',
  },
});
```

### 4.4 平台特定组件

```tsx
import React from 'react';
import {
  Platform,
  View,
  Text,
  StyleSheet,
  StatusBar,
  SafeAreaView,
} from 'react-native';

// 平台判断
const PlatformExample = () => {
  return (
    <SafeAreaView style={styles.container}>
      <StatusBar
        barStyle={Platform.OS === 'ios' ? 'dark-content' : 'light-content'}
        backgroundColor="#007AFF"
      />
      <View style={styles.content}>
        <Text>当前平台: {Platform.OS}</Text>
        <Text>系统版本: {Platform.Version}</Text>
        {Platform.OS === 'ios' && <Text>这是 iOS 特有内容</Text>}
        {Platform.OS === 'android' && <Text>这是 Android 特有内容</Text>}
      </View>
    </SafeAreaView>
  );
};

// 平台特定样式
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
  },
  content: {
    padding: 16,
  },
  // 使用 Platform.select
  box: {
    ...Platform.select({
      ios: {
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
      },
      android: {
        elevation: 4,
      },
    }),
  },
});

// 平台特定文件
// Button.ios.tsx - iOS 专用
// Button.android.tsx - Android 专用
// 导入时自动选择: import Button from './Button';
```

---

## 5. 样式与布局

### 5.1 StyleSheet

React Native 使用 JavaScript 对象定义样式，与 CSS 类似但有一些区别：

```tsx
import { StyleSheet } from 'react-native';

const styles = StyleSheet.create({
  // 容器样式
  container: {
    flex: 1,
    backgroundColor: '#ffffff',
    padding: 16,
  },
  
  // 文本样式
  title: {
    fontSize: 24,
    fontWeight: 'bold',      // 'normal' | 'bold' | '100'-'900'
    color: '#333333',
    textAlign: 'center',     // 'auto' | 'left' | 'right' | 'center' | 'justify'
    lineHeight: 32,
    letterSpacing: 0.5,
    textTransform: 'uppercase', // 'none' | 'capitalize' | 'uppercase' | 'lowercase'
    textDecorationLine: 'underline', // 'none' | 'underline' | 'line-through'
  },
  
  // 盒模型
  box: {
    width: 100,
    height: 100,
    margin: 10,              // 或 marginTop, marginRight, marginBottom, marginLeft
    marginHorizontal: 10,    // 左右 margin
    marginVertical: 10,      // 上下 margin
    padding: 10,             // 同上
    paddingHorizontal: 10,
    paddingVertical: 10,
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    borderTopLeftRadius: 8,  // 单独设置圆角
  },
  
  // 阴影（iOS）
  shadowIOS: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
  },
  
  // 阴影（Android）
  shadowAndroid: {
    elevation: 4,
  },
  
  // 定位
  absolute: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    zIndex: 10,
  },
});

// 样式组合
const combinedStyles = StyleSheet.compose(styles.container, styles.box);

// 扁平化样式
const flattenedStyle = StyleSheet.flatten([styles.container, styles.box]);
```

### 5.2 Flexbox 布局

React Native 默认使用 Flexbox 布局，但有一些与 Web 的区别：
- 默认 `flexDirection: 'column'`（Web 默认 row）
- 默认 `alignContent: 'flex-start'`
- `flex` 只接受单个数字

```tsx
import React from 'react';
import { View, Text, StyleSheet } from 'react-native';

const FlexboxExample = () => {
  return (
    <View style={styles.container}>
      {/* 主轴方向 */}
      <View style={styles.row}>
        <View style={styles.box1}><Text>1</Text></View>
        <View style={styles.box2}><Text>2</Text></View>
        <View style={styles.box3}><Text>3</Text></View>
      </View>

      {/* 主轴对齐 */}
      <View style={[styles.row, { justifyContent: 'space-between' }]}>
        <View style={styles.box1}><Text>1</Text></View>
        <View style={styles.box2}><Text>2</Text></View>
        <View style={styles.box3}><Text>3</Text></View>
      </View>

      {/* 交叉轴对齐 */}
      <View style={[styles.row, { alignItems: 'center', height: 100 }]}>
        <View style={[styles.box1, { height: 30 }]}><Text>1</Text></View>
        <View style={[styles.box2, { height: 50 }]}><Text>2</Text></View>
        <View style={[styles.box3, { height: 70 }]}><Text>3</Text></View>
      </View>

      {/* flex 比例 */}
      <View style={styles.row}>
        <View style={[styles.box1, { flex: 1 }]}><Text>1</Text></View>
        <View style={[styles.box2, { flex: 2 }]}><Text>2</Text></View>
        <View style={[styles.box3, { flex: 1 }]}><Text>3</Text></View>
      </View>

      {/* 换行 */}
      <View style={[styles.row, { flexWrap: 'wrap' }]}>
        {Array.from({ length: 8 }).map((_, i) => (
          <View key={i} style={styles.wrapItem}><Text>{i + 1}</Text></View>
        ))}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
  },
  row: {
    flexDirection: 'row',
    marginBottom: 16,
    backgroundColor: '#f0f0f0',
    padding: 8,
  },
  box1: {
    width: 50,
    height: 50,
    backgroundColor: '#FF6B6B',
    justifyContent: 'center',
    alignItems: 'center',
  },
  box2: {
    width: 50,
    height: 50,
    backgroundColor: '#4ECDC4',
    justifyContent: 'center',
    alignItems: 'center',
  },
  box3: {
    width: 50,
    height: 50,
    backgroundColor: '#45B7D1',
    justifyContent: 'center',
    alignItems: 'center',
  },
  wrapItem: {
    width: '23%',
    aspectRatio: 1,
    backgroundColor: '#95E1D3',
    margin: '1%',
    justifyContent: 'center',
    alignItems: 'center',
  },
});
```

### 5.3 响应式设计

```tsx
import { Dimensions, useWindowDimensions, PixelRatio, StyleSheet } from 'react-native';

// 获取屏幕尺寸
const { width: SCREEN_WIDTH, height: SCREEN_HEIGHT } = Dimensions.get('window');

// 设计稿基准（以 375 宽度为基准）
const BASE_WIDTH = 375;

// 响应式尺寸计算
export const scale = (size: number) => (SCREEN_WIDTH / BASE_WIDTH) * size;
export const verticalScale = (size: number) => (SCREEN_HEIGHT / 812) * size;
export const moderateScale = (size: number, factor = 0.5) =>
  size + (scale(size) - size) * factor;

// 使用 Hook 获取动态尺寸
const ResponsiveComponent = () => {
  const { width, height, fontScale } = useWindowDimensions();
  
  return (
    <View style={[styles.container, { width: width * 0.9 }]}>
      <Text style={{ fontSize: 16 / fontScale }}>响应式文本</Text>
    </View>
  );
};

// 响应式样式
const styles = StyleSheet.create({
  container: {
    width: scale(343),
    padding: scale(16),
    borderRadius: scale(8),
  },
  title: {
    fontSize: moderateScale(18),
    lineHeight: moderateScale(24),
  },
});

// 监听屏幕变化（横竖屏切换）
import { useEffect, useState } from 'react';

const useOrientation = () => {
  const [orientation, setOrientation] = useState<'portrait' | 'landscape'>(
    Dimensions.get('window').width < Dimensions.get('window').height
      ? 'portrait'
      : 'landscape'
  );

  useEffect(() => {
    const subscription = Dimensions.addEventListener('change', ({ window }) => {
      setOrientation(window.width < window.height ? 'portrait' : 'landscape');
    });
    return () => subscription.remove();
  }, []);

  return orientation;
};
```

### 5.4 主题系统

```tsx
// src/theme/index.tsx
import React, { createContext, useContext, useState } from 'react';
import { useColorScheme } from 'react-native';

// 定义主题类型
interface Theme {
  dark: boolean;
  colors: {
    primary: string;
    background: string;
    card: string;
    text: string;
    textSecondary: string;
    border: string;
    error: string;
    success: string;
  };
  spacing: {
    xs: number;
    sm: number;
    md: number;
    lg: number;
    xl: number;
  };
  typography: {
    h1: { fontSize: number; fontWeight: string };
    h2: { fontSize: number; fontWeight: string };
    body: { fontSize: number; fontWeight: string };
    caption: { fontSize: number; fontWeight: string };
  };
}

// 浅色主题
const lightTheme: Theme = {
  dark: false,
  colors: {
    primary: '#007AFF',
    background: '#FFFFFF',
    card: '#F8F8F8',
    text: '#333333',
    textSecondary: '#666666',
    border: '#E5E5E5',
    error: '#FF3B30',
    success: '#34C759',
  },
  spacing: {
    xs: 4,
    sm: 8,
    md: 16,
    lg: 24,
    xl: 32,
  },
  typography: {
    h1: { fontSize: 28, fontWeight: 'bold' },
    h2: { fontSize: 22, fontWeight: '600' },
    body: { fontSize: 16, fontWeight: 'normal' },
    caption: { fontSize: 12, fontWeight: 'normal' },
  },
};

// 深色主题
const darkTheme: Theme = {
  ...lightTheme,
  dark: true,
  colors: {
    primary: '#0A84FF',
    background: '#000000',
    card: '#1C1C1E',
    text: '#FFFFFF',
    textSecondary: '#8E8E93',
    border: '#38383A',
    error: '#FF453A',
    success: '#32D74B',
  },
};

// Context
const ThemeContext = createContext<{
  theme: Theme;
  toggleTheme: () => void;
  isDark: boolean;
}>({
  theme: lightTheme,
  toggleTheme: () => {},
  isDark: false,
});

// Provider
export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const colorScheme = useColorScheme();
  const [isDark, setIsDark] = useState(colorScheme === 'dark');

  const theme = isDark ? darkTheme : lightTheme;
  const toggleTheme = () => setIsDark(!isDark);

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, isDark }}>
      {children}
    </ThemeContext.Provider>
  );
};

// Hook
export const useTheme = () => useContext(ThemeContext);

// 使用示例
const ThemedComponent = () => {
  const { theme, toggleTheme, isDark } = useTheme();

  return (
    <View style={{ backgroundColor: theme.colors.background, padding: theme.spacing.md }}>
      <Text style={{ color: theme.colors.text, ...theme.typography.h1 }}>
        标题
      </Text>
      <Pressable onPress={toggleTheme}>
        <Text style={{ color: theme.colors.primary }}>
          切换到{isDark ? '浅色' : '深色'}模式
        </Text>
      </Pressable>
    </View>
  );
};
```

---

## 6. 导航系统

### 6.1 安装 React Navigation

```bash
# 核心包
npm install @react-navigation/native

# 依赖
npm install react-native-screens react-native-safe-area-context

# 导航器（按需安装）
npm install @react-navigation/native-stack    # 原生栈导航
npm install @react-navigation/bottom-tabs     # 底部标签导航
npm install @react-navigation/drawer          # 抽屉导航
npm install @react-navigation/material-top-tabs # 顶部标签导航

# Expo 项目
npx expo install react-native-screens react-native-safe-area-context
```

### 6.2 栈导航（Stack Navigator）

```tsx
// src/navigation/index.tsx
import React from 'react';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import HomeScreen from '../screens/Home';
import DetailScreen from '../screens/Detail';
import SettingsScreen from '../screens/Settings';

// 定义路由参数类型
export type RootStackParamList = {
  Home: undefined;
  Detail: { id: string; title: string };
  Settings: { userId?: string };
};

const Stack = createNativeStackNavigator<RootStackParamList>();

const RootNavigator = () => {
  return (
    <Stack.Navigator
      initialRouteName="Home"
      screenOptions={{
        headerStyle: { backgroundColor: '#007AFF' },
        headerTintColor: '#fff',
        headerTitleStyle: { fontWeight: 'bold' },
        animation: 'slide_from_right',
      }}
    >
      <Stack.Screen
        name="Home"
        component={HomeScreen}
        options={{ title: '首页' }}
      />
      <Stack.Screen
        name="Detail"
        component={DetailScreen}
        options={({ route }) => ({ title: route.params.title })}
      />
      <Stack.Screen
        name="Settings"
        component={SettingsScreen}
        options={{
          title: '设置',
          presentation: 'modal', // 模态展示
        }}
      />
    </Stack.Navigator>
  );
};

export default RootNavigator;
```

```tsx
// src/screens/Home/index.tsx
import React from 'react';
import { View, Text, Pressable, StyleSheet } from 'react-native';
import { NativeStackScreenProps } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../navigation';

type Props = NativeStackScreenProps<RootStackParamList, 'Home'>;

const HomeScreen: React.FC<Props> = ({ navigation }) => {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>首页</Text>
      
      {/* 导航到详情页 */}
      <Pressable
        style={styles.button}
        onPress={() => navigation.navigate('Detail', { id: '123', title: '商品详情' })}
      >
        <Text style={styles.buttonText}>查看详情</Text>
      </Pressable>

      {/* 导航到设置页 */}
      <Pressable
        style={styles.button}
        onPress={() => navigation.navigate('Settings', {})}
      >
        <Text style={styles.buttonText}>打开设置</Text>
      </Pressable>

      {/* 使用 push 添加新的栈 */}
      <Pressable
        style={styles.button}
        onPress={() => navigation.push('Detail', { id: '456', title: '另一个详情' })}
      >
        <Text style={styles.buttonText}>Push 详情</Text>
      </Pressable>
    </View>
  );
};

// src/screens/Detail/index.tsx
import React from 'react';
import { View, Text, Pressable, StyleSheet } from 'react-native';
import { NativeStackScreenProps } from '@react-navigation/native-stack';
import { RootStackParamList } from '../../navigation';

type Props = NativeStackScreenProps<RootStackParamList, 'Detail'>;

const DetailScreen: React.FC<Props> = ({ route, navigation }) => {
  const { id, title } = route.params;

  return (
    <View style={styles.container}>
      <Text style={styles.title}>{title}</Text>
      <Text>ID: {id}</Text>

      {/* 返回上一页 */}
      <Pressable style={styles.button} onPress={() => navigation.goBack()}>
        <Text style={styles.buttonText}>返回</Text>
      </Pressable>

      {/* 返回到指定页面 */}
      <Pressable style={styles.button} onPress={() => navigation.popToTop()}>
        <Text style={styles.buttonText}>返回首页</Text>
      </Pressable>

      {/* 替换当前页面 */}
      <Pressable
        style={styles.button}
        onPress={() => navigation.replace('Settings', {})}
      >
        <Text style={styles.buttonText}>替换为设置页</Text>
      </Pressable>

      {/* 设置页面参数 */}
      <Pressable
        style={styles.button}
        onPress={() => navigation.setParams({ title: '新标题' })}
      >
        <Text style={styles.buttonText}>修改标题</Text>
      </Pressable>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 16,
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 12,
    borderRadius: 8,
    marginBottom: 12,
    alignItems: 'center',
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
  },
});
```

### 6.3 底部标签导航（Tab Navigator）

```tsx
import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { Ionicons } from '@expo/vector-icons';
import HomeScreen from '../screens/Home';
import SearchScreen from '../screens/Search';
import ProfileScreen from '../screens/Profile';

export type TabParamList = {
  HomeTab: undefined;
  SearchTab: undefined;
  ProfileTab: undefined;
};

const Tab = createBottomTabNavigator<TabParamList>();

const TabNavigator = () => {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName: keyof typeof Ionicons.glyphMap;

          switch (route.name) {
            case 'HomeTab':
              iconName = focused ? 'home' : 'home-outline';
              break;
            case 'SearchTab':
              iconName = focused ? 'search' : 'search-outline';
              break;
            case 'ProfileTab':
              iconName = focused ? 'person' : 'person-outline';
              break;
            default:
              iconName = 'help-outline';
          }

          return <Ionicons name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: '#007AFF',
        tabBarInactiveTintColor: 'gray',
        headerShown: false,
      })}
    >
      <Tab.Screen
        name="HomeTab"
        component={HomeScreen}
        options={{ tabBarLabel: '首页' }}
      />
      <Tab.Screen
        name="SearchTab"
        component={SearchScreen}
        options={{
          tabBarLabel: '搜索',
          tabBarBadge: 3, // 显示角标
        }}
      />
      <Tab.Screen
        name="ProfileTab"
        component={ProfileScreen}
        options={{ tabBarLabel: '我的' }}
      />
    </Tab.Navigator>
  );
};

export default TabNavigator;
```

### 6.4 抽屉导航（Drawer Navigator）

```tsx
import React from 'react';
import { createDrawerNavigator } from '@react-navigation/drawer';
import { View, Text, StyleSheet, Pressable } from 'react-native';
import HomeScreen from '../screens/Home';
import SettingsScreen from '../screens/Settings';

const Drawer = createDrawerNavigator();

// 自定义抽屉内容
const CustomDrawerContent = ({ navigation }: any) => {
  return (
    <View style={styles.drawerContent}>
      <View style={styles.userInfo}>
        <View style={styles.avatar} />
        <Text style={styles.userName}>用户名</Text>
      </View>
      <Pressable
        style={styles.drawerItem}
        onPress={() => navigation.navigate('Home')}
      >
        <Text>首页</Text>
      </Pressable>
      <Pressable
        style={styles.drawerItem}
        onPress={() => navigation.navigate('Settings')}
      >
        <Text>设置</Text>
      </Pressable>
    </View>
  );
};

const DrawerNavigator = () => {
  return (
    <Drawer.Navigator
      drawerContent={(props) => <CustomDrawerContent {...props} />}
      screenOptions={{
        drawerPosition: 'left',
        drawerType: 'front',
      }}
    >
      <Drawer.Screen name="Home" component={HomeScreen} />
      <Drawer.Screen name="Settings" component={SettingsScreen} />
    </Drawer.Navigator>
  );
};

const styles = StyleSheet.create({
  drawerContent: {
    flex: 1,
    paddingTop: 50,
  },
  userInfo: {
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
    alignItems: 'center',
  },
  avatar: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#ddd',
    marginBottom: 12,
  },
  userName: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  drawerItem: {
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
});
```

### 6.5 嵌套导航

```tsx
// 常见模式：Tab 嵌套 Stack
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';

const Stack = createNativeStackNavigator();
const Tab = createBottomTabNavigator();

// 首页栈
const HomeStack = () => (
  <Stack.Navigator>
    <Stack.Screen name="HomeMain" component={HomeScreen} />
    <Stack.Screen name="HomeDetail" component={DetailScreen} />
  </Stack.Navigator>
);

// 个人中心栈
const ProfileStack = () => (
  <Stack.Navigator>
    <Stack.Screen name="ProfileMain" component={ProfileScreen} />
    <Stack.Screen name="ProfileSettings" component={SettingsScreen} />
  </Stack.Navigator>
);

// 主导航
const MainNavigator = () => (
  <Tab.Navigator>
    <Tab.Screen name="Home" component={HomeStack} options={{ headerShown: false }} />
    <Tab.Screen name="Profile" component={ProfileStack} options={{ headerShown: false }} />
  </Tab.Navigator>
);

// 根导航（包含登录流程）
const RootNavigator = () => {
  const isLoggedIn = useAuth();

  return (
    <Stack.Navigator screenOptions={{ headerShown: false }}>
      {isLoggedIn ? (
        <Stack.Screen name="Main" component={MainNavigator} />
      ) : (
        <Stack.Screen name="Auth" component={AuthNavigator} />
      )}
    </Stack.Navigator>
  );
};
```

### 6.6 导航 Hooks

```tsx
import {
  useNavigation,
  useRoute,
  useFocusEffect,
  useIsFocused,
  useNavigationState,
} from '@react-navigation/native';
import { useCallback } from 'react';

const MyComponent = () => {
  // 获取 navigation 对象
  const navigation = useNavigation();
  
  // 获取当前路由参数
  const route = useRoute();
  
  // 判断页面是否聚焦
  const isFocused = useIsFocused();
  
  // 获取导航状态
  const state = useNavigationState(state => state);
  const currentRouteName = useNavigationState(
    state => state.routes[state.index].name
  );

  // 页面聚焦时执行（类似 useEffect，但在页面获得焦点时触发）
  useFocusEffect(
    useCallback(() => {
      console.log('页面聚焦');
      // 获取数据等操作

      return () => {
        console.log('页面失焦');
        // 清理操作
      };
    }, [])
  );

  return (
    <View>
      <Text>当前页面: {route.name}</Text>
      <Text>是否聚焦: {isFocused ? '是' : '否'}</Text>
    </View>
  );
};
```

---

## 7. 状态管理

### 7.1 React Context + useReducer

适合中小型应用的状态管理方案：

```tsx
// src/store/AuthContext.tsx
import React, { createContext, useContext, useReducer, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';

// 状态类型
interface AuthState {
  isLoading: boolean;
  isLoggedIn: boolean;
  user: User | null;
  token: string | null;
}

interface User {
  id: string;
  name: string;
  email: string;
  avatar?: string;
}

// Action 类型
type AuthAction =
  | { type: 'RESTORE_TOKEN'; token: string | null; user: User | null }
  | { type: 'LOGIN'; token: string; user: User }
  | { type: 'LOGOUT' }
  | { type: 'UPDATE_USER'; user: Partial<User> };

// 初始状态
const initialState: AuthState = {
  isLoading: true,
  isLoggedIn: false,
  user: null,
  token: null,
};

// Reducer
const authReducer = (state: AuthState, action: AuthAction): AuthState => {
  switch (action.type) {
    case 'RESTORE_TOKEN':
      return {
        ...state,
        isLoading: false,
        isLoggedIn: !!action.token,
        token: action.token,
        user: action.user,
      };
    case 'LOGIN':
      return {
        ...state,
        isLoggedIn: true,
        token: action.token,
        user: action.user,
      };
    case 'LOGOUT':
      return {
        ...state,
        isLoggedIn: false,
        token: null,
        user: null,
      };
    case 'UPDATE_USER':
      return {
        ...state,
        user: state.user ? { ...state.user, ...action.user } : null,
      };
    default:
      return state;
  }
};

// Context
interface AuthContextType extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  updateUser: (user: Partial<User>) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Provider
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // 启动时恢复登录状态
  useEffect(() => {
    const restoreToken = async () => {
      try {
        const token = await AsyncStorage.getItem('token');
        const userJson = await AsyncStorage.getItem('user');
        const user = userJson ? JSON.parse(userJson) : null;
        dispatch({ type: 'RESTORE_TOKEN', token, user });
      } catch (e) {
        dispatch({ type: 'RESTORE_TOKEN', token: null, user: null });
      }
    };
    restoreToken();
  }, []);

  const login = async (email: string, password: string) => {
    // 调用登录 API
    const response = await fetch('/api/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    const { token, user } = await response.json();

    // 保存到本地
    await AsyncStorage.setItem('token', token);
    await AsyncStorage.setItem('user', JSON.stringify(user));

    dispatch({ type: 'LOGIN', token, user });
  };

  const logout = async () => {
    await AsyncStorage.multiRemove(['token', 'user']);
    dispatch({ type: 'LOGOUT' });
  };

  const updateUser = (user: Partial<User>) => {
    dispatch({ type: 'UPDATE_USER', user });
  };

  return (
    <AuthContext.Provider value={{ ...state, login, logout, updateUser }}>
      {children}
    </AuthContext.Provider>
  );
};

// Hook
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

### 7.2 Zustand（推荐）

轻量级状态管理库，API 简洁：

```bash
npm install zustand
```

```tsx
// src/store/useStore.ts
import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import AsyncStorage from '@react-native-async-storage/async-storage';

interface CartItem {
  id: string;
  name: string;
  price: number;
  quantity: number;
}

interface CartStore {
  items: CartItem[];
  totalPrice: number;
  addItem: (item: Omit<CartItem, 'quantity'>) => void;
  removeItem: (id: string) => void;
  updateQuantity: (id: string, quantity: number) => void;
  clearCart: () => void;
}

export const useCartStore = create<CartStore>()(
  persist(
    (set, get) => ({
      items: [],
      totalPrice: 0,

      addItem: (item) => {
        set((state) => {
          const existingItem = state.items.find((i) => i.id === item.id);
          if (existingItem) {
            return {
              items: state.items.map((i) =>
                i.id === item.id ? { ...i, quantity: i.quantity + 1 } : i
              ),
              totalPrice: state.totalPrice + item.price,
            };
          }
          return {
            items: [...state.items, { ...item, quantity: 1 }],
            totalPrice: state.totalPrice + item.price,
          };
        });
      },

      removeItem: (id) => {
        set((state) => {
          const item = state.items.find((i) => i.id === id);
          return {
            items: state.items.filter((i) => i.id !== id),
            totalPrice: state.totalPrice - (item ? item.price * item.quantity : 0),
          };
        });
      },

      updateQuantity: (id, quantity) => {
        set((state) => {
          const item = state.items.find((i) => i.id === id);
          if (!item) return state;
          
          const priceDiff = (quantity - item.quantity) * item.price;
          return {
            items: state.items.map((i) =>
              i.id === id ? { ...i, quantity } : i
            ),
            totalPrice: state.totalPrice + priceDiff,
          };
        });
      },

      clearCart: () => set({ items: [], totalPrice: 0 }),
    }),
    {
      name: 'cart-storage',
      storage: createJSONStorage(() => AsyncStorage),
    }
  )
);

// 使用
const CartScreen = () => {
  const { items, totalPrice, addItem, removeItem, clearCart } = useCartStore();

  return (
    <View>
      <FlatList
        data={items}
        renderItem={({ item }) => (
          <View>
            <Text>{item.name} x {item.quantity}</Text>
            <Pressable onPress={() => removeItem(item.id)}>
              <Text>删除</Text>
            </Pressable>
          </View>
        )}
      />
      <Text>总价: ¥{totalPrice}</Text>
      <Pressable onPress={clearCart}>
        <Text>清空购物车</Text>
      </Pressable>
    </View>
  );
};
```

### 7.3 React Query（服务端状态）

处理服务端数据的最佳方案：

```bash
npm install @tanstack/react-query
```

```tsx
// src/services/api.ts
import axios from 'axios';

const api = axios.create({
  baseURL: 'https://api.example.com',
  timeout: 10000,
});

export interface Product {
  id: string;
  name: string;
  price: number;
  image: string;
}

export const productApi = {
  getProducts: async (page: number): Promise<{ data: Product[]; hasMore: boolean }> => {
    const response = await api.get(`/products?page=${page}`);
    return response.data;
  },
  
  getProduct: async (id: string): Promise<Product> => {
    const response = await api.get(`/products/${id}`);
    return response.data;
  },
  
  createProduct: async (product: Omit<Product, 'id'>): Promise<Product> => {
    const response = await api.post('/products', product);
    return response.data;
  },
};

// src/hooks/useProducts.ts
import { useQuery, useMutation, useInfiniteQuery, useQueryClient } from '@tanstack/react-query';
import { productApi, Product } from '../services/api';

// 获取商品列表（分页）
export const useProducts = () => {
  return useInfiniteQuery({
    queryKey: ['products'],
    queryFn: ({ pageParam = 1 }) => productApi.getProducts(pageParam),
    getNextPageParam: (lastPage, pages) => 
      lastPage.hasMore ? pages.length + 1 : undefined,
    staleTime: 5 * 60 * 1000, // 5 分钟内不重新请求
  });
};

// 获取单个商品
export const useProduct = (id: string) => {
  return useQuery({
    queryKey: ['product', id],
    queryFn: () => productApi.getProduct(id),
    enabled: !!id, // id 存在时才请求
  });
};

// 创建商品
export const useCreateProduct = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: productApi.createProduct,
    onSuccess: () => {
      // 创建成功后刷新列表
      queryClient.invalidateQueries({ queryKey: ['products'] });
    },
  });
};

// 使用示例
const ProductListScreen = () => {
  const {
    data,
    isLoading,
    isError,
    error,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    refetch,
  } = useProducts();

  if (isLoading) return <ActivityIndicator />;
  if (isError) return <Text>Error: {error.message}</Text>;

  const products = data?.pages.flatMap(page => page.data) ?? [];

  return (
    <FlatList
      data={products}
      renderItem={({ item }) => <ProductItem product={item} />}
      keyExtractor={(item) => item.id}
      onEndReached={() => hasNextPage && fetchNextPage()}
      onEndReachedThreshold={0.5}
      ListFooterComponent={
        isFetchingNextPage ? <ActivityIndicator /> : null
      }
      refreshing={isLoading}
      onRefresh={refetch}
    />
  );
};
```

---

## 8. 网络请求

### 8.1 Fetch API

```tsx
// 基础请求
const fetchData = async () => {
  try {
    const response = await fetch('https://api.example.com/data');
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Fetch error:', error);
    throw error;
  }
};

// POST 请求
const postData = async (data: object) => {
  const response = await fetch('https://api.example.com/data', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(data),
  });
  
  return response.json();
};

// 上传文件
const uploadFile = async (uri: string) => {
  const formData = new FormData();
  formData.append('file', {
    uri,
    type: 'image/jpeg',
    name: 'photo.jpg',
  } as any);

  const response = await fetch('https://api.example.com/upload', {
    method: 'POST',
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    body: formData,
  });

  return response.json();
};
```

### 8.2 Axios 封装

```tsx
// src/services/request.ts
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

// 创建实例
const instance: AxiosInstance = axios.create({
  baseURL: 'https://api.example.com',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// 请求拦截器
instance.interceptors.request.use(
  async (config) => {
    // 添加 token
    const token = await AsyncStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    // 添加时间戳防止缓存
    if (config.method === 'get') {
      config.params = {
        ...config.params,
        _t: Date.now(),
      };
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 响应拦截器
instance.interceptors.response.use(
  (response: AxiosResponse) => {
    const { data } = response;
    
    // 根据业务状态码处理
    if (data.code === 0) {
      return data.data;
    }
    
    // 业务错误
    return Promise.reject(new Error(data.message || '请求失败'));
  },
  async (error) => {
    if (error.response) {
      const { status } = error.response;
      
      switch (status) {
        case 401:
          // token 过期，清除登录状态
          await AsyncStorage.removeItem('token');
          // 跳转登录页
          break;
        case 403:
          console.error('没有权限');
          break;
        case 404:
          console.error('资源不存在');
          break;
        case 500:
          console.error('服务器错误');
          break;
        default:
          console.error(`请求错误: ${status}`);
      }
    } else if (error.request) {
      console.error('网络错误，请检查网络连接');
    }
    
    return Promise.reject(error);
  }
);

// 封装请求方法
export const request = {
  get: <T>(url: string, config?: AxiosRequestConfig): Promise<T> =>
    instance.get(url, config),
    
  post: <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> =>
    instance.post(url, data, config),
    
  put: <T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> =>
    instance.put(url, data, config),
    
  delete: <T>(url: string, config?: AxiosRequestConfig): Promise<T> =>
    instance.delete(url, config),
};

export default instance;
```

### 8.3 网络状态监听

```tsx
import NetInfo, { NetInfoState } from '@react-native-community/netinfo';
import { useEffect, useState } from 'react';

// Hook
export const useNetworkStatus = () => {
  const [isConnected, setIsConnected] = useState<boolean | null>(null);
  const [networkType, setNetworkType] = useState<string | null>(null);

  useEffect(() => {
    const unsubscribe = NetInfo.addEventListener((state: NetInfoState) => {
      setIsConnected(state.isConnected);
      setNetworkType(state.type);
    });

    return () => unsubscribe();
  }, []);

  return { isConnected, networkType };
};

// 使用
const NetworkAwareComponent = () => {
  const { isConnected, networkType } = useNetworkStatus();

  if (isConnected === false) {
    return (
      <View style={styles.offline}>
        <Text>当前无网络连接</Text>
      </View>
    );
  }

  return (
    <View>
      <Text>网络类型: {networkType}</Text>
      {/* 正常内容 */}
    </View>
  );
};
```

---

## 9. 本地存储

### 9.1 AsyncStorage

```bash
npm install @react-native-async-storage/async-storage
```

```tsx
import AsyncStorage from '@react-native-async-storage/async-storage';

// 存储字符串
await AsyncStorage.setItem('username', 'john');

// 读取字符串
const username = await AsyncStorage.getItem('username');

// 存储对象（需要序列化）
const user = { id: 1, name: 'John' };
await AsyncStorage.setItem('user', JSON.stringify(user));

// 读取对象
const userJson = await AsyncStorage.getItem('user');
const userData = userJson ? JSON.parse(userJson) : null;

// 删除
await AsyncStorage.removeItem('username');

// 批量操作
await AsyncStorage.multiSet([
  ['key1', 'value1'],
  ['key2', 'value2'],
]);

const values = await AsyncStorage.multiGet(['key1', 'key2']);
// values = [['key1', 'value1'], ['key2', 'value2']]

await AsyncStorage.multiRemove(['key1', 'key2']);

// 清空所有
await AsyncStorage.clear();

// 获取所有 key
const keys = await AsyncStorage.getAllKeys();
```

### 9.2 封装存储工具

```tsx
// src/utils/storage.ts
import AsyncStorage from '@react-native-async-storage/async-storage';

class Storage {
  // 存储
  async set<T>(key: string, value: T): Promise<void> {
    try {
      const jsonValue = JSON.stringify(value);
      await AsyncStorage.setItem(key, jsonValue);
    } catch (e) {
      console.error('Storage set error:', e);
    }
  }

  // 读取
  async get<T>(key: string): Promise<T | null> {
    try {
      const jsonValue = await AsyncStorage.getItem(key);
      return jsonValue != null ? JSON.parse(jsonValue) : null;
    } catch (e) {
      console.error('Storage get error:', e);
      return null;
    }
  }

  // 删除
  async remove(key: string): Promise<void> {
    try {
      await AsyncStorage.removeItem(key);
    } catch (e) {
      console.error('Storage remove error:', e);
    }
  }

  // 清空
  async clear(): Promise<void> {
    try {
      await AsyncStorage.clear();
    } catch (e) {
      console.error('Storage clear error:', e);
    }
  }
}

export const storage = new Storage();

// 使用
await storage.set('user', { id: 1, name: 'John' });
const user = await storage.get<{ id: number; name: string }>('user');
```

### 9.3 MMKV（高性能存储）

```bash
npm install react-native-mmkv
```

```tsx
import { MMKV } from 'react-native-mmkv';

// 创建实例
const storage = new MMKV();

// 或创建加密实例
const secureStorage = new MMKV({
  id: 'secure-storage',
  encryptionKey: 'your-encryption-key',
});

// 存储
storage.set('username', 'john');
storage.set('age', 25);
storage.set('isLoggedIn', true);
storage.set('user', JSON.stringify({ id: 1, name: 'John' }));

// 读取
const username = storage.getString('username');
const age = storage.getNumber('age');
const isLoggedIn = storage.getBoolean('isLoggedIn');
const user = JSON.parse(storage.getString('user') || '{}');

// 删除
storage.delete('username');

// 检查是否存在
const hasUsername = storage.contains('username');

// 获取所有 key
const keys = storage.getAllKeys();

// 清空
storage.clearAll();

// 与 Zustand 集成
import { create } from 'zustand';
import { persist, createJSONStorage, StateStorage } from 'zustand/middleware';

const mmkvStorage: StateStorage = {
  setItem: (name, value) => storage.set(name, value),
  getItem: (name) => storage.getString(name) ?? null,
  removeItem: (name) => storage.delete(name),
};

const useStore = create(
  persist(
    (set) => ({
      // ...
    }),
    {
      name: 'app-storage',
      storage: createJSONStorage(() => mmkvStorage),
    }
  )
);
```

### 9.4 SecureStore（敏感数据）

```bash
npx expo install expo-secure-store
```

```tsx
import * as SecureStore from 'expo-secure-store';

// 存储敏感数据（如 token、密码）
await SecureStore.setItemAsync('token', 'your-secret-token');

// 读取
const token = await SecureStore.getItemAsync('token');

// 删除
await SecureStore.deleteItemAsync('token');

// 检查是否可用
const isAvailable = await SecureStore.isAvailableAsync();
```

---

## 10. 原生模块

### 10.1 使用 Expo 模块

Expo 提供了大量开箱即用的原生功能：

```bash
# 相机
npx expo install expo-camera

# 图片选择
npx expo install expo-image-picker

# 位置
npx expo install expo-location

# 通知
npx expo install expo-notifications

# 生物识别
npx expo install expo-local-authentication
```

```tsx
// 相机
import { Camera, CameraType } from 'expo-camera';

const CameraScreen = () => {
  const [permission, requestPermission] = Camera.useCameraPermissions();
  const [type, setType] = useState(CameraType.back);
  const cameraRef = useRef<Camera>(null);

  if (!permission?.granted) {
    return (
      <View>
        <Text>需要相机权限</Text>
        <Button title="授权" onPress={requestPermission} />
      </View>
    );
  }

  const takePicture = async () => {
    if (cameraRef.current) {
      const photo = await cameraRef.current.takePictureAsync();
      console.log(photo.uri);
    }
  };

  return (
    <Camera style={{ flex: 1 }} type={type} ref={cameraRef}>
      <Pressable onPress={takePicture}>
        <Text>拍照</Text>
      </Pressable>
    </Camera>
  );
};

// 图片选择
import * as ImagePicker from 'expo-image-picker';

const pickImage = async () => {
  const result = await ImagePicker.launchImageLibraryAsync({
    mediaTypes: ImagePicker.MediaTypeOptions.Images,
    allowsEditing: true,
    aspect: [4, 3],
    quality: 0.8,
  });

  if (!result.canceled) {
    console.log(result.assets[0].uri);
  }
};

// 位置
import * as Location from 'expo-location';

const getLocation = async () => {
  const { status } = await Location.requestForegroundPermissionsAsync();
  if (status !== 'granted') {
    console.log('位置权限被拒绝');
    return;
  }

  const location = await Location.getCurrentPositionAsync({});
  console.log(location.coords.latitude, location.coords.longitude);
};

// 生物识别
import * as LocalAuthentication from 'expo-local-authentication';

const authenticate = async () => {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const isEnrolled = await LocalAuthentication.isEnrolledAsync();

  if (hasHardware && isEnrolled) {
    const result = await LocalAuthentication.authenticateAsync({
      promptMessage: '请验证身份',
      fallbackLabel: '使用密码',
    });

    if (result.success) {
      console.log('验证成功');
    }
  }
};
```

### 10.2 Linking（打开外部链接）

```tsx
import { Linking, Alert } from 'react-native';

// 打开网页
const openURL = async (url: string) => {
  const supported = await Linking.canOpenURL(url);
  if (supported) {
    await Linking.openURL(url);
  } else {
    Alert.alert('无法打开链接');
  }
};

// 打开电话
await Linking.openURL('tel:+1234567890');

// 打开短信
await Linking.openURL('sms:+1234567890');

// 打开邮件
await Linking.openURL('mailto:example@email.com?subject=Hello&body=Hi there');

// 打开地图
await Linking.openURL('https://maps.google.com/?q=37.7749,-122.4194');

// 打开应用设置
await Linking.openSettings();

// 监听深度链接
useEffect(() => {
  const handleDeepLink = (event: { url: string }) => {
    console.log('Deep link:', event.url);
    // 解析 URL 并导航
  };

  // 应用已打开时收到链接
  const subscription = Linking.addEventListener('url', handleDeepLink);

  // 应用从链接启动
  Linking.getInitialURL().then((url) => {
    if (url) {
      handleDeepLink({ url });
    }
  });

  return () => subscription.remove();
}, []);
```

### 10.3 分享功能

```tsx
import { Share } from 'react-native';

const shareContent = async () => {
  try {
    const result = await Share.share({
      message: '这是分享的内容',
      url: 'https://example.com', // iOS only
      title: '分享标题',
    });

    if (result.action === Share.sharedAction) {
      if (result.activityType) {
        console.log('分享到:', result.activityType);
      } else {
        console.log('分享成功');
      }
    } else if (result.action === Share.dismissedAction) {
      console.log('取消分享');
    }
  } catch (error) {
    console.error('分享失败:', error);
  }
};
```

### 10.4 剪贴板

```tsx
import * as Clipboard from 'expo-clipboard';

// 复制文本
const copyToClipboard = async (text: string) => {
  await Clipboard.setStringAsync(text);
};

// 读取剪贴板
const getClipboardContent = async () => {
  const text = await Clipboard.getStringAsync();
  return text;
};

// 监听剪贴板变化
useEffect(() => {
  const subscription = Clipboard.addClipboardListener(({ contentTypes }) => {
    console.log('剪贴板内容变化');
  });

  return () => subscription.remove();
}, []);
```

---

## 11. 动画系统

### 11.1 Animated API

React Native 内置的动画 API：

```tsx
import React, { useRef, useEffect } from 'react';
import { Animated, View, StyleSheet, Pressable, Easing } from 'react-native';

const AnimatedExample = () => {
  // 创建动画值
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const slideAnim = useRef(new Animated.Value(-100)).current;
  const scaleAnim = useRef(new Animated.Value(1)).current;

  // 淡入动画
  const fadeIn = () => {
    Animated.timing(fadeAnim, {
      toValue: 1,
      duration: 500,
      useNativeDriver: true, // 使用原生驱动，性能更好
    }).start();
  };

  // 滑入动画
  const slideIn = () => {
    Animated.spring(slideAnim, {
      toValue: 0,
      friction: 5,
      tension: 40,
      useNativeDriver: true,
    }).start();
  };

  // 缩放动画
  const pulse = () => {
    Animated.sequence([
      Animated.timing(scaleAnim, {
        toValue: 1.2,
        duration: 200,
        useNativeDriver: true,
      }),
      Animated.timing(scaleAnim, {
        toValue: 1,
        duration: 200,
        useNativeDriver: true,
      }),
    ]).start();
  };

  // 并行动画
  const animateAll = () => {
    Animated.parallel([
      Animated.timing(fadeAnim, { toValue: 1, duration: 500, useNativeDriver: true }),
      Animated.spring(slideAnim, { toValue: 0, useNativeDriver: true }),
    ]).start();
  };

  // 循环动画
  const rotateAnim = useRef(new Animated.Value(0)).current;
  
  useEffect(() => {
    Animated.loop(
      Animated.timing(rotateAnim, {
        toValue: 1,
        duration: 2000,
        easing: Easing.linear,
        useNativeDriver: true,
      })
    ).start();
  }, []);

  const spin = rotateAnim.interpolate({
    inputRange: [0, 1],
    outputRange: ['0deg', '360deg'],
  });

  return (
    <View style={styles.container}>
      {/* 淡入 */}
      <Animated.View style={[styles.box, { opacity: fadeAnim }]}>
        <Pressable onPress={fadeIn}>
          <Text>淡入</Text>
        </Pressable>
      </Animated.View>

      {/* 滑入 */}
      <Animated.View
        style={[styles.box, { transform: [{ translateX: slideAnim }] }]}
      >
        <Pressable onPress={slideIn}>
          <Text>滑入</Text>
        </Pressable>
      </Animated.View>

      {/* 缩放 */}
      <Animated.View
        style={[styles.box, { transform: [{ scale: scaleAnim }] }]}
      >
        <Pressable onPress={pulse}>
          <Text>缩放</Text>
        </Pressable>
      </Animated.View>

      {/* 旋转 */}
      <Animated.View
        style={[styles.box, { transform: [{ rotate: spin }] }]}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 100,
    height: 100,
    backgroundColor: '#007AFF',
    marginVertical: 10,
    justifyContent: 'center',
    alignItems: 'center',
  },
});
```

### 11.2 Reanimated（推荐）

更强大的动画库，支持手势交互：

```bash
npm install react-native-reanimated
```

```tsx
import React from 'react';
import { View, StyleSheet, Pressable, Text } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withSpring,
  withTiming,
  withRepeat,
  withSequence,
  Easing,
  interpolate,
  runOnJS,
} from 'react-native-reanimated';

const ReanimatedExample = () => {
  // 共享值
  const offset = useSharedValue(0);
  const scale = useSharedValue(1);
  const rotation = useSharedValue(0);

  // 动画样式
  const animatedStyles = useAnimatedStyle(() => ({
    transform: [
      { translateX: offset.value },
      { scale: scale.value },
      { rotate: `${rotation.value}deg` },
    ],
  }));

  // 弹性动画
  const handleSpring = () => {
    offset.value = withSpring(offset.value === 0 ? 100 : 0, {
      damping: 10,
      stiffness: 100,
    });
  };

  // 时间动画
  const handleTiming = () => {
    scale.value = withTiming(scale.value === 1 ? 1.5 : 1, {
      duration: 300,
      easing: Easing.bezier(0.25, 0.1, 0.25, 1),
    });
  };

  // 序列动画
  const handleSequence = () => {
    scale.value = withSequence(
      withTiming(1.2, { duration: 150 }),
      withTiming(0.9, { duration: 150 }),
      withTiming(1, { duration: 150 })
    );
  };

  // 循环动画
  const handleRepeat = () => {
    rotation.value = withRepeat(
      withTiming(360, { duration: 1000, easing: Easing.linear }),
      -1, // 无限循环
      false // 不反向
    );
  };

  // 停止动画
  const handleStop = () => {
    rotation.value = withTiming(0);
  };

  return (
    <View style={styles.container}>
      <Animated.View style={[styles.box, animatedStyles]} />
      
      <View style={styles.buttons}>
        <Pressable style={styles.button} onPress={handleSpring}>
          <Text style={styles.buttonText}>弹性</Text>
        </Pressable>
        <Pressable style={styles.button} onPress={handleTiming}>
          <Text style={styles.buttonText}>缩放</Text>
        </Pressable>
        <Pressable style={styles.button} onPress={handleSequence}>
          <Text style={styles.buttonText}>序列</Text>
        </Pressable>
        <Pressable style={styles.button} onPress={handleRepeat}>
          <Text style={styles.buttonText}>旋转</Text>
        </Pressable>
        <Pressable style={styles.button} onPress={handleStop}>
          <Text style={styles.buttonText}>停止</Text>
        </Pressable>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 100,
    height: 100,
    backgroundColor: '#007AFF',
    borderRadius: 10,
  },
  buttons: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'center',
    marginTop: 50,
  },
  button: {
    backgroundColor: '#333',
    padding: 10,
    margin: 5,
    borderRadius: 5,
  },
  buttonText: {
    color: '#fff',
  },
});
```

### 11.3 手势动画

```tsx
import React from 'react';
import { View, StyleSheet } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  useAnimatedGestureHandler,
  withSpring,
} from 'react-native-reanimated';
import {
  GestureDetector,
  Gesture,
  GestureHandlerRootView,
} from 'react-native-gesture-handler';

const GestureExample = () => {
  const translateX = useSharedValue(0);
  const translateY = useSharedValue(0);
  const scale = useSharedValue(1);

  // 拖拽手势
  const panGesture = Gesture.Pan()
    .onUpdate((event) => {
      translateX.value = event.translationX;
      translateY.value = event.translationY;
    })
    .onEnd(() => {
      translateX.value = withSpring(0);
      translateY.value = withSpring(0);
    });

  // 缩放手势
  const pinchGesture = Gesture.Pinch()
    .onUpdate((event) => {
      scale.value = event.scale;
    })
    .onEnd(() => {
      scale.value = withSpring(1);
    });

  // 组合手势
  const composedGesture = Gesture.Simultaneous(panGesture, pinchGesture);

  const animatedStyle = useAnimatedStyle(() => ({
    transform: [
      { translateX: translateX.value },
      { translateY: translateY.value },
      { scale: scale.value },
    ],
  }));

  return (
    <GestureHandlerRootView style={styles.container}>
      <GestureDetector gesture={composedGesture}>
        <Animated.View style={[styles.box, animatedStyle]} />
      </GestureDetector>
    </GestureHandlerRootView>
  );
};

// 可拖拽列表项
const DraggableItem = () => {
  const translateX = useSharedValue(0);
  const isDeleting = useSharedValue(false);

  const panGesture = Gesture.Pan()
    .onUpdate((event) => {
      translateX.value = Math.max(-100, event.translationX);
    })
    .onEnd(() => {
      if (translateX.value < -50) {
        translateX.value = withSpring(-100);
        isDeleting.value = true;
      } else {
        translateX.value = withSpring(0);
        isDeleting.value = false;
      }
    });

  const animatedStyle = useAnimatedStyle(() => ({
    transform: [{ translateX: translateX.value }],
  }));

  const deleteButtonStyle = useAnimatedStyle(() => ({
    opacity: interpolate(translateX.value, [-100, 0], [1, 0]),
  }));

  return (
    <View style={styles.itemContainer}>
      <Animated.View style={[styles.deleteButton, deleteButtonStyle]}>
        <Text style={styles.deleteText}>删除</Text>
      </Animated.View>
      <GestureDetector gesture={panGesture}>
        <Animated.View style={[styles.item, animatedStyle]}>
          <Text>滑动删除</Text>
        </Animated.View>
      </GestureDetector>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 150,
    height: 150,
    backgroundColor: '#007AFF',
    borderRadius: 10,
  },
  itemContainer: {
    width: '100%',
    height: 60,
    marginBottom: 10,
  },
  item: {
    width: '100%',
    height: '100%',
    backgroundColor: '#fff',
    justifyContent: 'center',
    paddingHorizontal: 16,
  },
  deleteButton: {
    position: 'absolute',
    right: 0,
    width: 100,
    height: '100%',
    backgroundColor: 'red',
    justifyContent: 'center',
    alignItems: 'center',
  },
  deleteText: {
    color: '#fff',
    fontWeight: 'bold',
  },
});
```

---

## 12. 性能优化

### 12.1 列表优化

```tsx
import React, { useCallback, useMemo } from 'react';
import { FlatList, View, Text, StyleSheet } from 'react-native';

interface Item {
  id: string;
  title: string;
}

const OptimizedList = ({ data }: { data: Item[] }) => {
  // 使用 useCallback 缓存渲染函数
  const renderItem = useCallback(({ item }: { item: Item }) => (
    <View style={styles.item}>
      <Text>{item.title}</Text>
    </View>
  ), []);

  // 使用 useCallback 缓存 keyExtractor
  const keyExtractor = useCallback((item: Item) => item.id, []);

  // 固定高度时使用 getItemLayout
  const getItemLayout = useCallback(
    (data: Item[] | null | undefined, index: number) => ({
      length: 60,
      offset: 60 * index,
      index,
    }),
    []
  );

  return (
    <FlatList
      data={data}
      renderItem={renderItem}
      keyExtractor={keyExtractor}
      getItemLayout={getItemLayout}
      // 性能优化配置
      removeClippedSubviews={true}      // 移除屏幕外的视图
      maxToRenderPerBatch={10}          // 每批渲染数量
      updateCellsBatchingPeriod={50}    // 批量更新间隔
      windowSize={5}                     // 渲染窗口大小
      initialNumToRender={10}           // 初始渲染数量
      // 避免不必要的重渲染
      extraData={null}
    />
  );
};

// 使用 React.memo 优化列表项
const ListItem = React.memo(({ item }: { item: Item }) => (
  <View style={styles.item}>
    <Text>{item.title}</Text>
  </View>
));

const styles = StyleSheet.create({
  item: {
    height: 60,
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
});
```

### 12.2 图片优化

```tsx
import { Image } from 'expo-image';

// 使用 expo-image 或 react-native-fast-image
const OptimizedImage = ({ uri }: { uri: string }) => (
  <Image
    source={{ uri }}
    style={{ width: 200, height: 200 }}
    contentFit="cover"
    placeholder={blurhash}  // 模糊占位图
    transition={200}        // 过渡动画
    cachePolicy="memory-disk" // 缓存策略
  />
);

// 图片预加载
import { Image } from 'react-native';

const preloadImages = (urls: string[]) => {
  urls.forEach(url => {
    Image.prefetch(url);
  });
};
```

### 12.3 避免不必要的重渲染

```tsx
import React, { useMemo, useCallback, memo } from 'react';

// 1. 使用 React.memo
const ExpensiveComponent = memo(({ data }: { data: object }) => {
  // 复杂渲染逻辑
  return <View>{/* ... */}</View>;
});

// 2. 使用 useMemo 缓存计算结果
const Component = ({ items }: { items: Item[] }) => {
  const sortedItems = useMemo(() => {
    return [...items].sort((a, b) => a.name.localeCompare(b.name));
  }, [items]);

  return <FlatList data={sortedItems} />;
};

// 3. 使用 useCallback 缓存函数
const Parent = () => {
  const [count, setCount] = useState(0);

  // 不使用 useCallback，每次渲染都会创建新函数
  // const handlePress = () => console.log('pressed');

  // 使用 useCallback，函数引用保持不变
  const handlePress = useCallback(() => {
    console.log('pressed');
  }, []);

  return <Child onPress={handlePress} />;
};

// 4. 避免在 render 中创建对象/数组
const BadExample = () => (
  // 每次渲染都创建新对象，导致子组件重渲染
  <Child style={{ padding: 10 }} data={[1, 2, 3]} />
);

const GoodExample = () => {
  const style = useMemo(() => ({ padding: 10 }), []);
  const data = useMemo(() => [1, 2, 3], []);
  return <Child style={style} data={data} />;
};
```

### 12.4 使用 Hermes 引擎

Hermes 是 Facebook 为 React Native 优化的 JavaScript 引擎：

```json
// android/app/build.gradle
project.ext.react = [
    enableHermes: true
]

// iOS: ios/Podfile
:hermes_enabled => true
```

**Hermes 优势**：
- 更快的启动时间
- 更低的内存占用
- 更小的包体积

### 12.5 性能监控

```tsx
import { InteractionManager } from 'react-native';

// 延迟执行非关键任务
const loadData = () => {
  InteractionManager.runAfterInteractions(() => {
    // 在动画/交互完成后执行
    fetchData();
  });
};

// 使用 React DevTools Profiler
// 在开发模式下分析组件渲染性能

// 使用 Flipper 进行性能分析
// https://fbflipper.com/
```

---

## 13. 调试与测试

### 13.1 调试工具

**开发者菜单**：
- iOS 模拟器：`Cmd + D`
- Android 模拟器：`Cmd + M` 或摇晃设备
- 真机：摇晃设备

**常用调试选项**：
- Reload：重新加载应用
- Debug：打开 Chrome 调试器
- Show Inspector：元素检查器
- Show Perf Monitor：性能监控

**React Native Debugger**：
```bash
# 安装
brew install --cask react-native-debugger

# 启动（在启动 RN 应用前）
open "rndebugger://set-debugger-loc?host=localhost&port=8081"
```

**Flipper**：
```bash
# 下载安装
# https://fbflipper.com/

# 支持功能：
# - 网络请求查看
# - 布局检查
# - 数据库查看
# - 日志查看
# - 性能分析
```

### 13.2 Console 调试

```tsx
// 基础日志
console.log('普通日志');
console.warn('警告信息');
console.error('错误信息');

// 分组日志
console.group('用户信息');
console.log('姓名:', user.name);
console.log('年龄:', user.age);
console.groupEnd();

// 表格日志
console.table([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
]);

// 计时
console.time('fetchData');
await fetchData();
console.timeEnd('fetchData'); // fetchData: 123.45ms

// 条件日志
console.assert(value > 0, 'value 必须大于 0');
```

### 13.3 错误边界

```tsx
import React, { Component, ErrorInfo, ReactNode } from 'react';
import { View, Text, Pressable, StyleSheet } from 'react-native';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // 上报错误到监控平台
    console.error('Error caught:', error, errorInfo);
    // reportError(error, errorInfo);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <View style={styles.container}>
          <Text style={styles.title}>出错了</Text>
          <Text style={styles.message}>{this.state.error?.message}</Text>
          <Pressable style={styles.button} onPress={this.handleRetry}>
            <Text style={styles.buttonText}>重试</Text>
          </Pressable>
        </View>
      );
    }

    return this.props.children;
  }
}

// 使用
const App = () => (
  <ErrorBoundary>
    <MainApp />
  </ErrorBoundary>
);

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  message: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    marginBottom: 20,
  },
  button: {
    backgroundColor: '#007AFF',
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderRadius: 8,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
  },
});
```

### 13.4 单元测试

```bash
npm install --save-dev jest @testing-library/react-native @testing-library/jest-native
```

```tsx
// __tests__/Button.test.tsx
import React from 'react';
import { render, fireEvent, screen } from '@testing-library/react-native';
import Button from '../src/components/Button';

describe('Button', () => {
  it('renders correctly', () => {
    render(<Button title="Click me" onPress={() => {}} />);
    expect(screen.getByText('Click me')).toBeTruthy();
  });

  it('calls onPress when pressed', () => {
    const onPress = jest.fn();
    render(<Button title="Click me" onPress={onPress} />);
    
    fireEvent.press(screen.getByText('Click me'));
    expect(onPress).toHaveBeenCalledTimes(1);
  });

  it('is disabled when disabled prop is true', () => {
    const onPress = jest.fn();
    render(<Button title="Click me" onPress={onPress} disabled />);
    
    fireEvent.press(screen.getByText('Click me'));
    expect(onPress).not.toHaveBeenCalled();
  });
});

// __tests__/hooks/useCounter.test.ts
import { renderHook, act } from '@testing-library/react-native';
import { useCounter } from '../src/hooks/useCounter';

describe('useCounter', () => {
  it('should increment counter', () => {
    const { result } = renderHook(() => useCounter());

    act(() => {
      result.current.increment();
    });

    expect(result.current.count).toBe(1);
  });
});
```

### 13.5 E2E 测试（Detox）

```bash
npm install --save-dev detox
```

```tsx
// e2e/login.test.ts
describe('Login Flow', () => {
  beforeAll(async () => {
    await device.launchApp();
  });

  beforeEach(async () => {
    await device.reloadReactNative();
  });

  it('should login successfully', async () => {
    await element(by.id('email-input')).typeText('test@example.com');
    await element(by.id('password-input')).typeText('password123');
    await element(by.id('login-button')).tap();
    
    await expect(element(by.text('Welcome'))).toBeVisible();
  });

  it('should show error for invalid credentials', async () => {
    await element(by.id('email-input')).typeText('wrong@example.com');
    await element(by.id('password-input')).typeText('wrongpassword');
    await element(by.id('login-button')).tap();
    
    await expect(element(by.text('Invalid credentials'))).toBeVisible();
  });
});
```

---

## 14. 打包发布

### 14.1 Expo 打包

```bash
# 安装 EAS CLI
npm install -g eas-cli

# 登录
eas login

# 配置
eas build:configure

# 构建 Android APK
eas build --platform android --profile preview

# 构建 Android AAB（上架 Google Play）
eas build --platform android --profile production

# 构建 iOS
eas build --platform ios --profile production

# 提交到应用商店
eas submit --platform ios
eas submit --platform android
```

**eas.json 配置**：
```json
{
  "cli": {
    "version": ">= 5.0.0"
  },
  "build": {
    "development": {
      "developmentClient": true,
      "distribution": "internal"
    },
    "preview": {
      "android": {
        "buildType": "apk"
      }
    },
    "production": {
      "android": {
        "buildType": "app-bundle"
      }
    }
  },
  "submit": {
    "production": {}
  }
}
```

### 14.2 React Native CLI 打包

#### Android 打包

```bash
# 1. 生成签名密钥
cd android/app
keytool -genkeypair -v -storetype PKCS12 -keystore my-upload-key.keystore -alias my-key-alias -keyalg RSA -keysize 2048 -validity 10000

# 2. 配置 gradle.properties
# android/gradle.properties
MYAPP_UPLOAD_STORE_FILE=my-upload-key.keystore
MYAPP_UPLOAD_KEY_ALIAS=my-key-alias
MYAPP_UPLOAD_STORE_PASSWORD=*****
MYAPP_UPLOAD_KEY_PASSWORD=*****

# 3. 配置 build.gradle
# android/app/build.gradle
android {
    signingConfigs {
        release {
            storeFile file(MYAPP_UPLOAD_STORE_FILE)
            storePassword MYAPP_UPLOAD_STORE_PASSWORD
            keyAlias MYAPP_UPLOAD_KEY_ALIAS
            keyPassword MYAPP_UPLOAD_KEY_PASSWORD
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}

# 4. 打包
cd android
./gradlew assembleRelease  # APK
./gradlew bundleRelease    # AAB

# 输出位置
# APK: android/app/build/outputs/apk/release/app-release.apk
# AAB: android/app/build/outputs/bundle/release/app-release.aab
```

#### iOS 打包

```bash
# 1. 在 Xcode 中打开项目
cd ios && open MyApp.xcworkspace

# 2. 配置签名
# - 选择 Team
# - 配置 Bundle Identifier
# - 选择 Provisioning Profile

# 3. 选择 Generic iOS Device

# 4. Product -> Archive

# 5. 上传到 App Store Connect
# - Distribute App -> App Store Connect
```

### 14.3 应用图标和启动屏

**Expo**：
```json
// app.json
{
  "expo": {
    "icon": "./assets/icon.png",
    "splash": {
      "image": "./assets/splash.png",
      "resizeMode": "contain",
      "backgroundColor": "#ffffff"
    },
    "android": {
      "adaptiveIcon": {
        "foregroundImage": "./assets/adaptive-icon.png",
        "backgroundColor": "#ffffff"
      }
    }
  }
}
```

**React Native CLI**：
```bash
# 使用 react-native-bootsplash
npm install react-native-bootsplash

# 生成启动屏资源
npx react-native generate-bootsplash assets/bootsplash.png \
  --background-color=FFFFFF \
  --logo-width=100 \
  --assets-path=assets
```

### 14.4 版本管理

```json
// package.json
{
  "version": "1.0.0"
}

// app.json (Expo)
{
  "expo": {
    "version": "1.0.0",
    "ios": {
      "buildNumber": "1"
    },
    "android": {
      "versionCode": 1
    }
  }
}
```

```bash
# 使用 standard-version 管理版本
npm install --save-dev standard-version

# 发布新版本
npm run release        # 自动升级版本号
npm run release:minor  # 升级次版本
npm run release:major  # 升级主版本
```

---

## 15. 常见错误与解决方案

### 15.1 环境配置错误

#### Unable to load script

**错误信息**：
```
Unable to load script. Make sure you're either running a Metro server or that your bundle 'index.android.bundle' is packaged correctly for release.
```

**解决方案**：
```bash
# 1. 确保 Metro 服务器运行
npx react-native start --reset-cache

# 2. 检查 adb 连接
adb devices
adb reverse tcp:8081 tcp:8081

# 3. 清理并重新构建
cd android && ./gradlew clean
cd .. && npx react-native run-android
```

#### CocoaPods 错误

**错误信息**：
```
[!] CocoaPods could not find compatible versions for pod "xxx"
```

**解决方案**：
```bash
# 1. 更新 CocoaPods
sudo gem install cocoapods

# 2. 清理并重新安装
cd ios
rm -rf Pods Podfile.lock
pod install --repo-update

# 3. 清理 Xcode 缓存
rm -rf ~/Library/Developer/Xcode/DerivedData
```

#### Android SDK 错误

**错误信息**：
```
SDK location not found. Define location with sdk.dir in the local.properties file
```

**解决方案**：
```bash
# 创建 local.properties
# android/local.properties
sdk.dir=/Users/你的用户名/Library/Android/sdk  # macOS
sdk.dir=C:\\Users\\你的用户名\\AppData\\Local\\Android\\Sdk  # Windows
```

### 15.2 构建错误

#### Gradle 构建失败

**错误信息**：
```
Execution failed for task ':app:mergeDebugResources'
```

**解决方案**：
```bash
# 1. 清理 Gradle 缓存
cd android
./gradlew clean
./gradlew --stop

# 2. 删除缓存目录
rm -rf ~/.gradle/caches/
rm -rf android/.gradle/

# 3. 重新构建
npx react-native run-android
```

#### Xcode 构建失败

**错误信息**：
```
Build input file cannot be found: '.../node_modules/xxx'
```

**解决方案**：
```bash
# 1. 清理 node_modules
rm -rf node_modules
npm install

# 2. 重新安装 Pods
cd ios
rm -rf Pods Podfile.lock
pod install

# 3. 清理 Xcode
# Product -> Clean Build Folder (Cmd + Shift + K)
```

### 15.3 运行时错误

#### Invariant Violation: Text strings must be rendered within a <Text> component

**原因**：文本内容没有包裹在 `<Text>` 组件中

**错误代码**：
```tsx
// ❌ 错误
<View>
  Hello World
</View>

// ❌ 错误 - 条件渲染返回空字符串
<View>
  {condition && 'Hello'}
</View>
```

**正确代码**：
```tsx
// ✅ 正确
<View>
  <Text>Hello World</Text>
</View>

// ✅ 正确 - 使用 null 而非空字符串
<View>
  {condition ? <Text>Hello</Text> : null}
</View>
```

#### VirtualizedLists should never be nested inside plain ScrollViews

**原因**：在 ScrollView 中嵌套了 FlatList

**解决方案**：
```tsx
// ❌ 错误
<ScrollView>
  <FlatList data={data} />
</ScrollView>

// ✅ 方案一：使用 FlatList 的 ListHeaderComponent
<FlatList
  data={data}
  ListHeaderComponent={<HeaderContent />}
  renderItem={renderItem}
/>

// ✅ 方案二：禁用 FlatList 滚动
<ScrollView>
  <FlatList
    data={data}
    scrollEnabled={false}
    renderItem={renderItem}
  />
</ScrollView>

// ✅ 方案三：使用 SectionList
<SectionList
  sections={[
    { title: 'Header', data: [] },
    { title: 'List', data: listData },
  ]}
/>
```

#### Cannot read property 'xxx' of undefined

**原因**：访问了未定义对象的属性

**解决方案**：
```tsx
// ❌ 错误
const name = user.profile.name;

// ✅ 使用可选链
const name = user?.profile?.name;

// ✅ 使用默认值
const name = user?.profile?.name ?? '未知';

// ✅ 条件渲染
{user?.profile && <Text>{user.profile.name}</Text>}
```

#### Maximum update depth exceeded

**原因**：组件无限循环更新

**错误代码**：
```tsx
// ❌ 错误 - useEffect 依赖导致无限循环
const [data, setData] = useState([]);

useEffect(() => {
  setData([...data, newItem]); // data 变化触发 useEffect，又修改 data
}, [data]);

// ❌ 错误 - 在渲染时直接调用 setState
const Component = () => {
  const [count, setCount] = useState(0);
  setCount(count + 1); // 直接调用导致无限循环
  return <Text>{count}</Text>;
};
```

**正确代码**：
```tsx
// ✅ 正确 - 使用函数式更新
useEffect(() => {
  setData(prev => [...prev, newItem]);
}, [newItem]); // 依赖 newItem 而非 data

// ✅ 正确 - 在事件处理中调用 setState
const Component = () => {
  const [count, setCount] = useState(0);
  
  const handlePress = () => {
    setCount(count + 1);
  };
  
  return (
    <Pressable onPress={handlePress}>
      <Text>{count}</Text>
    </Pressable>
  );
};
```

### 15.4 样式问题

#### 阴影不显示

**iOS 阴影**：
```tsx
const styles = StyleSheet.create({
  shadow: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
    backgroundColor: '#fff', // iOS 阴影需要背景色
  },
});
```

**Android 阴影**：
```tsx
const styles = StyleSheet.create({
  shadow: {
    elevation: 5, // Android 使用 elevation
    backgroundColor: '#fff', // 也需要背景色
  },
});
```

**跨平台阴影**：
```tsx
const styles = StyleSheet.create({
  shadow: {
    ...Platform.select({
      ios: {
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.25,
        shadowRadius: 3.84,
      },
      android: {
        elevation: 5,
      },
    }),
    backgroundColor: '#fff',
  },
});
```

#### 图片不显示

```tsx
// ❌ 网络图片没有指定尺寸
<Image source={{ uri: 'https://...' }} />

// ✅ 必须指定宽高
<Image
  source={{ uri: 'https://...' }}
  style={{ width: 100, height: 100 }}
/>

// ❌ 本地图片路径错误
<Image source={require('./image.png')} /> // 文件不存在

// ✅ 确保文件存在且路径正确
<Image source={require('../assets/images/logo.png')} />
```

### 15.5 导航问题

#### Navigation 对象未定义

**错误信息**：
```
Cannot read property 'navigate' of undefined
```

**解决方案**：
```tsx
// ❌ 在非屏幕组件中直接使用 navigation prop
const MyComponent = () => {
  // navigation 未定义
  return <Button onPress={() => navigation.navigate('Home')} />;
};

// ✅ 使用 useNavigation Hook
import { useNavigation } from '@react-navigation/native';

const MyComponent = () => {
  const navigation = useNavigation();
  return <Button onPress={() => navigation.navigate('Home')} />;
};

// ✅ 或通过 props 传递
const MyComponent = ({ navigation }) => {
  return <Button onPress={() => navigation.navigate('Home')} />;
};
```

#### 导航参数类型错误

```tsx
// 定义类型
type RootStackParamList = {
  Home: undefined;
  Detail: { id: string };
};

// ❌ 参数类型不匹配
navigation.navigate('Detail'); // 缺少必需参数

// ✅ 正确传递参数
navigation.navigate('Detail', { id: '123' });
```

### 15.6 性能问题

#### 列表卡顿

```tsx
// ❌ 在 renderItem 中创建新函数
<FlatList
  data={data}
  renderItem={({ item }) => (
    <Pressable onPress={() => handlePress(item.id)}>
      <Text>{item.name}</Text>
    </Pressable>
  )}
/>

// ✅ 使用 useCallback 和 memo
const renderItem = useCallback(({ item }) => (
  <MemoizedItem item={item} onPress={handlePress} />
), [handlePress]);

const MemoizedItem = memo(({ item, onPress }) => (
  <Pressable onPress={() => onPress(item.id)}>
    <Text>{item.name}</Text>
  </Pressable>
));

<FlatList
  data={data}
  renderItem={renderItem}
  keyExtractor={item => item.id}
  getItemLayout={(data, index) => ({
    length: ITEM_HEIGHT,
    offset: ITEM_HEIGHT * index,
    index,
  })}
/>
```

#### 内存泄漏

```tsx
// ❌ 未清理订阅
useEffect(() => {
  const subscription = eventEmitter.addListener('event', handler);
  // 忘记清理
}, []);

// ✅ 正确清理
useEffect(() => {
  const subscription = eventEmitter.addListener('event', handler);
  return () => subscription.remove();
}, []);

// ❌ 组件卸载后更新状态
useEffect(() => {
  fetchData().then(data => {
    setData(data); // 组件可能已卸载
  });
}, []);

// ✅ 使用标志位
useEffect(() => {
  let isMounted = true;
  
  fetchData().then(data => {
    if (isMounted) {
      setData(data);
    }
  });
  
  return () => {
    isMounted = false;
  };
}, []);
```

---

## 快速参考

### 常用命令

| 命令 | 说明 |
|------|------|
| `npx expo start` | 启动 Expo 开发服务器 |
| `npx react-native start` | 启动 Metro 服务器 |
| `npx react-native run-ios` | 运行 iOS 应用 |
| `npx react-native run-android` | 运行 Android 应用 |
| `npx react-native start --reset-cache` | 清除缓存并启动 |
| `cd ios && pod install` | 安装 iOS 依赖 |
| `cd android && ./gradlew clean` | 清理 Android 构建 |

### 常用库推荐

| 类别 | 库名 | 说明 |
|------|------|------|
| 导航 | @react-navigation/native | 官方推荐导航库 |
| 状态管理 | zustand | 轻量级状态管理 |
| 数据请求 | @tanstack/react-query | 服务端状态管理 |
| 动画 | react-native-reanimated | 高性能动画库 |
| 手势 | react-native-gesture-handler | 手势处理 |
| 存储 | react-native-mmkv | 高性能存储 |
| 图片 | expo-image | 优化的图片组件 |
| 图标 | @expo/vector-icons | 图标库 |
| 表单 | react-hook-form | 表单处理 |
| UI 库 | react-native-paper | Material Design |

---

> 💡 **小贴士**：React Native 生态发展迅速，建议关注官方文档和社区动态，及时了解最新的最佳实践和工具更新。遇到问题时，GitHub Issues 和 Stack Overflow 是很好的资源。
