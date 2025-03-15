# Spring 5 前言
## Spring5概述
Spring Framework 5 是一个功能强大的开源Java应用程序框架，它提供了全面的编程和配置模型，用于构建现代Java应用程序。Spring 5 带来了许多新特性和改进，包括对Java 8+的全面支持、响应式编程模型（Reactive Programming Model）、HTTP/2支持等。以下是Spring 5框架的一些关键特性和概念：

### 1. 响应式编程模型

Spring 5 引入了Spring WebFlux，这是一个响应式的Web框架，它支持响应式流（Reactive Streams）和背压（Backpressure），允许构建非阻塞的、事件驱动的应用程序。WebFlux 基于Project Reactor，它提供了`Flux`和`Mono`两种响应式类型。

### 2. Java 8+支持

Spring 5 对Java 8的新特性提供了全面支持，包括Lambda表达式、方法引用、Stream API等。Spring 5 也支持Java 9的模块系统（JPMS）。

### 3. 核心容器改进

Spring 5 对核心容器进行了改进，包括对Java 8的优化、泛型类型推断的改进等。引入了`@Nullable`注解，用于指示一个方法参数或返回值可以是`null`。

### 4. Kotlin支持

Spring 5 对Kotlin提供了良好的支持，允许使用Kotlin语言特性来编写Spring应用程序。

### 5. 测试改进

Spring 5 提供了对JUnit 5的支持，并引入了新的测试注解，如`@ExtendWith(SpringExtension.class)`。

### 6. HTTP/2支持

Spring 5 支持HTTP/2，允许在Web应用程序中使用HTTP/2特性。

### 7. 其他改进

- **依赖注入**：Spring 5 提供了更强大的依赖注入功能，包括构造函数注入、字段注入和方法注入。
- **事件机制**：Spring 5 提供了更灵活的事件机制，允许发布和订阅自定义事件。
- **消息传递**：Spring 5 提供了对消息传递系统的支持，包括JMS、AMQP和Kafka。

### 8. 函数式Web框架

Spring 5 引入了函数式Web框架，允许使用函数式编程风格来构建Web应用程序。

### 9. 安全性

Spring 5 提供了对Spring Security的改进，包括对OAuth 2.0和OpenID Connect的支持。

### 10. 文档和社区

Spring 5 提供了丰富的文档和社区支持，包括官方文档、教程、示例代码和社区论坛。
## 创建一个简单的Spring应用程序
创建一个简单的Spring应用程序通常包括以下几个步骤：

1. **设置项目结构**：使用构建工具如Maven或Gradle来管理项目依赖。
2. **添加Spring依赖**：在构建配置文件中添加Spring框架的依赖。
3. **创建应用程序配置**：使用Java配置类或XML文件来配置Spring应用程序。
4. **创建应用程序组件**：编写应用程序的业务逻辑组件。
5. **运行应用程序**：使用Spring的`ApplicationContext`来启动应用程序。

下面是一个使用Java配置和Maven构建工具的简单Spring应用程序示例。

### 1. 设置项目结构

首先，创建一个新的Maven项目，并在`pom.xml`中添加Spring框架的依赖。

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0" 
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>spring-simple-app</artifactId>
    <version>1.0-SNAPSHOT</version>
    <dependencies>
        <!-- Spring Context -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-context</artifactId>
            <version>5.3.24</version>
        </dependency>
        <!-- JUnit for testing -->
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

### 2. 创建应用程序配置

创建一个Java配置类来定义Spring应用程序上下文。

```java
package com.example.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackages = "com.example")
public class AppConfig {
    // Bean definitions can be added here if needed
}
```

### 3. 创建应用程序组件

创建一个简单的服务类和一个控制器类。

```java
package com.example.service;

public interface MyService {
    String getMessage();
}

package com.example.service;

import org.springframework.stereotype.Service;

@Service
public class MyServiceImpl implements MyService {
    @Override
    public String getMessage() {
        return "Hello, Spring!";
    }
}

package com.example.controller;

import com.example.service.MyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

@Controller
public class MyController {
    private final MyService myService;

    @Autowired
    public MyController(MyService myService) {
        this.myService = myService;
    }

    public void printMessage() {
        System.out.println(myService.getMessage());
    }
}
```

### 4. 运行应用程序

创建一个主类来启动Spring应用程序上下文并运行应用程序。

```java
package com.example;

import com.example.controller.MyController;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

public class Application {
    public static void main(String[] args) {
        ApplicationContext context = new AnnotationConfigApplicationContext(AppConfig.class);
        MyController controller = context.getBean(MyController.class);
        controller.printMessage();
    }
}
```

### 5. 运行应用程序

运行`Application`类的`main`方法，你将看到控制台输出：

```
Hello, Spring!
```

这个简单的应用程序展示了如何使用Spring框架来管理应用程序组件。`AppConfig`类使用`@Configuration`和`@ComponentScan`注解来配置Spring上下文，`MyServiceImpl`类使用`@Service`注解标记为一个服务组件，`MyController`类使用`@Controller`注解标记为一个控制器组件，并通过构造函数注入`MyService`依赖。`Application`类使用`AnnotationConfigApplicationContext`来启动Spring上下文并获取`MyController`的实例，然后调用`printMessage`方法。



### 总结
通过配置类.class可获得上下文对象，通过上下文对象调用getBean(具体控制类.class)可获得控制类的实例对象从而调用控制类的方法





# Spring 5核心概念
## Bean 的定义与作用域
在Spring框架中，Bean是构成应用程序主干的对象，由Spring IoC容器管理。理解Bean的定义与作用域对于有效地使用Spring框架至关重要。

#### Bean的定义

Bean的定义包含了创建Bean实例所需的信息。Spring提供了多种方式来定义Bean：

1. **基于XML的配置**：使用XML文件来定义Bean及其属性和依赖关系。
2. **基于Java的配置**：使用带有`@Configuration`注解的Java类来定义Bean。
3. **基于注解的配置**：使用如`@Component`, `@Service`, `@Repository`, `@Controller`等注解来定义Bean。

##### 基于XML的配置示例

```xml
<bean id="myBean" class="com.example.MyBean">
    <property name="propertyName" value="propertyValue"/>
</bean>
```

##### 基于Java的配置示例

```java
@Configuration
public class AppConfig {

    @Bean
    public MyBean myBean() {
        MyBean myBean = new MyBean();
        myBean.setPropertyName("propertyValue");
        return myBean;
    }
}
```

##### 基于注解的配置示例

```java
@Component("myBean")
public class MyBean {
    @Value("propertyValue")
    private String propertyName;

    // Getters and Setters
}
```

#### Bean的作用域

Bean的作用域决定了Spring容器创建Bean实例的方式。Spring支持以下几种作用域：

1. **singleton（单例）**：这是默认的作用域。Spring容器只创建一个Bean实例，并且所有对该Bean的请求都会返回同一个实例。
2. **prototype（原型）**：每次请求Bean时都会创建一个新的实例。
3. **request（请求）**：每个HTTP请求都会创建一个新的Bean实例。仅在Web应用中有效。
4. **session（会话）**：每个HTTP会话都会创建一个新的Bean实例。仅在Web应用中有效。
5. **application（应用）**：每个Web应用程序都会创建一个新的Bean实例。仅在Web应用中有效。
6. **websocket（WebSocket）**：每个WebSocket会话都会创建一个新的Bean实例。仅在Web应用中有效。

##### 设置Bean的作用域

**基于XML的配置**

```xml
<bean id="myBean" class="com.example.MyBean" scope="prototype"/>
```

**基于Java的配置**

```java
@Bean
@Scope("prototype")
public MyBean myBean() {
    return new MyBean();
}
```

**基于注解的配置**

```java
@Component
@Scope("prototype")
public class MyBean {
    // ...
}
```

#### 生命周期回调

Bean的生命周期回调方法允许在Bean的创建和销毁过程中执行自定义逻辑。可以通过实现`InitializingBean`和`DisposableBean`接口，或者使用`@PostConstruct`和`@PreDestroy`注解来定义这些回调方法。

##### 使用接口定义生命周期回调

```java
public class MyBean implements InitializingBean, DisposableBean {

    @Override
    public void afterPropertiesSet() throws Exception {
        // Initialization logic
    }

    @Override
    public void destroy() throws Exception {
        // Destruction logic
    }
}
```

##### 使用注解定义生命周期回调

```java
public class MyBean {

    @PostConstruct
    public void init() {
        // Initialization logic
    }

    @PreDestroy
    public void cleanup() {
        // Destruction logic
    }
}
```

通过理解Bean的定义与作用域，开发者可以更有效地管理应用程序中的对象，确保它们按照预期的方式被创建、配置和使用。



## Bean的生命周期
在Spring框架中，Bean的生命周期指的是一个Bean从创建到销毁的整个过程。Spring IoC容器负责管理Bean的生命周期，包括实例化、配置、初始化、使用和销毁等阶段。理解Bean的生命周期对于编写高效、可维护的Spring应用程序至关重要。

#### Bean生命周期的阶段

1. **实例化**：Spring容器通过反射机制或工厂方法创建Bean的实例。

2. **属性赋值**：容器设置Bean的属性和依赖项。这包括通过setter方法注入依赖项。

3. **BeanNameAware的setBeanName**：如果Bean实现了`BeanNameAware`接口，容器会调用`setBeanName`方法，传入Bean的名称。

4. **BeanFactoryAware的setBeanFactory**：如果Bean实现了`BeanFactoryAware`接口，容器会调用`setBeanFactory`方法，传入当前的`BeanFactory`实例。

5. **ApplicationContextAware的setApplicationContext**：如果Bean实现了`ApplicationContextAware`接口，容器会调用`setApplicationContext`方法，传入当前的`ApplicationContext`实例。

6. **BeanPostProcessor的postProcessBeforeInitialization**：容器会调用所有`BeanPostProcessor`实现类的`postProcessBeforeInitialization`方法。

7. **InitializingBean的afterPropertiesSet**：如果Bean实现了`InitializingBean`接口，容器会调用`afterPropertiesSet`方法。

8. **自定义初始化方法**：如果配置了自定义的初始化方法，容器会调用这个方法。

9. **BeanPostProcessor的postProcessAfterInitialization**：容器会调用所有`BeanPostProcessor`实现类的`postProcessAfterInitialization`方法。

10. **Bean的使用**：此时，Bean已经准备就绪，可以被应用程序使用。

11. **DisposableBean的destroy**：如果Bean实现了`DisposableBean`接口，容器会在Bean销毁前调用`destroy`方法。

12. **自定义销毁方法**：如果配置了自定义的销毁方法，容器会调用这个方法。

#### 生命周期回调方法

- **@PostConstruct和@PreDestroy注解**：Spring支持使用`@PostConstruct`和`@PreDestroy`注解来定义初始化和销毁回调方法。这些方法会在Bean初始化后和销毁前被调用。

- **实现接口**：除了使用注解，开发者还可以通过实现`InitializingBean`和`DisposableBean`接口来定义初始化和销毁逻辑。

- **自定义方法**：在Bean的配置中指定初始化和销毁方法也是一种常见的方式。

#### 示例

以下是一个简单的示例，展示了如何定义一个Bean并实现生命周期回调方法：

```java
public class MyBean implements InitializingBean, DisposableBean {

    public MyBean() {
        System.out.println("Bean is going through constructor");
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        System.out.println("Bean has been initialized");
    }

    public void someBusinessLogic() {
        // Business logic here
    }

    @Override
    public void destroy() throws Exception {
        System.out.println("Bean will be destroyed now");
    }
}
```

在这个示例中，`MyBean`类实现了`InitializingBean`和`DisposableBean`接口，并重写了`afterPropertiesSet`和`destroy`方法。这些方法分别在Bean初始化和销毁时被调用。

通过理解Bean的生命周期，开发者可以更好地控制Bean的创建和销毁过程，从而编写出更加健壮和高效的Spring应用程序。


## Bean的继承
在Spring框架中，Bean的继承并不是指Java类之间的继承关系，而是指在Spring容器中，一个Bean定义可以继承另一个Bean定义的配置。这种继承关系允许你复用Bean的配置，减少重复的配置代码。

#### Bean继承的基本概念

- **父Bean定义**：一个作为模板的Bean定义，包含了一些通用的配置属性。
- **子Bean定义**：一个继承自父Bean定义的Bean定义，可以覆盖或添加父Bean定义中的配置。

#### 配置Bean继承

在XML配置中，可以使用`parent`属性来指定一个Bean定义继承自另一个Bean定义。

**示例：**

```xml
<bean id="parentBean" class="com.example.ParentBean">
    <property name="commonProperty" value="commonValue"/>
</bean>

<bean id="childBean" class="com.example.ChildBean" parent="parentBean">
    <property name="childProperty" value="childValue"/>
</bean>
```

在这个例子中，`childBean`继承了`parentBean`的定义，并添加了自己的属性`childProperty`。

#### 使用抽象Bean

如果一个Bean定义仅作为模板使用，不希望它被实例化，可以将其定义为抽象的。抽象Bean不能被单独实例化，只能作为其他Bean的父Bean。

**示例：**

```xml
<bean id="abstractParentBean" class="com.example.ParentBean" abstract="true">
    <property name="commonProperty" value="commonValue"/>
</bean>

<bean id="childBean" class="com.example.ChildBean" parent="abstractParentBean">
    <property name="childProperty" value="childValue"/>
</bean>
```

在这个例子中，`abstractParentBean`被标记为抽象的，因此它不会被实例化。`childBean`继承了`abstractParentBean`的定义。

#### 使用Java配置

在Java配置中，可以通过继承配置类并使用`@Bean`注解来创建父子Bean关系。

**示例：**

```java
@Configuration
public class ParentConfig {

    @Bean
    public ParentBean parentBean() {
        ParentBean parent = new ParentBean();
        parent.setCommonProperty("commonValue");
        return parent;
    }
}

@Configuration
public class ChildConfig extends ParentConfig {

    @Bean
    public ChildBean childBean() {
        ChildBean child = new ChildBean();
        child.setParentBean(parentBean());
        child.setChildProperty("childValue");
        return child;
    }
}
```

在这个例子中，`ChildConfig`类继承了`ParentConfig`类，并定义了一个`childBean` Bean，该Bean依赖于`parentBean`。

#### 注意事项

- **Bean的作用域**：父Bean和子Bean可以有不同的作用域。
- **Bean的覆盖**：子Bean可以覆盖父Bean中的属性值。
- **抽象Bean**：如果一个Bean被定义为抽象的，它不能被实例化，只能作为其他Bean的父Bean。

#### 总结

Bean的继承是Spring框架中一个强大的特性，它允许开发者复用Bean的配置，减少重复的配置代码。通过使用父Bean和子Bean，开发者可以创建更加模块化和可维护的Spring应用程序。
## 依赖注入(DI)
### 什么是DI？
依赖注入（Dependency Injection，简称DI）是一种设计模式，它允许对象定义它们的依赖关系（即它们使用的其他对象），而不需要自己创建这些依赖关系。依赖注入的核心思想是反转控制（Inversion of Control，简称IoC），即控制对象的创建和依赖关系的绑定从对象本身转移到外部容器或框架。

#### DI的主要优点

1. **解耦**：通过依赖注入，对象不需要知道依赖对象的创建细节，这减少了对象之间的耦合度。
2. **可测试性**：由于依赖关系可以通过外部注入，单元测试可以轻松地模拟依赖对象。
3. **可维护性**：依赖注入使得代码更加模块化，易于维护和扩展。
4. **灵活性**：依赖注入允许在运行时配置对象之间的依赖关系，这提供了更大的灵活性。

#### DI的类型

依赖注入主要有三种方式：

1. **构造函数注入（Constructor Injection）**：通过构造函数将依赖对象传递给依赖对象。
2. **Setter方法注入（Setter Injection）**：通过setter方法将依赖对象传递给依赖对象。
3. **字段注入（Field Injection）**：通过直接设置字段来注入依赖对象，通常使用反射或注解来实现。

#### DI在Spring中的实现
Spring框架广泛使用依赖注入来管理bean之间的依赖关系。Spring容器负责创建bean实例并注入它们之间的依赖关系。
##### 构造函数注入示例

```java
public class MyService {
    private MyRepository myRepository;

    @Autowired
    public MyService(MyRepository myRepository) {
        this.myRepository = myRepository;
    }

    // ...
}
```

在这个例子中，`MyService`类通过构造函数注入了`MyRepository`依赖。

##### Setter方法注入示例

```java
public class MyService {
    private MyRepository myRepository;

    @Autowired
    public void setMyRepository(MyRepository myRepository) {
        this.myRepository = myRepository;
    }

    // ...
}
```

在这个例子中，`MyService`类通过setter方法注入了`MyRepository`依赖。

##### 字段注入示例

```java
public class MyService {
    @Autowired
    private MyRepository myRepository;

    // ...
}
```

在这个例子中，`MyService`类通过字段注入了`MyRepository`依赖。

#### 总结

依赖注入是Spring框架的核心概念之一，它通过将对象的创建和依赖关系的绑定从对象本身转移到外部容器或框架中，从而实现了对象之间的解耦，提高了代码的可测试性、可维护性和灵活性。理解并正确使用依赖注入是构建高效Spring应用程序的关键。


### 显式装配
在Spring框架中，依赖注入（DI）可以通过多种方式进行装配，包括显式装配和隐式装配。显式装配指的是开发者明确地告诉Spring容器如何装配bean的依赖关系。这通常通过XML配置文件或Java配置类来实现。
#### 显式装配的类型

1. **基于XML的显式装配**：使用XML配置文件来定义bean及其依赖关系。
2. **基于Java的显式装配**：使用Java配置类（带有`@Configuration`注解的类）来定义bean及其依赖关系。

#### 基于XML的显式装配

在基于XML的配置中，可以使用`<bean>`标签来定义bean，并使用`<property>`或`<constructor-arg>`标签来注入依赖。

**示例：**

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- 定义MyRepository bean -->
    <bean id="myRepository" class="com.example.repository.MyRepositoryImpl"/>

    <!-- 定义MyService bean，并注入MyRepository依赖 -->
    <bean id="myService" class="com.example.service.MyServiceImpl">
        <property name="myRepository" ref="myRepository"/>
    </bean>

</beans>
```

在这个例子中，`myService` bean通过`<property>`标签注入了`myRepository`依赖。

#### 基于Java的显式装配

在基于Java的配置中，可以使用`@Bean`注解来定义bean，并使用方法调用来注入依赖。

**示例：**

```java
@Configuration
public class AppConfig {

    @Bean
    public MyRepository myRepository() {
        return new MyRepositoryImpl();
    }
//Myservice类型的函数
    @Bean
    public MyService myService() {
        MyServiceImpl myService = new MyServiceImpl();
        myService.setMyRepository(myRepository());
        return myService;
    }
}
```

在这个例子中，`myService` bean通过方法调用注入了`myRepository`依赖。

#### 构造函数注入的显式装配

对于构造函数注入，可以在XML配置中使用`<constructor-arg>`标签，或在Java配置中使用构造函数参数。

**XML配置示例：**

```xml
<bean id="myService" class="com.example.service.MyServiceImpl">
    <constructor-arg ref="myRepository"/>
</bean>
```

**Java配置示例：**

```java
@Bean
public MyService myService(MyRepository myRepository) {
    return new MyServiceImpl(myRepository);
}
```

#### Setter方法注入的显式装配

对于Setter方法注入，可以在XML配置中使用`<property>`标签，或在Java配置中使用Setter方法。

**XML配置示例：**

```xml
<bean id="myService" class="com.example.service.MyServiceImpl">
    <property name="myRepository" ref="myRepository"/>
</bean>
```

**Java配置示例：**

```java
@Bean
public MyService myService() {
    MyServiceImpl myService = new MyServiceImpl();
    myService.setMyRepository(myRepository());
    return myService;
}
```

#### 总结

显式装配提供了对bean依赖关系的完全控制，使得开发者可以精确地指定如何装配每个bean的依赖关系。尽管这可能需要更多的配置工作，但它提供了更高的透明度和可预测性。通过显式装配，开发者可以确保应用程序的行为符合预期，特别是在复杂的应用程序中。


### 自动装配
在Spring框架中，自动装配（Autowiring）是一种机制，它允许Spring容器自动解析协作bean之间的依赖关系，而无需开发者显式地配置每个依赖项。自动装配可以显著减少配置工作量，并使代码更加简洁。

#### 自动装配的模式

Spring支持几种自动装配的模式，可以通过`autowire`属性在XML配置中指定，或者通过`@Autowired`注解在Java配置中指定：

1. **no**：默认设置，意味着没有自动装配。bean的依赖必须通过显式配置来注入。
2. **byName**：根据属性名自动装配。Spring容器会查找与属性同名的bean，并将其注入。
3. **byType**：根据属性类型自动装配。Spring容器会查找与属性类型匹配的bean，并将其注入。如果找到多个匹配的bean，则会抛出异常。
4. **constructor**：类似于`byType`，但是应用于构造函数参数。如果容器中不存在与构造函数参数类型匹配的bean，则会抛出异常。

#### 使用`@Autowired`注解进行自动装配

`@Autowired`是Spring提供的一个注解，用于指示Spring容器自动装配bean的依赖项。它可以用于构造函数、setter方法、字段以及配置方法。

**构造函数注入示例：**

```java
@Service
public class MyService {
    
    private final MyRepository myRepository;

    @Autowired
    public MyService(MyRepository myRepository) {
        this.myRepository = myRepository;
    }

    // ...
}
```

**Setter方法注入示例：**

```java
@Service
public class MyService {
    
    private MyRepository myRepository;

    @Autowired
    public void setMyRepository(MyRepository myRepository) {
        this.myRepository = myRepository;
    }

    // ...
}
```

**字段注入示例：**

```java
@Service
public class MyService {
    
    @Autowired
    private MyRepository myRepository;

    // ...
}
```

#### 使用`@Qualifier`注解进行限定装配

当有多个bean符合自动装配的类型时，可以使用`@Qualifier`注解来指定要装配的具体bean。

**示例：**

```java
@Service
public class MyService {
    
    private final MyRepository myRepository;

    @Autowired
    public MyService(@Qualifier("要注入的bean名") MyRepository myRepository) {
        this.myRepository = myRepository;
    }

    // ...
}
```



#### 使用`@Primary`注解指定主要候选者

如果希望某个bean在自动装配时具有更高的优先级，可以使用`@Primary`注解。

**示例：**

```java
@Repository
@Primary
public class MyRepositoryImpl implements MyRepository {
    // ...
}
```

在这个例子中，`MyRepositoryImpl`被标记为`@Primary`，因此在自动装配`MyRepository`时，`MyRepositoryImpl`会被优先选择。

#### 总结

自动装配是Spring框架中一个强大的特性，它简化了bean之间的依赖注入过程。通过使用`@Autowired`和其他相关注解，开发者可以减少显式配置的需要，使代码更加简洁和易于维护。然而，在某些情况下，显式装配可能更适合，特别是当需要更精确地控制依赖关系时。

## 控制反转(IOC)容器
### 什么是IOC容器？
IoC容器（Inversion of Control Container）是Spring框架的核心组件之一，它负责管理应用程序中的对象（通常称为“bean”）的生命周期，包括对象的创建、配置和组装。IoC容器通过依赖注入（Dependency Injection, DI）来实现对象之间的解耦，使得对象不需要知道依赖对象的创建和配置细节。
#### IoC容器的工作原理

IoC容器通过读取配置元数据（可以是XML文件、Java注解或Java配置类）来了解需要创建哪些对象，以及这些对象之间的依赖关系。容器根据这些配置信息来实例化、配置和组装bean。

#### IoC容器的主要功能

1. **依赖注入**：容器负责将依赖对象注入到需要它们的对象中，而不是由对象自己创建或查找依赖对象。
2. **生命周期管理**：容器管理bean的生命周期，包括对象的创建、初始化、使用和销毁。
3. **配置管理**：容器允许通过外部配置文件来管理应用程序的配置，使得应用程序可以更容易地适应不同的环境。
4. **AOP支持**：容器支持面向切面编程（Aspect-Oriented Programming, AOP），允许将横切关注点（如日志记录、事务管理）模块化。

#### IoC容器的类型

Spring框架提供了两种主要的IoC容器：

1. **BeanFactory**：这是Spring框架中基本的IoC容器接口。它提供了配置框架和基本功能，加载bean的定义并管理它们。`BeanFactory`是懒加载的，意味着只有在请求bean时才会创建它们。
   
2. **ApplicationContext**：这是`BeanFactory`的一个子接口，提供了更完整的功能集。它在启动时立即加载所有单例bean，而不是在请求时加载。`ApplicationContext`还提供了文本消息的解析、国际化的支持、事件发布和应用程序层的特定上下文，如`WebApplicationContext`用于Web应用程序。

#### 使用IoC容器
要使用IoC容器，首先需要配置它。配置可以通过XML文件、Java注解或Java配置类来完成。以下是使用Java配置类和`AnnotationConfigApplicationContext`来启动Spring IoC容器的步骤：

##### 1. 创建配置类

使用`@Configuration`注解标记一个类为配置类，并使用`@Bean`注解定义bean。

```java
@Configuration
public class AppConfig {

    @Bean
    public MyService myService() {
        return new MyServiceImpl();
    }

    @Bean
    public MyController myController() {
        return new MyController(myService());
    }
}
```

在这个例子中，`AppConfig`类定义了两个bean：`myService`和`myController`。`myController` bean依赖于`myService` bean。

##### 2. 启动容器

使用`AnnotationConfigApplicationContext`来启动Spring容器，并传入配置类作为参数。

```java
//Annotation注解
public class Application {
    public static void main(String[] args) {
        ApplicationContext context = new AnnotationConfigApplicationContext(AppConfig.class);
        
        MyController controller = context.getBean(MyController.class);
        controller.processRequest();
    }
}
```

在这个例子中，`Application`类使用`AnnotationConfigApplicationContext`来启动Spring容器，并获取`MyController`的实例，然后调用`processRequest`方法。

==.java转为流参数为.class  .xml转为为流参数为.xml==


将配置类.class转流到上下文对象，通过上下文对象的getBean(A.class)方法从上下文流中的A类获得A的bean(A类的对象)，最后A类的对象调用A类中的方法

##### 3. 使用容器

一旦容器启动并配置完成，就可以从容器中获取bean的实例，并使用它们。

```java
public class MyController {
    private MyService myService;

    public MyController(MyService myService) {
        this.myService = myService;
    }

    public void processRequest() {
        myService.performService();
    }
}
```

在这个例子中，`MyController`类通过构造函数注入了`MyService`依赖，并调用了`performService`方法。

##### 容器的高级用法

除了基本的容器使用，Spring IoC容器还提供了许多高级功能，例如：

- **Bean的作用域**：可以定义bean的作用域，如singleton、prototype、request、session等。
- **生命周期回调**：可以定义bean的初始化和销毁回调方法。
- **事件机制**：可以发布和监听容器事件。
- **国际化支持**：可以配置消息源，实现国际化。
- **资源管理**：可以管理应用程序的资源，如文件、URL等。

#### 总结

通过使用Spring IoC容器，开发者可以更专注于业务逻辑的实现，而不需要关心对象的创建和依赖管理，从而提高了开发效率和代码的可维护性。Spring IoC容器提供了丰富的功能和灵活性，使得开发者可以轻松地构建复杂的应用程序。

### 容器扩展点
在Spring框架中，容器扩展点是指允许开发者自定义和扩展Spring IoC容器行为的机制。这些扩展点允许开发者在Bean的创建、配置、初始化和销毁过程中插入自定义逻辑。Spring提供了多种扩展点，主要通过实现特定的接口或使用注解来实现。

以下是一些主要的容器扩展点：

#### 1. BeanPostProcessor

`BeanPostProcessor`接口允许在Bean初始化前后对Bean进行自定义处理。实现该接口的类可以定义`postProcessBeforeInitialization`和`postProcessAfterInitialization`方法，分别在Bean的初始化回调（如`afterPropertiesSet`或`@PostConstruct`）之前和之后被调用。

**示例：**

```java
public class MyBeanPostProcessor implements BeanPostProcessor {

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        // 自定义逻辑
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        // 自定义逻辑
        return bean;
    }
}
```

#### 2. BeanFactoryPostProcessor

`BeanFactoryPostProcessor`接口允许在BeanFactory标准初始化之后修改其内部的Bean定义。实现该接口的类可以定义`postProcessBeanFactory`方法，该方法在所有Bean定义被加载后，但在Bean被实例化之前被调用。

**示例：**

```java
public class MyBeanFactoryPostProcessor implements BeanFactoryPostProcessor {

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // 自定义逻辑
    }
}
```

#### 3. InstantiationAwareBeanPostProcessor

`InstantiationAwareBeanPostProcessor`接口是`BeanPostProcessor`的一个子接口，它提供了在Bean实例化前后进行自定义处理的能力。实现该接口的类可以定义`postProcessBeforeInstantiation`和`postProcessAfterInstantiation`方法。

**示例：**

```java
public class MyInstantiationAwareBeanPostProcessor implements InstantiationAwareBeanPostProcessor {

    @Override
    public Object postProcessBeforeInstantiation(Class<?> beanClass, String beanName) throws BeansException {
        // 自定义逻辑
        return null;
    }

    @Override
    public boolean postProcessAfterInstantiation(Object bean, String beanName) throws BeansException {
        // 自定义逻辑
        return true;
    }
}
```

#### 4. BeanNameAware, BeanFactoryAware, ApplicationContextAware

这些接口允许Bean感知到它们在容器中的名称、BeanFactory或ApplicationContext。

**示例：**

```java
public class MyBean implements BeanNameAware, BeanFactoryAware, ApplicationContextAware {

    @Override
    public void setBeanName(String name) {
        // 自定义逻辑
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        // 自定义逻辑
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        // 自定义逻辑
    }
}
```

#### 5. InitializingBean 和 DisposableBean

`InitializingBean`接口允许Bean在所有属性设置完成后执行初始化逻辑。`DisposableBean`接口允许Bean在容器关闭时执行销毁逻辑。

**示例：**

```java
public class MyBean implements InitializingBean, DisposableBean {

    @Override
    public void afterPropertiesSet() throws Exception {
        // 初始化逻辑
    }

    @Override
    public void destroy() throws Exception {
        // 销毁逻辑
    }
}
```

#### 6. @PostConstruct 和 @PreDestroy

这些注解用于在Bean初始化后和销毁前执行自定义方法。

**示例：**

```java
public class MyBean {

    @PostConstruct
    public void init() {
        // 初始化逻辑
    }

    @PreDestroy
    public void cleanup() {
        // 销毁逻辑
    }
}
```

通过使用这些扩展点，开发者可以高度定制Spring容器的行为，从而满足应用程序的特定需求。



## Spring事务
Spring框架提供了强大而灵活的事务管理支持，它允许开发者以声明式的方式管理事务，而无需编写大量的样板代码。Spring事务管理支持多种事务API，包括JDBC, Hibernate, JPA等，并且可以与各种事务管理器（如DataSourceTransactionManager, HibernateTransactionManager等）集成。

### Spring事务管理的主要概念

1. **事务管理器（Transaction Manager）**：这是Spring事务管理的核心接口，负责管理事务的启动、提交和回滚。不同的持久化技术需要不同的事务管理器实现。

2. **事务属性（Transaction Attributes）**：定义事务的行为，包括传播行为、隔离级别、超时时间、只读标志和回滚规则。

3. **传播行为（Propagation Behavior）**：定义事务方法如何传播到另一个事务方法中。Spring支持的事务传播行为包括REQUIRED, SUPPORTS, MANDATORY, REQUIRES_NEW, NOT_SUPPORTED, NEVER, NESTED。

4. **隔离级别（Isolation Level）**：定义事务的隔离级别，以防止脏读、不可重复读和幻读等问题。Spring支持的事务隔离级别包括DEFAULT, READ_UNCOMMITTED, READ_COMMITTED, REPEATABLE_READ, SERIALIZABLE。

5. **只读标志（Read-only Flag）**：指示事务是否为只读。如果事务是只读的，Spring可以对其进行优化。

6. **回滚规则（Rollback Rules）**：定义哪些异常会导致事务回滚。默认情况下，运行时异常会导致事务回滚，而检查型异常不会。

### 声明式事务管理

Spring提供了两种主要的方式来声明式地管理事务：基于XML的配置和基于注解的配置。

#### 基于XML的配置

在XML配置中，可以使用`<tx:annotation-driven>`元素启用注解驱动的事务管理，并使用`<bean>`元素配置事务管理器。

**示例：**

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:tx="http://www.springframework.org/schema/tx"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
           http://www.springframework.org/schema/beans
           http://www.springframework.org/schema/beans/spring-beans.xsd
           http://www.springframework.org/schema/tx
           http://www.springframework.org/schema/tx/spring-tx.xsd">

    <!-- 配置事务管理器 -->
    <bean id="transactionManager" class="org.springframework.jdbc.datasource.DataSourceTransactionManager">
        <property name="dataSource" ref="dataSource"/>
    </bean>

    <!-- 启用注解驱动的事务管理 -->
    <tx:annotation-driven transaction-manager="transactionManager"/>
</beans>
```

#### 基于注解的配置

在Java配置中，可以使用`@EnableTransactionManagement`注解启用注解驱动的事务管理，并使用`@Bean`注解配置事务管理器。

**示例：**

```java
@Configuration
@EnableTransactionManagement
public class AppConfig {

    @Bean
    public DataSource dataSource() {
        // 配置数据源
    }

    @Bean
    public PlatformTransactionManager transactionManager() {
        return new DataSourceTransactionManager(dataSource());
    }
}
```

### 使用`@Transactional`注解

`@Transactional`注解用于标记一个方法或类，表示该方法或类中的所有方法需要事务管理。

**示例：**

```java
@Service
public class UserService {

    @Transactional
    public void createUser(User user) {
        // 执行业务逻辑
    }

    @Transactional(rollbackFor = Exception.class)
    public void updateUser(User user) {
        // 执行业务逻辑
    }
}
```

在这个例子中，`createUser`方法使用默认的事务配置，而`updateUser`方法使用`rollbackFor`属性指定了哪些异常会导致事务回滚。

### 事务传播行为

Spring支持多种事务传播行为，可以通过`@Transactional`注解的`propagation`属性来指定。

**示例：**

```java
@Transactional(propagation = Propagation.REQUIRED)
public void someMethod() {
    // 执行业务逻辑
}
```

在这个例子中，`someMethod`方法使用`REQUIRED`传播行为，这意味着如果当前存在事务，则加入该事务；如果当前没有事务，则创建一个新的事务。

### 事务隔离级别

Spring支持多种事务隔离级别，可以通过`@Transactional`注解的`isolation`属性来指定。

**示例：**

```java
@Transactional(isolation = Isolation.READ_COMMITTED)
public void someMethod() {
    // 执行业务逻辑
}
```

在这个例子中，`someMethod`方法使用`READ_COMMITTED`隔离级别，这意味着事务只能读取已提交的数据。

### 总结

Spring事务管理提供了强大的功能，使得开发者可以以声明式的方式管理事务。通过使用`@Transactional`注解和事务管理器，开发者可以轻松地配置和管理事务，从而提高应用程序的可靠性和数据一致性。











# Spring 5模块
## [[Spring AOP]]
## [[Spring MVC]]

## Spring Security
## Spring Boot 2



# Spring 5框架与插件
## [[Apache Shiro]]



# 自创问题
## Spring 5 框架中的上下文
在 **Spring 5** 框架中，**上下文（ApplicationContext）** 是一个核心概念，负责管理和协调应用程序中的所有组件。它是 Spring IoC（控制反转）容器的高级实现，提供了更丰富的企业级功能。以下是 Spring 5 中上下文的详细解释：

#### 1. **定义与作用**
- **定义**: `ApplicationContext` 是 Spring 框架中用于管理应用程序中所有 Bean（对象）的容器。它实现了 `BeanFactory` 接口，并提供了更多的企业级功能。
- **作用**:
  - **依赖注入（DI）**: 通过配置文件或注解，管理 Bean 之间的依赖关系，实现松耦合。
  - **生命周期管理**: 控制 Bean 的创建、初始化、销毁等生命周期。
  - **资源管理**: 加载和管理资源文件，如属性文件、国际化资源等。
  - **事件发布**: 支持事件发布和监听机制，允许应用程序组件之间进行通信。
  - **国际化支持**: 提供国际化（i18n）功能，支持多语言环境。
  - **AOP 支持**: 与 Spring AOP 集成，支持面向切面编程。

#### 2. **与 BeanFactory 的区别**
- `BeanFactory` 是 Spring 容器的低级实现，主要提供依赖注入功能。
- `ApplicationContext` 是 `BeanFactory` 的子接口，提供了更多的企业级功能，如国际化、事件发布、AOP 支持等。

#### 3. **配置方式**
- **XML 配置**: 通过 XML 文件配置 Bean 和依赖关系。
- **注解配置**: 使用注解（如 `@Component`, `@Autowired`, `@Configuration`）进行配置。
- **Java 配置**: 使用 Java 类和 `@Configuration` 注解进行配置。

#### 4. **常见实现类**
- **ClassPathXmlApplicationContext**: 从类路径加载 XML 配置文件。
- **FileSystemXmlApplicationContext**: 从文件系统加载 XML 配置文件。
- **AnnotationConfigApplicationContext**: 从 Java 配置类加载配置。
- **WebApplicationContext**: 用于 Web 应用的上下文实现，如 `XmlWebApplicationContext`。

#### 5. **主要功能**

- **依赖注入**:
  - 通过 `getBean` 方法获取 Bean 实例。
  - 支持构造器注入、Setter 注入和接口注入。

- **事件发布与监听**:
  - 通过 `ApplicationEventPublisher` 接口发布事件。
  - 通过实现 `ApplicationListener` 接口监听事件。

- **国际化（i18n）**:
  - 通过 `MessageSource` 接口获取国际化消息。
  - 支持多语言环境。

- **AOP 支持**:
  - 与 Spring AOP 集成，支持面向切面编程。
  - 通过配置切面，实现横切关注点的注入。

#### 6. **生命周期管理**
- `ApplicationContext` 管理 Bean 的生命周期，包括初始化和销毁。
- 可以通过 `InitializingBean` 和 `DisposableBean` 接口，或使用 `@PostConstruct` 和 `@PreDestroy` 注解来定义初始化和销毁方法。

#### 7. **总结**
Spring 5 中的 `ApplicationContext` 是一个功能强大的 IoC 容器，提供了丰富的企业级功能，包括依赖注入、生命周期管理、资源管理、事件发布、国际化支持和 AOP 支持。它是 Spring 应用的核心组件，负责管理应用程序中的所有组件和资源。

通过 `ApplicationContext`，开发者可以更轻松地构建松耦合、可维护、可测试的应用程序






## 什么是依赖（Dependency）

在软件开发中，**依赖**指的是一个组件（如类、模块或包）依赖于另一个组件来完成其功能。换句话说，当一个组件需要另一个组件来完成其任务时，就存在依赖关系。依赖关系在面向对象编程（OOP）和软件设计中是一个基本概念，影响着代码的可维护性、可测试性和灵活性。

#### 1. **依赖的基本概念**
- **定义**: 依赖是指一个组件依赖于另一个组件来完成其功能。例如，一个类可能依赖于另一个类来执行某个操作。
- **依赖关系**: 依赖关系通常通过方法调用、继承或组合来实现。

**示例**:
```java
public class UserService {
    private UserRepository userRepository;

//每创建一个UserService的对象，无参构造器就创建一个UserRepository的对象
    public UserService() {
        this.userRepository = new UserRepository(); // UserService 依赖于 UserRepository
    }
//依赖UserRepository对象调用save方法实现UserService的create方法
    public void createUser(User user) {
        userRepository.save(user); // 调用 UserRepository 的方法
    }
}
```
在这个例子中，`UserService` 类依赖于 `UserRepository` 类来完成用户保存的功能。


#### 2. **依赖的类型**
- **编译时依赖**: 代码在编译时依赖于另一个组件。例如，一个类继承自另一个类，或者一个类使用另一个类的静态方法。
- **运行时依赖**: 代码在运行时依赖于另一个组件。例如，通过依赖注入（DI）将一个类的实例传递给另一个类。

**示例**:
```java
public class PaymentService {
    private PaymentGateway paymentGateway;

    public PaymentService(PaymentGateway paymentGateway) { // 构造器注入，运行时依赖
        this.paymentGateway = paymentGateway;
    }
//order订单
    public void processPayment(Order order) {
        paymentGateway.charge(order.getAmount()); // 调用 PaymentGateway 的方法
    }
}
```
在这个例子中，`PaymentService` 在运行时依赖于 `PaymentGateway` 类。

#### 3. **依赖注入（Dependency Injection, DI）**
依赖注入是一种设计模式，用于管理类的依赖关系。它通过将依赖对象传递给类，而不是在类内部直接创建依赖对象，来实现松耦合。

**优点**:
- **松耦合**: 类不需要知道依赖对象的创建过程。
- **可测试性**: 更容易进行单元测试，因为可以注入模拟对象（mock objects）。
- **灵活性**: 可以在运行时动态地改变依赖对象。

**示例**:
```java
public class OrderService {
    private PaymentService paymentService;

    public OrderService(PaymentService paymentService) { // 通过构造器注入依赖
        this.paymentService = paymentService;
    }

    public void checkout(Order order) {
        paymentService.processPayment(order); // 使用注入的 PaymentService
    }
}
```

#### 4. **依赖倒置原则（Dependency Inversion Principle, DIP）**
依赖倒置原则是 SOLID 设计原则之一，指出：
- **高层模块不应该依赖于低层模块**，两者都应该依赖于抽象。
- **抽象不应该依赖于细节**，细节应该依赖于抽象。

**示例**:
```java
public interface PaymentGateway {
    void charge(double amount);
}

public class PayPalGateway implements PaymentGateway {
    @Override
    public void charge(double amount) {
        // PayPal 实现
    }
}

public class OrderService {
    private PaymentGateway paymentGateway;

    public OrderService(PaymentGateway paymentGateway) { // 依赖于接口，而不是具体实现
        this.paymentGateway = paymentGateway;
    }

    public void checkout(Order order) {
        paymentGateway.charge(order.getAmount());
    }
}
```
在这个例子中，`OrderService` 依赖于 `PaymentGateway` 接口，而不是具体的 `PayPalGateway` 实现，符合依赖倒置原则。

#### 5. **依赖管理工具**
- **Maven**: 通过 `pom.xml` 文件管理项目依赖，自动下载和管理库文件。
- **Gradle**: 通过 `build.gradle` 文件管理项目依赖，提供更灵活的配置方式。

**示例**:
```xml
<!-- Maven 依赖管理示例 -->
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.3.20</version>
    </dependency>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-context</artifactId>
        <version>5.3.20</version>
    </dependency>
</dependencies>
```

#### 6. **总结**
依赖是软件开发中的一个基本概念，指的是一个组件依赖于另一个组件来完成其功能。管理依赖关系是构建可维护、可测试和灵活的软件系统的关键。通过依赖注入和依赖倒置原则，可以实现松耦合的代码结构，提高代码质量和可维护性。依赖管理工具（如 Maven 和 Gradle）则帮助开发者有效地管理和维护项目依赖。

