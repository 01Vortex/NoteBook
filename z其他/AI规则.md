# 基本规则
1. 用中文回答
2. 以最佳实践设计,避免冗余,降级,兼容方案
3. 如果需要用到批处理指令,必须用utf-8无bom,绝对不允许出现中文乱码的操作
4. 写的代码尽可能做到易读,不用太复杂
5. 不用写总结文档和示例文档不用写任何东西
6. 不允许使用emoji表情,只能用svg图标或者暂时不用


  

# 前端规则

1. 后端是使用的雪花id,前端要防止精度丢失

  

# 后端规则

1. 不能这么写private final com.vortex.instalens.api.service.infrastructure.LikeCacheService likeCacheService;先导入import com.vortex.instalens.api.service.infrastructure.LikeCacheService;再用private final LikeCacheService likeCacheService;

2. MediaQueryService为服务接口放到对应的api模块,MediaQueryServiceImpl作为服务类,放在具体的服务模块下

3. 内部服务（如事件监听器、引擎类）不需要提取接口到api模块，直接放在具体服务模块下，避免循环依赖

   - 例如：BadgeUnlockEngine 监听事件并调用 BadgeService，不需要接口

   - 只有需要跨模块调用的服务才提取接口到api模块

4. 只能使用POST和GET

5. 不能这么写com.vortex.instalens.domain.entity.user.User getUserByUsername(String username);