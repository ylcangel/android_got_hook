# android_got_hook
android got hook under version 5.0

基于学习和分享的目的，你可以自行下载，随意进行更改，但需要注明出处，版权属于我个人所有。

实现原理和思路：

1、必须完全了解Android linker加载和解析so过程

2、仿照linker解析过程解析要进行hook的so

3、修改GOT条目对于segment属性为可写，替换GOT条目，修改回为原属性

