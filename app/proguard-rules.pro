# 代码混淆压缩比，在0~7之间，默认为5，一般不做修改
-optimizationpasses 7

# 混合时不使用大小写混合，混合后的类名为小写
-dontusemixedcaseclassnames

# 指定不去忽略非公共库的类
-dontskipnonpubliclibraryclasses

# 指定不去忽略非公共库的类成员
-dontskipnonpubliclibraryclassmembers

# 不做预校验，preverify是proguard的四个步骤之一，Android不需要preverify，去掉这一步能够加快混淆速度。
-dontpreverify

# 保留Annotation不混淆
-keepattributes *Annotation*,InnerClasses

# 避免混淆泛型
-keepattributes Signature

# 指定混淆是采用的算法，后面的参数是一个过滤器
# 这个过滤器是谷歌推荐的算法，一般不做更改
-optimizations !code/simplification/cast,!field/*,!class/merging/*

#这个选项禁用了对算术操作的简化优化
#在某些情况下，简化算术操作可能导致精度损失或异常情况的发生
#因此禁用这个优化可以确保算术操作的准确性。
-optimizations !code/simplification/arithmetic

#这个选项禁用了对类型转换操作的简化优化
#类型转换操作在某些情况下可能会引发运行时异常
#因此禁用这个优化可以确保类型转换操作的安全性。
-optimizations !code/simplification/cast

#这个选项禁用了对字段操作的简化优化
#字段操作包括读取和写入类的字段（成员变量）
#禁用这个优化可以确保字段操作的准确性和可靠性
-optimizations !code/simplification/field

#这个选项禁用了对变量操作的简化优化
#变量操作包括对局部变量和参数的读取和写入
#禁用这个优化可以确保变量操作的准确性和可靠性
-optimizations !code/simplification/variable

#这个选项禁用了对分支语句（如 if-else、switch-case）的简化优化
#禁用这个优化可以确保分支语句的逻辑不会被改变，以保证代码的正确性
-optimizations !code/simplification/branch

#这个选项禁用了对方法调用的内联优化
#内联优化会将方法调用替换为方法内的实际代码，以减少方法调用的开销
#禁用这个优化可以确保方法调用的正确性和可读性
-optimizations !code/simplification/inlining

# 保留我们使用的四大组件，自定义的Application等等这些类不被混淆
# 因为这些子类都有可能被外部调用
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider
-keep public class * extends android.app.backup.BackupAgentHelper
-keep public class * extends android.preference.Preference
-keep public class * extends android.view.View
-keep public class com.android.vending.licensing.ILicensingService

# 保留R下面的资源
#-keep class **.R$* {*;}

#保留本地native方法不被混淆
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留枚举类不被混淆
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# 保留Parcelable序列化类不被混淆
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# 保留Serializable序列化的类不被混淆
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    !static !transient <fields>;
    !private <fields>;
    !private <methods>;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# 对于带有回调函数的onXXEvent、**On*Listener的，不能被混淆
-keepclassmembers class * {
    void *(**On*Event);
    void *(**On*Listener);
}

#使用给定文件中的关键字作为要混淆方法能和字段的名称,默认使用像'a'这样的短名称
-obfuscationdictionary dictionary.txt
#指定包含合法的用于混淆后的类的名称的字符集合的文本文件
-classobfuscationdictionary dictionary.txt
#通过文本文件指定合法的包名
-packageobfuscationdictionary dictionary.txt

#处理扩展类和类成员的访问修饰符
-allowaccessmodification
#允许多个字段和方法相同名称,只是参数和返回类型不同
-overloadaggressively
#重新包装所有已重命名的类文件,移动到给定的单一包中
-repackageclasses 'littlewhitebear.signverification'