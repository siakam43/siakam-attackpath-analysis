# 原始需求

## 整体说明
1. 我需要开发一个单纯由markdown文档和python脚本组成的skill, 名字叫siakam-attackpath-analysis
2. 核心功能：从一个外部攻击者可以传入“攻击数据”的入口函数开始，识别可能被“攻击数据”影响的攻击路径（函数序列），并深入分析每条攻击路径中存在的安全隐患。

## 流程与架构
### 0 工具输入
1. SKILL使用方法：/siakam-attackpath-analysis  project_dir 
2. 参数project_dir为待分析项目路径，如果用户没有指定该参数，默认为当前文件夹。
3. 在project_dir中，如果存在.siakamignore文件，需要将该文件中指定的子目录或文件排除掉，不进行分析。.siakamignore文件语法和.gitignore语法一样。
4. 在project_dir中,如果存在.siakam_out/callgraph.json文件,可以利用其辅助识别攻击路径。在本文件相同目录有一个callgraph.json样例文件，根据样例了解文件格式。
5. 在project_dir中，应该存在.siakam_out/SII/apis.json文件,该文件提供全部入口函数的信息。如果apis.json不存在，需提醒用户指定该文件的路径给agent，否则无法继续
- apis.json格式，其中interfaces字段中保存了全部入口函数：
'''json
{
  "project": "<project_dir basename>",
  "analysis_date": "<YYYY-MM-DD>",
  "total_candidates": <N>,
  "confirmed_interfaces": <X>,
  "summary": {
    "high_confidence": <H>,
    "medium_confidence": <M>,
    "exclusion_reasons": {
      "<reason_key>": <count>,
      "...": 0
    }
  },
  "interfaces": [
    {
      "name": "<function name>",
      "file": "<path relative to project_dir>",
      "line": <line>,
      "confidence": "<high or medium>",
      "analysis": "<multi-line structured analysis>"
    }
  ],
  "failures": [
    {
      "name": "<function name>",
      "file": "<path>",
      "line": <line>,
      "reason": "<failure reason>"
    }
  ],
  "errors": ["<error string>"],
  "warnings": ["<warning string>"]
}
'''

### callgraph解析工具cg_helper.py
1. cg_helper.py。使用方法：
- python3 cg_helper.py FUNC caller   : 输出所有会调用FUNC的函数列表
- python3 cg_helper.py FUNC callee   : 输出FUNC调用的全部函数列表


### 步骤1：攻击路径识别
1. 针对每个入口函数entry，构建以entry为起点的函数调用图。之后再分析函数调用图中，哪些节点函数会被entry的参数（“攻击数据”）影响，将这些函数列为高危函数。从entry到每个高危函数的代码调用路径就是攻击路径。
2. 入口函数有多个，但分析相互独立。提示词应该要求采取多subagent并行分析的策略，同时应有任务列表文件（临时文件，全部任务结束后清理掉，可以暂存在.siakam_out/SAA目录）来跟踪进度，避免任务丢失。每个入口函数生成一个结果文件，保存在.siakam_out/SAA/attack_path/xxx_attack_path.md中。文件中应包含全部高危函数以及从entry到高危函数的调用关系， 格式待设计。
3. 设计精准提示词描述识别攻击路径的方法，保证结果的准确性。


### 步骤2：安全漏洞识别
1. 针对每条攻击路径，分析路径中每一个函数中是否存在安全漏洞。
2. 分析的业务全部是c语言代码。目标包括：linux内核驱动模块，手机主核启动链（uefi,bl31,bl2,xloader等），手机小核固件（isp，sensorhub，gpu等）
3. 不关心数据库，web，隐私泄露，内存泄漏等方面的安全问题。不关心性能问题和稳定性问题
4. 重点关注的安全问题类别，待补充完善
- 外部输入未校验或校验不充分: Missing validation on all external inputs (interface parameter, file, IPC, shared memory); Shared memory data read without integrity/safety checks; Trust boundary violations (trusting data from untrusted sources); Missing bounds checking on data from external sources; Type confusion from unvalidated input; Deserialization of untrusted data without validation; Missing validation on inter-process communication (IPC) data; Environment variable injection from external sources
- 内存安全：Buffer overflows (stack-based, heap-based); Out-of-bounds read/write (array index vulnerabilities); Use-after-free (UAF) vulnerabilities; Double free vulnerabilities; Null pointer dereference; Uninitialized memory access; Integer overflow/underflow leading to memory corruption; Format string vulnerabilities
- 系统安全:Authentication bypass logic; Privilege escalation paths; Remote code execution; dynamic code execution
- 密码安全:Hardcoded API keys, passwords, or tokens; Weak cryptographic algorithms or implementations; Improper key storage or management; Cryptographic randomness issues; Certificate validation bypasses
- 多线程竞争场景下的内存安全问题
5. 根据上述信息，设计安全漏洞的分析方法提示词（重点），精准识别安全漏洞。安全漏洞识别任务也采用多subagent并行分析的策略,每个subagent负责分析一个入口函数的攻击路径。发现的漏洞保存在：.siakam_out/SAA/vulns/xxx_vuls.md。保存的内容包括安全评级，置信度，漏洞描述，从entry到漏洞点的调用路径，漏洞利用场景，修复建议等。
- SEVERITY GUIDELINES:HIGH: Directly exploitable vulnerabilities leading to RCE, data breach, or authentication bypass; MEDIUM: Vulnerabilities requiring specific conditions but with significant impact; LOW: Defense-in-depth issues or lower-impact vulnerabilities
- CONFIDENCE SCORING:0.9-1.0: Certain exploit path identified, tested if possible; 0.8-0.9: Clear vulnerability pattern with known exploitation methods; 0.7-0.8: Suspicious pattern requiring specific conditions to exploit; Below 0.7: Don't report (too speculative)


### 步骤3: 去误报
1. 通过干净的上下文分析每一个漏洞，不要被之前的分析所影响。评估是否为误报。确定为误报漏洞在文档中标记。重要：do not need to run commands to reproduce the vulnerability，Do not use the bash tool or write to any files.
2. 去误报的规则，待拓展完善
HARD EXCLUSIONS - Automatically exclude findings matching these patterns:

- Denial of Service (DOS) vulnerabilities or resource exhaustion attacks.
- Secrets or credentials stored on disk if they are otherwise secured.
- Rate limiting concerns or service overload scenarios.
- Memory consumption or CPU exhaustion issues.
- Lack of input validation on non-security-critical fields without proven security impact.
- A lack of hardening measures. Code is not expected to implement all security best practices, only flag concrete vulnerabilities.
- Race conditions that are purely theoretical without a concrete exploitation path. However, DO report race conditions if: (1) there is a clear TOCTOU pattern with exploitable window, (2) shared state is accessed without synchronization in multi-threaded code, (3) there is a demonstrable data race with security impact.
- Vulnerabilities related to outdated third-party libraries. These are managed separately and should not be reported here.
- Files that are only unit tests or only used as part of running tests.
- Log spoofing concerns. Outputting un-sanitized user input to logs is not a vulnerability.
- Including user-controlled content in AI system prompts is not a vulnerability.
- Regex injection. Injecting untrusted content into a regex is not a vulnerability.
- Insecure documentation. Do not report any findings in documentation files such as markdown files.
- A lack of audit logs is not a vulnerability.
3. 本步骤依然使用多subagent并行分析。
4. 完成全部去误报工作后，汇总全部漏洞到一份报告中：.siakam_out/SAA/Vul_report.md




## 要求
1. 需要使用代码仓探索的常用工具，SKILL应提前申请权限。
2. 本SKILL全部功能由LLM完成分析，在Agent(claude/opencode)调用skill时，遵循skill的说明知道LLM工作。仅步骤1可能需要cg_helper.py辅助，除此之外，本模块禁止开发使用任何脚本和代码！ 
3. LLM应尽最大努力，精准分析每一个任务，做出最合理的判断。
4. 本skill由LLM review代码的方式完成，SKILL提示词是本工具开发的重点。需要标准的提示词，创建任务列表等方式严格限制LLM的行为，避免发生任务遗忘。同时，要注意不同间接调用分析过程的相互影响。
5. 整个skill的提示词都用英文。
6. 漏洞分析原则：Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a security engineer would confidently raise in a PR review.


