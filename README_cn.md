## Google Play就是整个Android系统安全的基石
装置内建google play即包含google play services，每天严格的扫描装置及其安装的应用。
有害应用程序（PHAs）指的是：
1. 滥用APIs（90%）——比如網路釣魚、勒索。
2. 剥削用户（10%）——比如root、获取操作特权、升级、恶意获取管理者权限。

## Google Play审查基准

![gpv.png][gpv.png]

1. 人工检查权限（打扰／侵犯的内容比如spam、非法内容、假冒）——进入自动分析或拒绝。
2. 自动分析，用评分引擎对应用评分（低分原因比如容易被攻击的apps，比如open ssl版本过旧（可能造成Logjam攻击也就是阻塞攻击）——上架或人工再审或拒绝。
3. 用户安装，这些已安装的应用每天都会通过sensor network分析回馈，进而影响应用的分数。或者也会通过verify apps被卸载或是影响评分。

## Google如何分析应用
1. 静态分析——反编译应用并分析代码
2. 动态分析——在google的模拟器运行应用（测试网络传输、与其它服务的交互应用）
3. 第三方报告——学术机构、安全公司、独立研究学者
4. 开发者联系——通过签名证书、google play账户、甚至应用的结构来关联开发者或其它应用
5. 感知网络——就是sensor network
6. 类似分析——大多恶意行为都不是全新的，可比对过去案例。

Google分析不断的进步，因为分析了来自十万个以上不同网站的应用和每日用户安装的应用、日渐扩充的硬件设备与机器学习。

## Google Play Services即用的保护机制
### Verify apps
 - 侦测有害应用并卸载
 - 非google play来源应用限制安装
 - 罕见UID（Linux UID）
 - 应用的安装来自其它有害应用触发
 - 每日扫描装置上安装的应用

### Sensor Network
 - 监督应用的行为并且每日回馈google，能远端阻止恶意行为

### Developer APIs
 - 审查安全装置的状态

### Android Device Manager
 - 让用户能定位、大响、锁屏、寻找及清除账户信息。
 - 前提也是装置须安装google services，链接google账户

## SafetyNet APIS

### Attestation
在下列几种情形，可以通过调用google提供的SafetyNet类的Attestation API找到答案：
1. 目前和我的server沟通的应用是不是真的我的应用。
2. 我可以相信这个Android的API么？
3. 这是真正的、相容的装置么？
4. 我的应用是不是运行在一个rooted的装置。

简言之，这是用来评估自己的应用运行的环境安全和相容性的API，
验证应用的完整性，兼容性和签名。

至于对于这个运行环境（装置或应用）要不要信任就是自定义的了（让自己的服务器决定）。

API说明<br>
nonce就是token，自己的服务器提供或是从装置随机生成。
client：呼叫API就行了，取得JWS结果，并​​传送给自己的server。
server：检查SSL的证书链（根证书是不是来自官方或可信任机构的），检查用来签名JWS的证书。

JWS栏位说明<br>
nonce：client随机生成或是来自自己服务器的token。
timestamp：呼叫该API的时间戳。
apkPackageName：包名是不是对的（这个正在跟服务器沟通的是不是自己的应用）。
apkCertificateDigestSHA256：打包apk的keystore的信息摘要值检查（这个APK是不是我本人发布的）。
apkDigestSHA256：apk的hash值。（这个APK有没有被篡改过）。
ctsProfileMatch：这个装置是不是真正的、可信任的装置。
basicIntegrity：过滤条件略比ctsProfileMatch宽容，告诉你这个装置是否兼容Android的，有没有被篡改过。

实测数据<br>
运行于LG Pro2得JWS为：
```JSON
{"nonce":"XYFykVQX2mNyVDYZa4YAu8gBP6/3XWqg+zloYjhrg9M=",
"timestampMs":1498718050630,
"apkPackageName":"com.catherine.securitysample",
"apkDigestSha256":"dDUhx9ODbLHNYxN8Is+1RX/9RWhQ3FwCpRWLHFP5Qp8=",
"ctsProfileMatch":true,
"extension":"CXGWLc3ajPR5",
"apkCertificateDigestSha256":["9mLFS3eHWOBcHlA4MmODmfGvzgkbg2YSQ2z/ww9lCfw="],
"basicIntegrity":true}​
```

运行于nox模拟器，所得JWS为：
```JSON
{"nonce":"3QVAX20nI/uir405vctoInSvgYYudRUFts7gLDDGCxE=​",
"timestampMs":1498718484795​,
"apkPackageName":"com.catherine.securitysample",
"apkDigestSha256":"dDUhx9ODbLHNYxN8Is+1RX/9RWhQ3FwCpRWLHFP5Qp8=",
"ctsProfileMatch":false,
"extension":"CXGWLc3ajPR5",
"apkCertificateDigestSha256":["9mLFS3eHWOBcHlA4MmODmfGvzgkbg2YSQ2z/ww9lCfw="],
"basicIntegrity":false}​​
```

### Safe browsing
评估一个链接的危险程度，检查是不是有潜在危害，然后警告用户不要前往或分享。
可以保护隐私、提高带宽。
Chrome也有串接此API。

API用法：
SafetyNetApi.lookupUri(...)
传入一个URL，Safe browsing会告诉你

# License

```
Copyright 2017 Catherine Chen (https://github.com/Catherine22)

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License. You may obtain a copy of
the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
```
[gpv.png]: https://github.com/Catherine22/SecuritySample/blob/master/gpv.png
