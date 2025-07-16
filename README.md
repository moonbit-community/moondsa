# ruifeng/dilithium

本项目使用 MoonBit 实现了 Dilithium 算法，一种抗量子的签名算法。
提供秘钥生成，签名，验证等三个函数。

## RoadMap

- [x] 基本功能:keygen, sign, verify
- [x] 多种安全级别，Dilithium-2, Dilithium-3, Dilithium-5
- [x] 使用 kat 进行全面测试
- [ ] AES 签名算法
- [ ] 实现非确定性算法（需要 random）

## Warning

本项目没有经过安全性分析。请谨慎使用。

## Examples

```
// 首先需要设置优先级别
@dilithium.dilithium_context.set_level(SecurityLevel::Dilithium5)
let (pk, sk) = keypair_gen(Ok(seed)) // 这里需要传入seed或者Rand作为随机
let sign = sign(msg, sk) 
let result : Result[Unit, SignError] = verify(sig, msg, pk)
```
