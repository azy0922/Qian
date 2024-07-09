```rust
      ___                       ___           ___     
     /\  \          ___        /\  \         /\__\    
    /::\  \        /\  \      /::\  \       /::|  |   
   /:/\:\  \       \:\  \    /:/\:\  \     /:|:|  |   
   \:\~\:\  \      /::\__\  /::\~\:\  \   /:/|:|  |__ 
    \:\ \:\__\  __/:/\/__/ /:/\:\ \:\__\ /:/ |:| /\__\
     \:\/:/  / /\/:/  /    \/__\:\/:/  / \/__|:|/:/  /
      \::/  /  \::/__/          \::/  /      |:/:/  / 
      /:/  /    \:\__\          /:/  /       |::/  /  
     /:/  /      \/__/         /:/  /        /:/  /   
     \/__/                     \/__/         \/__/    
     
时间：2024.07.05
版本：ver 2.1
作者：@剁刀师甲
```

千军网安Rank 2.0版本，旨在构建去中心化、加密安全、实时兑换、自由可达的数字资产体系，为此将引入新的子系统：Qian。

### 0x01. Qian子系统

Qian子系统的核心是：定义单位"芊"（Qan）和"荌"（an），1 芊和1个[Ethereum](https://ethereum.org/zh/)（ETH）具有相同价值。

在此基础上，Rank的价格锚定Qan的价格，二者兑换关系如下：

$$
1 ETH = 1 芊 = 1000 荌
$$

$$
1 Rank = 10^{-5} 荌 \times 杠杆倍数
$$

### 0x02. 杠杆倍数

杠杆的初始值为0，最大值为9。杠杆倍数按群每日出块数量即时调整（见表）。杠杆倍数的跌落，每24小时只跌落1级，不跨级跌落。Beta测试期间暂不执行0杠杆，最低杠杆倍数为1。

| 每日出块数 | 杠杆倍数 |
| :--------: | :------: |
|    0~5     |    0     |
|    6~23    |    1     |
|   24~47    |    2     |
|   48~95    |    3     |
|   96~191   |    4     |
|  192~383   |    5     |
|  384~767   |    6     |
|  768~1535  |    7     |
| 1536~3071  |    8     |
|  3072以上  |  **9**   |

若杠杆倍数发生变化，由bot在群中发送消息："出块数达到XX，杠杆倍数调整为XX"。

**示例场景1**：若群日出块数不足6块，则杠杆倍数为0，Rank价值为0；当挖出6块，杠杆倍数为1时，Rank才有价值。

**示例场景2**：若群挖出Lv4的超级大块1536块，则杠杆倍数将瞬间调整为8，Rank价格将升至初始值的8倍。

综上，Rank的价格由Qan的当前市场价格和杠杆倍数同时决定。当Qan的市场价格波动很小时，发言越多，出块数越多，Rank价值越大。



### 0x03. Rank总量

当前Rank总量为840,000个，无法满足未来5年挖矿需求，**故将Rank增发至21,000,000个**（后续视挖矿情况继续增发扩大市值），具体模型如下：

|     Level     |  区块数  | 每个区块Rank数 |
| :-----------: | :------: | :------------: |
|       1       |   2100   |       1        |
|       2       |   2100   |       2        |
|       3       |   2100   |       3        |
|       4       |   2100   |       6        |
|       5       |   2100   |       13       |
|       6       |   2100   |       25       |
| **当前 => 7** | **2100** |     **50**     |
|       8       |   2100   |      100       |
|       9       |   2100   |      200       |
|      10       |   2100   |      300       |
|      11       |   2100   |      500       |
|      12       |   2100   |      800       |
|      13       |   2100   |      1200      |
|      14       |   2100   |      1600      |
|      15       |   2100   |      2000      |
|      16       |   2100   |      3200      |



### 0x04. 相关命令

新增命令主要用于为用户生成Arbitrum Layer2层的钱包地址和私钥，执行转账等操作。

- [x] **/wallet（私聊）**，首次执行时，生成Layer2层钱包地址、私钥和助记词，并将用户钱包地址和wxid进行绑定
- [x] **/redeem 数量（私聊）**，将Rank按当前市场价格兑换为Qan，并提款至用户钱包地址（暂时仅支持Rank兑换为Qan不允许反向兑换）
- [x] **/price（私聊+群聊）**，查询1 Rank的即时价格（按CNY计价）
- [x] **/qian（私聊）**，显示使用手册

