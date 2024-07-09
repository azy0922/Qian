package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
)

var (
	PRIVATE_KEY   = os.Getenv("PRIVATE_KEY_HEX") //
	PASS_PHRASE   = os.Getenv("PASS_PHRASE")     //
	IP_WHITE_LIST = os.Getenv("IP_WHITE_LIST")
)

func main() {

	gin.DisableConsoleColor()
	gin.SetMode(gin.ReleaseMode)
	logFile, err := os.OpenFile("qian.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("Create qian.log failed:", err)
	}

	if PRIVATE_KEY == "" {
		log.Fatalln("Private key initialize failed.")
	}

	if PASS_PHRASE == "" {
		log.Fatalln("Pass phrase initialize failed.")
	}

	app := gin.New()
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime)
	app.Use(gin.Recovery())
	app.GET("/qian", redeem)

	app.Run(":80")
}

func redeem(c *gin.Context) {
	// 检查是否白名单ip
	client := c.ClientIP()
	if client != IP_WHITE_LIST {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code": -1001,
			"msg":  "No such IP has been white listed.",
		})
		c.Abort()
		return
	}
	// 获取时间戳
	timestamp := c.Query("timestamp")
	timeInt64, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		// 转换失败，返回错误信息
		c.JSON(http.StatusBadRequest, gin.H{
			"code": -1002,
			"msg":  "Invalid timestamp format.",
		})
		c.Abort()
		return
	}

	serverTime := time.Now().UnixMilli()
	if timeInt64 < (serverTime+1000) && (serverTime-timeInt64) <= 5000 {
		// 开始验证签名信息
		sign := c.Query("signature")
		address := c.Query("addr")
		amount := c.Query("amnt")
		query := "addr=" + address + "&amnt=" + amount + "&timestamp=" + timestamp

		re := regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)
		if !re.MatchString(address) {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": -1003,
				"msg":  "Invalid address format.",
			})
			c.Abort()
			return
		}

		amount64, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": -1004,
				"msg":  "Invalid amount format.",
			})
			c.Abort()
			return
		}

		// 控制单次提取数量
		if amount64 > 0.01 || amount64 < 0.00001 {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": -1101,
				"msg":  "The redeem amount is too small or too large.",
			})
			c.Abort()
			return
		}

		signature := signature(query, PASS_PHRASE)

		if sign != signature {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": -1005,
				"msg":  "Signature for this request is not valid.",
			})
			c.Abort()
			return
		}

		// 记录日志
		log.Println("Query string: ", query)

		// 执行转账操作
		txid, err := transfer(address, amount64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": -2001,
				"msg":  err.Error(),
			})
			c.Abort()
			return
		}

		// 转账成功
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"txid": txid,
		})

	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": -1006,
			"msg":  "Timestamp for this request is outside of the recvWindow.",
		})
		c.Abort()
		return
	}

}

func waitConfirm(ctx context.Context, ec *ethclient.Client, txHash common.Hash, timeout time.Duration) error {
	pending := true
	for pending {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(timeout):
			return errors.New("timeout")
		case <-time.After(time.Second):
			_, isPending, err := ec.TransactionByHash(ctx, txHash)
			if err != nil {
				return err
			}
			if !isPending {
				pending = false // break `for`
			}
		}
	}
	receipt, err := ec.TransactionReceipt(ctx, txHash)
	if err != nil {
		return err
	}
	if receipt.Status == 0 {
		msg := fmt.Sprintf("transaction reverted, hash %s", receipt.TxHash.String())
		return errors.New(msg)
	}
	return nil
}

func transfer(address string, amount float64) (string, error) {
	client, err := ethclient.Dial("https://arb1.arbitrum.io/rpc")
	if err != nil {
		log.Println("ethclient.Dial failed:", err.Error())
		return "", err
	}
	defer client.Close()

	ctx := context.Background()

	// 将私钥字节转换为 ecdsa.PrivateKey 类型
	privateKey, err := crypto.HexToECDSA(PRIVATE_KEY)
	if err != nil {
		log.Println("crypto.HexToECDSA failed:", err.Error())
		return "", err
	}

	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	// 收款地址
	toAddress := common.HexToAddress(address)

	// 资产
	value := big.NewInt(int64(amount * float64(1e18)))

	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		log.Println("client.HeaderByNumber failed:", err.Error())
		return "", err
	}

	// 构建交易
	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		log.Println("client.PendingNonceAt failed:", err.Error())
		return "", err
	}

	gasTipCap, err := client.SuggestGasTipCap(ctx)
	maxFeePerGas := new(big.Int).Add(header.BaseFee, big.NewInt(1_000_000))

	msg := ethereum.CallMsg{
		From:      fromAddress,
		To:        &toAddress,
		Gas:       0,
		Value:     value,
		GasFeeCap: maxFeePerGas,
		GasTipCap: gasTipCap,
	}

	// 估算gas limit
	gasLimit, err := client.EstimateGas(ctx, msg)
	if err != nil {
		log.Println("client.EstimateGas failed:", err.Error())
		return "", err
	}

	chainId := big.NewInt(42161) // Arbitrum One 的 Chain ID

	tx := &types.DynamicFeeTx{
		ChainID:   chainId,
		Nonce:     nonce,
		To:        &toAddress,
		Value:     value,
		Gas:       gasLimit,
		GasFeeCap: maxFeePerGas,
		GasTipCap: gasTipCap,
	}

	// 签署交易
	signedTx, err := types.SignNewTx(privateKey, types.LatestSignerForChainID(chainId), tx)
	if err != nil {
		log.Println("types.SignNewTx failed:", err.Error())
		return "", err
	}

	// 发送交易
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		log.Println("client.SendTransaction failed:", err.Error())
		return "", err
	}

	if err = waitConfirm(ctx, client, signedTx.Hash(), time.Minute*5); err != nil {
		log.Println("wait confirmation error:", err.Error())
		return "", err
	}

	log.Printf("Toaddres: %s, amount: %f, txid: %s confirmed\n",
		address,
		amount,
		signedTx.Hash())

	return signedTx.Hash().Hex(), nil
}

func signature(message, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signingKey := fmt.Sprintf("%x", mac.Sum(nil))
	return signingKey
}
