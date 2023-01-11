package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"sandPay/util"
	"time"
)

func main() {

	pubKey := util.LoadPublicKey("cert/public.pem")
	prvKey := util.LoadPrivateKey("cert/private.pem")
	fd := Params()
	sanDe := util.SandAES{}
	key := sanDe.RandStr(16)

	fdata, _ := FormData(fd, key)
	fd["encryptKey"], _ = FormEncryptKey(key, pubKey)
	fd["sign"], _ = FormSign(fdata, prvKey)
	fd["data"] = fdata
	//display(fd)

	DataByte, _ := json.Marshal(fd)
	api := "https://ceas-uat01.sand.com.cn/v4/electrans/ceas.elec.trans.corp.transfer"

	resp, err := util.Do(api, string(DataByte))
	fmt.Println(err)
	d := make(map[string]interface{})
	if err := json.Unmarshal(resp, &d); err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("杉德回调解析结果:" + string(resp))
}

func display(fd map[string]interface{}) {
	for k, v := range fd {
		fmt.Println(k, "->", v)
	}
}

func Params() map[string]interface{} {

	User := struct {
		BizUserNo string `json:"bizUserNo"` // 会员编号
		Name      string `json:"name"`      // 会员姓名
	}{
		BizUserNo: "101",
		Name:      "章三",
	}

	//整理签名数据
	orderNo := time.Now().Format("20060102150405")
	paraMap := make(map[string]interface{})
	paraMap["mid"] = "68888TS117374"
	paraMap["timestamp"] = time.Now().Format("20060102150405")
	paraMap["version"] = "1.0"
	paraMap["signType"] = "SHA1WithRSA"
	paraMap["encryptType"] = "AES"

	paraMap["customerOrderNo"] = orderNo
	paraMap["accountType"] = "01"
	paraMap["orderAmt"] = "0.01"
	paraMap["payee"] = User
	paraMap["postscript"] = "附言"
	paraMap["remark"] = "备注"
	return paraMap

}

func FormData(paraMap map[string]interface{}, key string) (string, error) {

	dataJson, err := json.Marshal(paraMap)
	if err != nil {
		return "", err
	}
	aes := util.SandAES{}
	aes.Key = []byte(key)

	data := aes.Encypt5(dataJson)
	return data, nil
}

func FormEncryptKey(key string, pubKey *rsa.PublicKey) (string, error) {

	return util.RsaEncrypt(key, pubKey)
}

func FormSign(data string, priKey *rsa.PrivateKey) (string, error) {
	return util.SignSand(priKey, data)
}
