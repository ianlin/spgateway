const SHA256 = require("./sha256");
const DataChainGenerator = require("./data.chain.generator");
const aes = require('aes-js')
const crypto = require('crypto')

class ValidationHelper {

    constructor(config) {
        this.config = config;
        this.sha256 = new SHA256();
    }

    genTradeInfo(payload) {
		let data = []
        Object.keys(payload).forEach(key => {
            data.push(`${key}=${encodeURIComponent(payload[key])}`)
        })

        let cbc = new aes.ModeOfOperation.cbc(Buffer.from(this.config.HashKey), Buffer.from(this.config.HashIV))
        let info = aes.utils.hex.fromBytes(cbc.encrypt(aes.utils.utf8.toBytes(this.padding(data.join('&')))))
        return info;
    }

    genTradeSha(tradeInfo) {
        if (!tradeInfo) return null;
        return crypto.createHash('sha256')
            .update(`HashKey=${this.config.HashKey}&${tradeInfo}&HashIV=${this.config.HashIV}`)
            .digest('hex')
            .toUpperCase();
    }

    padding(str) {
        var len = str.length
        var pad = 32 - (len % 32)
        str += String.fromCharCode(pad).repeat(pad)
        return str
    }

    removePadding(plaintext) {
        var len = 0
        for (var i = plaintext.length - 1; i >= 0; i--) {
            if (plaintext[i] === '}') break
            len++
        }

        return plaintext.substr(0, plaintext.length - len)
    }

    decrypt(key, iv, data) {
        let cbc = new aes.ModeOfOperation.cbc(Buffer.from(key), Buffer.from(iv))
        //console.log('IANXXX 1 cbc:', cbc);

        let encryptedBytes = aes.utils.hex.toBytes(data)
        //console.log('IANXXX 2 encryptedBytes:', encryptedBytes);

        let decryptedBytes = cbc.decrypt(encryptedBytes)
        //console.log('IANXXX 3 decryptedBytes:', decryptedBytes);

        let plaintext = aes.utils.utf8.fromBytes(decryptedBytes)
        //console.log('IANXXX 4 plaintext:', plaintext);

        let plaintextNoPad = this.removePadding(plaintext);
        //console.log('IANXXX 5 plaintextNoPad:', plaintextNoPad);

        //return plaintextNoPad;
        return plaintext;
    }

    /**
     * 上行 Qry check value 建立
     * @param {*} Amt
     * @param {*} MerchantOrderNo
     */
    genQryTrdInfoChkValue(Amt, MerchantOrderNo) {
        let dcg = new DataChainGenerator();
        dcg.addKeyValue("IV", this.config.HashIV);
        dcg.addKeyValue("Amt", Amt);
        dcg.addKeyValue("MerchantID", this.config.MerchantID);
        dcg.addKeyValue("MerchantOrderNo", MerchantOrderNo);
        dcg.addKeyValue("Key", this.config.HashKey);
        let dataChain = dcg.genDataChain();
        return this.sha256.encrypt(dataChain).toUpperCase();
    }


    /**
     * 下行 Qry check code 建立
     * @param {*} Amt
     * @param {*} MerchantOrderNo
     */
    genQryTrdInfoChkCode(Amt, MerchantOrderNo, TradeNo) {
        let dcg = new DataChainGenerator();
        dcg.addKeyValue("HashIV", this.config.HashIV);
        dcg.addKeyValue("Amt", Amt);
        dcg.addKeyValue("MerchantID", this.config.MerchantID);
        dcg.addKeyValue("MerchantOrderNo", MerchantOrderNo);
        dcg.addKeyValue("TradeNo", TradeNo);
        dcg.addKeyValue("HashKey", this.config.HashKey);
        let dataChain = dcg.genDataChain();
        return this.sha256.encrypt(dataChain).toUpperCase();
    }

    /**
     * 上行 MPG check value 建立
     * @param {*} Amt
     * @param {*} MerchantOrderNo
     * @param {*} TimeStamp
     * @param {*} Version
     */
    genMpgCheckValue(Amt, MerchantOrderNo, TimeStamp, Version) {
        let dcg = new DataChainGenerator();
        dcg.addKeyValue("HashKey", this.config.HashKey);
        dcg.addKeyValue("Amt", Amt);
        dcg.addKeyValue("MerchantID", this.config.MerchantID);
        dcg.addKeyValue("MerchantOrderNo", MerchantOrderNo);
        dcg.addKeyValue("TimeStamp", TimeStamp);
        dcg.addKeyValue("Version", Version);
        dcg.addKeyValue("HashIV", this.config.HashIV);
        let dataChain = dcg.genDataChain();
        return this.sha256.encrypt(dataChain).toUpperCase();
    }

    /**
     * MPG 回傳check code 檢驗
     * @param {*} Amt
     * @param {*} MerchantOrderNo
     * @param {*} TradeNo
     */
    genMpgCheckCode(Amt, MerchantOrderNo, TradeNo) {
        let dcg = new DataChainGenerator();
        dcg.addKeyValue("HashIV", this.config.HashIV);
        dcg.addKeyValue("Amt", Amt);
        dcg.addKeyValue("MerchantID", this.config.MerchantID);
        dcg.addKeyValue("MerchantOrderNo", MerchantOrderNo);
        dcg.addKeyValue("TradeNo", TradeNo);
        dcg.addKeyValue("HashKey", this.config.HashKey);
        let dataChain = dcg.genDataChain();
        return this.sha256.encrypt(dataChain).toUpperCase();
    }

    /**
     * CreditCard Cancel 回傳check code 檢驗
     * @param {*} Amt
     * @param {*} MerchantOrderNo
     * @param {*} TradeNo
     */
    genCreditCardCancelCheckCode(Amt, MerchantOrderNo, TradeNo) {
        let dcg = new DataChainGenerator();
        dcg.addKeyValue("HashIV", this.config.HashIV);
        dcg.addKeyValue("Amt", Amt);
        dcg.addKeyValue("MerchantID", this.config.MerchantID);
        dcg.addKeyValue("MerchantOrderNo", MerchantOrderNo);
        dcg.addKeyValue("TradeNo", TradeNo);
        dcg.addKeyValue("HashKey", this.config.HashKey);
        let dataChain = dcg.genDataChain();
        return this.sha256.encrypt(dataChain).toUpperCase();
    }

    genPeriodicalPlainPostData(model) {
        let dcg = new DataChainGenerator();

        dcg.addKeyValue("RespondType", model.RespondType);
        dcg.addKeyValue("TimeStamp", model.TimeStamp);
        dcg.addKeyValue("Version", "1.0");
        dcg.addKeyValue("MerOrderNo", model.MerOrderNo);
        dcg.addKeyValue("ProdDesc", model.ProdDesc);
        dcg.addKeyValue("PeriodAmt", model.PeriodAmt);
        dcg.addKeyValue("PeriodType", model.PeriodType);
        dcg.addKeyValue("PeriodPoint", model.PeriodPoint);
        dcg.addKeyValue("PeriodStartType", model.PeriodStartType);
        dcg.addKeyValue("PeriodTimes", model.PeriodTimes);
        dcg.addKeyValue("ReturnURL", model.ReturnURL);
        dcg.addKeyValue("PeriodMemo", model.PeriodMemo);
        dcg.addKeyValue("PayerEmail", model.PayerEmail);
        dcg.addKeyValue("EmailModify", model.EmailModify);
        dcg.addKeyValue("PaymentInfo", model.PaymentInfo);
        dcg.addKeyValue("OrderInfo", model.OrderInfo);
        dcg.addKeyValue("NotifyURL", model.NotifyURL);
        dcg.addKeyValue("BackURL", model.BackURL);

        return dcg.genDataChain();
    }

}


module.exports = ValidationHelper;
