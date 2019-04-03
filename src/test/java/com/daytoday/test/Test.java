package com.daytoday.test;

import com.neusoft.pspenv.utils.StringUtils;
import com.neusoft.pspenv.utils.XmlUtil;
import com.neusoft.rsa.entity.BizPrivateKey;
import com.neusoft.rsa.service.RsaService;
import com.neusoft.rsa.utils.*;
import org.apache.commons.codec.binary.Base64;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @DO:
 * @Program:pspenv
 * @Author 李君（2765395275）
 * @Create: 2019/3/6 14:35
 * --学海无涯苦作舟--
 */
public class Test {

    @org.junit.Test
    public void test() {
        HashMap<String, String> params = new HashMap<String, String>();
        Element dataOT009 = DocumentHelper.createElement("data");
        //医院医保支付虚拟收费员账户-即操作员账号
        XmlUtil.appendElement(dataOT009, "operatorid", "OT009");     //?????强哥jar里获取的????
        XmlUtil.appendElement(dataOT009, "patientname", "江悦");    //患者姓名
        XmlUtil.appendElement(dataOT009, "patientcardno", "530103197605240315");    //患者身份证
        XmlUtil.appendElement(dataOT009, "sicardno", "0000151471");    //患者医保卡号
        XmlUtil.appendElement(dataOT009, "sino", "00004128884");    //患者医保个人编号
//业务参数
        params.put("orderdata", dataOT009.asXML());
//医保个人编号，验证系统使用
        params.put("sino", "00004128884");
//业务周期号
        params.put("busicycleno", System.currentTimeMillis() + "");
        System.out.println(params.toString());

        //商户
        PublicKey merchantPublicKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\530000\\BX100301\\530000_BX100301.cer");
        PrivateKey merchantPrivateKey = CertUtil.getRSAPrivateKey("D:\\neusoft\\certs\\530000\\BX100301\\530000_BX100301.pfx", "fcih3f", "DFPnGr");
        //接入系统
        PublicKey srcSystemPubKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\SYS100322\\530000_SYS100322.cer");
        PrivateKey srcSystemPrivateKey = CertUtil.getRSAPrivateKey("D:\\neusoft\\certs\\SYS100322\\530000_SYS100322.pfx", "3AiCJS", "Pj7MDw");
        //平台
        PublicKey platformPubKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\SYS100266\\530000_SYS100266.cer");

        params.put("version", "1.0");
        params.put("merchantCode", "BX100301");
        params.put("infoSysCode", "SYS100322");
        params.put("merchantCertId", "2017062810525777421");
        params.put("infoSysCertId", "2017062913460780953");
        params.put("transtype", "OT009");
        String stringData = BaseUtil.coverMap2String(params, new ArrayList());
        String merchantSignature = SecureUtil.sign(merchantPrivateKey, stringData);
        String infoSysSignature = SecureUtil.sign(srcSystemPrivateKey, stringData);
        params.put("merchantSignature", merchantSignature);
        params.put("infoSysSignature", infoSysSignature);

        String message = "";
        Map<String, String> resultMap = new HashMap();
        Map reqMap = new HashMap();
        reqMap.put("transtype", params.get("transtype"));
        String encrpteddataStr = JsonUtils.objectToJson(params);
        if (platformPubKey == null) {
            message = "验签平台数据失败,未获取到平台公钥，请核实";
            resultMap.clear();
            resultMap.put("respcode", "10");
            resultMap.put("respmsg", message);
        } else {
            try {
                new Base64();
                String encrpteddata = Base64.encodeBase64String(RSAUtils.encryptByPublicKey(encrpteddataStr.getBytes("UTF-8"), platformPubKey));
                reqMap.put("encrpteddata", encrpteddata);
                String overtimestr = "120";
                int overtime = 120000;
                if (!BaseUtil.isEmpty(overtimestr)) {
                    overtime = Integer.parseInt(overtimestr) * 1000;
                }

                HttpClient hc = new HttpClient("http://10.176.59.19:13351/siepayForYHsb/OrderDeal.do", overtime, overtime);
                message = "开始提交医保电子支付平台!";
                int status = hc.send(reqMap, "UTF-8");
                if (200 == status) {
                    String resultString = hc.getResult();
                    //logger.info("调用医保电子支付平台结束，开始解析应答报文。");
                    if (resultString != null && !"".equals(resultString)) {
                        resultMap = HttpClient.convertResultStringToMap(resultString);
                        if (resultString.indexOf("encrypteddata") > -1) {
                            //logger.info("应答报文被加密，开始解密报文。");
                            String encrypteddata = (String) resultMap.get("encrypteddata");
                            new Base64();
                            String decrypteddata = new String(RSAUtils.decryptByPrivateKey(Base64.decodeBase64(encrypteddata), srcSystemPrivateKey), "UTF-8");
                            resultMap = BaseUtil.coverString2Map(decrypteddata);
                            //logger.info("应答报文解密完成，开始进行验签。");
                            String signStr = (String) resultMap.get("pltfrmSignature");
                            List<String> rmlist = new ArrayList();
                            rmlist.add("pltfrmSignature");
                            String srcStr = BaseUtil.coverMap2String(resultMap, rmlist);
                            boolean validResult1 = SecureUtil.validateSignBySoft(platformPubKey, signStr, srcStr);
                            if (validResult1) {
                                message = "验签平台数据成功。";
                                //logger.info(message);
                                resultMap.remove("version");
                                resultMap.remove("pltfrmCertId");
                                resultMap.remove("transtype");
                                resultMap.remove("pltfrmSignature");
                                //return resultMap;
                            } else {
                                message = "验签平台数据失败,签名验证不通过。";
                                //logger.error(message);
                                resultMap.clear();
                                resultMap.put("respcode", "10");
                                resultMap.put("respmsg", message);
                                //return resultMap;
                            }
                        } else {
                            //logger.info("应答报文未被加密，直接返回数据。");
                            resultMap.remove("transtype");
                            //return resultMap;
                        }
                    } else {
                        //return resultMap;
                    }
                } else {
                    message = "调用医保电子支付平台错误,返回" + status + ",请稍后再试！";
                    //logger.error(message);
                    resultMap.put("respcode", "10");
                    resultMap.put("respmsg", message);
                    //return resultMap;
                }
            } catch (Exception var18) {
                var18.printStackTrace();
                message = "调用医保电子支付平台时发生异常！异常原因" + var18.getMessage();
                //logger.error(message, var18);
                resultMap.put("respcode", "-1");
                resultMap.put("respmsg", message);
                //return resultMap;
            }

        }

    }

    @org.junit.Test
    public void testNewData() {
        try {
            //商户
            PublicKey merchantPublicKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\530000\\BX100301\\530000_BX100301.cer");
            PrivateKey merchantPrivateKey = CertUtil.getRSAPrivateKey("D:\\neusoft\\certs\\530000\\BX100301\\530000_BX100301.pfx", "fcih3f", "DFPnGr");
            //接入系统
            PublicKey srcSystemPubKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\SYS100322\\530000_SYS100322.cer");
            PrivateKey srcSystemPrivateKey = CertUtil.getRSAPrivateKey("D:\\neusoft\\certs\\SYS100322\\530000_SYS100322.pfx", "3AiCJS", "Pj7MDw");
            //平台
            PublicKey platformPubKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\SYS100242\\SYS100242.cer");


            HashMap<String, String> params = new HashMap<String, String>();
            Element dataOT009 = DocumentHelper.createElement("data");
            //医院医保支付虚拟收费员账户-即操作员账号
            XmlUtil.appendElement(dataOT009, "operatorid", "OT009");     //?????强哥jar里获取的????
            XmlUtil.appendElement(dataOT009, "patientname", "江悦");    //患者姓名
            XmlUtil.appendElement(dataOT009, "patientcardno", "530103197605240315");    //患者身份证
            XmlUtil.appendElement(dataOT009, "sicardno", "0000151471");    //患者医保卡号
            XmlUtil.appendElement(dataOT009, "sino", "00004128884");    //患者医保个人编号
            //业务参数
            params.put("transdata", dataOT009.asXML());
            //医保个人编号，验证系统使用
            params.put("sino", "00004128884");
            //业务周期号
            params.put("busicycleno", System.currentTimeMillis() + "");
            System.out.println(params.toString());

           /* //签到
            Element transdataElement = DocumentHelper.createElement("data");
            XmlUtil.appendElement(transdataElement, "operatorid", "admin"); //操作员账号
            HashMap<String, String> params = new HashMap<String, String>();
            System.out.println("业务数据："+transdataElement.asXML());
            params.put("transdata", transdataElement.asXML());*/
            params.put("version", "1.0");
            params.put("merchantcode", "BX100301");
            params.put("infosyscode", "SYS100322");
            params.put("merchantcertid", "2017062810525777421");
            params.put("infosyscertid", "2017062913460780953");
            params.put("transtype", "8000001");
            String stringData = BaseUtil.coverMap2String(params, new ArrayList());
            System.out.println("待签名数据：" + stringData);

            String merchantSignature = SecureUtil.sign(merchantPrivateKey, stringData);
            String infoSysSignature = SecureUtil.sign(srcSystemPrivateKey, stringData);
            params.put("merchantsignature", merchantSignature);
            params.put("infosyssignature", infoSysSignature);

            String desKey = StringUtils.getRandNum(8);
            System.out.println("对称秘钥：" + desKey);

            Map reqMap = new HashMap();
            reqMap.put("transtype", params.get("transtype"));
            String desKeyEncrpteddata = Base64.encodeBase64String(RSAUtils.encryptByPublicKey(desKey.getBytes("UTF-8"), platformPubKey));
            System.out.println("对称加密后的密文：" + desKeyEncrpteddata);
            reqMap.put("encryptkey", desKeyEncrpteddata);

            String encrpteddataStr = BaseUtil.coverMap2String(params, new ArrayList<String>());
            String encrpteddata = Base64.encodeBase64String(DesDec.desEncrypt(encrpteddataStr.getBytes("UTF-8"), desKey.getBytes("UTF-8")));
            System.out.println("对称加密后的密文：" + encrpteddata);
            reqMap.put("encrpteddata", encrpteddata);

            String overtimestr = "120";
            int overtime = 120000;
            if (!BaseUtil.isEmpty(overtimestr)) {
                overtime = Integer.parseInt(overtimestr) * 1000;
            }
            HttpClient hc = new HttpClient("http://127.0.0.1:12336/MobileOutPatient/MiepayService.do", overtime, overtime);
            //开始提交医保电子支付平台
            int status = hc.send(reqMap, "UTF-8");
            if (200 == status) {
                String resultString = hc.getResult();
                //调用医保电子支付平台结束，开始解析应答报文
                if (resultString != null && !"".equals(resultString)) {
                    Map resultMap = HttpClient.convertResultStringToMap(resultString);
                    //应答报文被加密，开始解密报文
                    String encrypteddata = (String) resultMap.get("encrpteddata");
                    byte[] dataSrc = Base64.decodeBase64(encrypteddata.getBytes());
                    String decrypteddata = new String(DesDec.desDecrypt(dataSrc, desKey.getBytes()));
                    resultMap = BaseUtil.coverString2Map(decrypteddata);
                    //应答报文解密完成，开始进行验签
                    String signStr = (String) resultMap.get("pltfrmsignature");
                    List<String> rmlist = new ArrayList();
                    rmlist.add("pltfrmsignature");
                    String srcStr = BaseUtil.coverMap2String(resultMap, rmlist);
                    //平台公钥验签
                    boolean validResult1 = SecureUtil.validateSignBySoft(platformPubKey, signStr, srcStr);
                    if (validResult1) {
                        //验签处理成功
                        resultMap.remove("version");
                        resultMap.remove("pltfrmCertId");
                        resultMap.remove("transtype");
                        resultMap.remove("pltfrmSignature");
                    } else {
                        //验证失败
                        resultMap.clear();
                        resultMap.put("respcode", "10");
                        resultMap.put("respmsg", "");
                    }

                } else {
                    System.out.println("调用成功，返回报文异常...");
                }
            } else {
                System.out.println("调医保电子支付平台异常...");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    @org.junit.Test
    public void testDoSomething() {
        try {
            //商户
            PublicKey merchantPublicKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\bst\\merchant\\530000_DD00000007.cer");
            PrivateKey merchantPrivateKey = CertUtil.getRSAPrivateKey("D:\\neusoft\\certs\\bst\\merchant\\530000_DD00000007.pfx", "s2NABe", "7cyGBi");
            //接入系统
            PublicKey srcSystemPubKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\bst\\srcsystem\\530000_SYS100401.cer");
            PrivateKey srcSystemPrivateKey = CertUtil.getRSAPrivateKey("D:\\neusoft\\certs\\bst\\srcsystem\\530000_SYS100401.pfx", "D77MtW", "dfknbS");
            //平台
            PublicKey platformPubKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\bst\\platform\\530000_SYS100266.cer");
            HashMap<String, String> params = new HashMap<String, String>();
            //签到
            Element transdataElement = DocumentHelper.createElement("data");
            XmlUtil.appendElement(transdataElement, "operatorid", "admin"); //操作员账号
            System.out.println("业务数据：" + transdataElement.asXML());

            //HashMap<String, String> params = new HashMap<String, String>();
            /*Element dataOT009 = DocumentHelper.createElement("data");
            //医院医保支付虚拟收费员账户-即操作员账号
            XmlUtil.appendElement(dataOT009, "operatorid", "OT009");     //?????强哥jar里获取的????
            XmlUtil.appendElement(dataOT009, "patientname", "江悦");    //患者姓名
            XmlUtil.appendElement(dataOT009, "patientcardno", "530103197605240315");    //患者身份证
            XmlUtil.appendElement(dataOT009, "sicardno", "0000151471");    //患者医保卡号
            XmlUtil.appendElement(dataOT009, "sino", "00004128884");    //患者医保个人编号*/
            //业务参数
            params.put("transdata", transdataElement.asXML());
            //医保个人编号，验证系统使用
            //params.put("sino", "00004128884");
            //业务周期号
            //params.put("busicycleno", System.currentTimeMillis() + "");
            System.out.println(params.toString());
            params.put("version", "1.0");
            params.put("merchantcode", "DD00000007");
            params.put("infosyscode", "SYS100401");
            params.put("merchantcertid", "2019030709254786554");
            params.put("infosyscertid", "2019030709154840326");
            params.put("transtype", "8000003");
            String stringData = BaseUtil.coverMap2String(params, new ArrayList());
            System.out.println("待签名数据：" + stringData);

            String merchantSignature = SecureUtil.sign(merchantPrivateKey, stringData);
            String infoSysSignature = SecureUtil.sign(srcSystemPrivateKey, stringData);
            params.put("merchantsignature", merchantSignature);
            params.put("infosyssignature", infoSysSignature);
            System.out.println("商户签名值：" + merchantSignature);
            System.out.println("接入系统签名值：" + infoSysSignature);

            String desKey = "IDzkclPg";
            System.out.println("对称秘钥：" + desKey);

            Map reqMap = new HashMap();
            reqMap.put("transtype", params.get("transtype"));
            String desKeyEncrpteddata = Base64.encodeBase64String(RSAUtils.encryptByPublicKey(desKey.getBytes("UTF-8"), platformPubKey));
            System.out.println("平台公钥加密对称密钥后密文base64编码：" + desKeyEncrpteddata);
            reqMap.put("encryptkey", desKeyEncrpteddata);

            String encrpteddataStr = BaseUtil.coverMap2String(params, new ArrayList<String>());
            System.out.println("需要进行对称加密的明文:" + encrpteddataStr);
            String encrpteddata = Base64.encodeBase64String(DesDec.desEncrypt(encrpteddataStr.getBytes("UTF-8"), desKey.getBytes("UTF-8")));
            System.out.println("对称加密后密文的base64编码：" + encrpteddata);
            reqMap.put("encrpteddata", encrpteddata);
            encrpteddataStr = BaseUtil.coverMap2String(reqMap, new ArrayList<String>());

            System.out.println("http:" + encrpteddataStr);

            String overtimestr = "120";
            int overtime = 120000;
            if (!BaseUtil.isEmpty(overtimestr)) {
                overtime = Integer.parseInt(overtimestr) * 1000;
            }
            HttpClient hc = new HttpClient("http://222.172.223.141:10103/miepaytrans/MiepayService.do", overtime, overtime);
            //开始提交医保电子支付平台
            int status = hc.send(reqMap, "UTF-8");
            if (200 == status) {
                String resultString = hc.getResult();
                //调用医保电子支付平台结束，开始解析应答报文
                if (resultString != null && !"".equals(resultString)) {
                    Map resultMap = HttpClient.convertResultStringToMap(resultString);
                    //应答报文被加密，开始解密报文
                    String encrypteddata = (String) resultMap.get("encrpteddata");
                    byte[] dataSrc = Base64.decodeBase64(encrypteddata.getBytes());
                    String decrypteddata = new String(DesDec.desDecrypt(dataSrc, desKey.getBytes()));
                    resultMap = BaseUtil.coverString2Map(decrypteddata);
                    //应答报文解密完成，开始进行验签
                    String signStr = (String) resultMap.get("pltfrmsignature");
                    List<String> rmlist = new ArrayList();
                    rmlist.add("pltfrmsignature");
                    String srcStr = BaseUtil.coverMap2String(resultMap, rmlist);
                    //平台公钥验签
                    boolean validResult1 = SecureUtil.validateSignBySoft(platformPubKey, signStr, srcStr);
                    if (validResult1) {
                        //验签处理成功
                        resultMap.remove("version");
                        resultMap.remove("pltfrmCertId");
                        resultMap.remove("transtype");
                        resultMap.remove("pltfrmSignature");
                    } else {
                        //验证失败
                        resultMap.clear();
                        resultMap.put("respcode", "10");
                        resultMap.put("respmsg", "");
                    }

                } else {
                    System.out.println("调用成功，返回报文异常...");
                }
            } else {
                System.out.println("调医保电子支付平台异常...");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @org.junit.Test
    public void testCallService() throws Exception {
        String str = "encrpteddata=5JvNp5V8KwvCAKEz9dOOVneYeYWKkx4iBfpLqia0Ecz2ruU0HlUL8Oumojmy0j0MFWFxlUjUbf3OGkhOa7hC5Cm0Awsc29q05YRWX6CYzVBtfPVb6By73eP2U24FcJ5qQnda+QHUYQOLdkzVx7FJ9o3gUL7FFYYLnbqXQGceAFWbDyOpYCPrslFYYRXb/stH1Mx0BXXu/lKQEpayH0J6vNmORHZpk34uazTkscY/oSMsSx5q0cFti5ZZURVjNgLbvT77+iT72oxmhziO0R6EvcmI/G50AIIexECuv0iJEAvw38w5rPgq9vF/Is6j2hi+wYLQSSpfVgkqo4yrPEcHbwAji8vkbrCHX7VQo3PtWqZ1/igEyVAWgLNvyv1NadGEcFdcYW4cTJ2JpDjaz8EbhrNvyv1NadGE8EYp/q4rZAkHBhyPs9J4pd9xsTtfTxS4hwrqkdnLaUBNT8Yab2lN9/22rUIRwHzpLyXDZrd1XHpEGB5YSGwAQ/fe8eOuA1c8ur8hH25BNbg+KeqZu09tWU3EMW57inEfRAjffp4/dqZJSFqHMtJsrk6hafZTj2I03U0lLmCNmYoF9FuTWcPgus0mxT+u5Oxl4N6l0/UHgVYTLtor8SFDkUpKDgggidCDmOFEcHVucaROWE+a9TqnjbrC6dkF4+ICom0MBxRU29rAVQ1LY0UZrhhcjT24i2aaTOlRKvBUbj9rk6Et5DFZPVx3lGHoCIZngkVeEJnCvk6o0+RLvkabkJ4TAEFHlXIiw96cFinvyg0=&encryptkey=Bj5VQCknk2zrFaLWpUcniLW7/60wXmuLYEjVkhljUsOT4tD7IL2IsijkAes/9CbqCgz64GuMRw6jFrHEl1ABNVIFMjmrzKpTQxPCVLoqVSBzrZQNQ0oose/o7TKBzzX+dnBjjoEcfosR4md79IZBVXEdo0SS4wlgDkaCRIUEY/c=&transtype=8000001";

       /* postParams.add("encrpteddata", "5JvNp5V8KwvCAKEz9dOOVneYeYWKkx4iBfpLqia0Ecz2ruU0HlUL8Oumojmy0j0MFWFxlUjUbf3OGkhOa7hC5Cm0Awsc29q05YRWX6CYzVBtfPVb6By73eP2U24FcJ5qQnda+QHUYQOLdkzVx7FJ9o3gUL7FFYYLnbqXQGceAFWbDyOpYCPrslFYYRXb/stH1Mx0BXXu/lKQEpayH0J6vNmORHZpk34uazTkscY/oSMsSx5q0cFti5ZZURVjNgLbvT77+iT72oxmhziO0R6EvcmI/G50AIIexECuv0iJEAvw38w5rPgq9vF/Is6j2hi+wYLQSSpfVgkqo4yrPEcHbwAji8vkbrCHX7VQo3PtWqZ1/igEyVAWgLNvyv1NadGEcFdcYW4cTJ2JpDjaz8EbhrNvyv1NadGE8EYp/q4rZAkHBhyPs9J4pd9xsTtfTxS4hwrqkdnLaUBNT8Yab2lN9/22rUIRwHzpLyXDZrd1XHpEGB5YSGwAQ/fe8eOuA1c8ur8hH25BNbg+KeqZu09tWU3EMW57inEfRAjffp4/dqZJSFqHMtJsrk6hafZTj2I03U0lLmCNmYoF9FuTWcPgus0mxT+u5Oxl4N6l0/UHgVYTLtor8SFDkUpKDgggidCDmOFEcHVucaROWE+a9TqnjbrC6dkF4+ICom0MBxRU29rAVQ1LY0UZrhhcjT24i2aaTOlRKvBUbj9rk6Et5DFZPVx3lGHoCIZngkVeEJnCvk6o0+RLvkabkJ4TAEFHlXIiw96cFinvyg0");
        postParams.add("encryptkey", "Bj5VQCknk2zrFaLWpUcniLW7/60wXmuLYEjVkhljUsOT4tD7IL2IsijkAes/9CbqCgz64GuMRw6jFrHEl1ABNVIFMjmrzKpTQxPCVLoqVSBzrZQNQ0oose/o7TKBzzX+dnBjjoEcfosR4md79IZBVXEdo0SS4wlgDkaCRIUEY/c=");
        postParams.add("transtype", "8000001");*/


        //String URL = "http://127.0.0.1:12336/MobileOutPatient/MiepayService.do";
        MultiValueMap<String, Object> postParams = new LinkedMultiValueMap<>();
        postParams.add("encrpteddata", "siEQsEMqsMlhKJ1mvyxnsWw1p2gQbROZcmYotkpsJ6LyjeehHkYirLQkRLvpOmDmJR91zC3ryk51pdy8jsi3LfJj8sG2lV/KdhTH0fcVlDpVLI8iLIHdmDMGsuMn7+ZxeObc+swUTbRPQgb7zyLMry+p4jcdrHlywpKFvDeHTr9fnKkxBlm/X6mslEJ4rLTbtNg08t+rajRpmnP2Nm0kxr2Sx6VpIzfr0Mnd1fabPOwfJ65gDkZU/oaIGkSgl/ZtC/OT5Eh8HXg9amhQ7W2yybAZ0ls7zBTqldoxuR3HTZ638w1Tnmk/eoyFbwOOB2QmwizFh+J+fukDmZkQZVev5CYyZ6HAeJw/Vc9I+txqzKAg5zGl/D4mItnVRC5KJq283Xbax/Rut9Jqzn3UmcJX1tnVRC5KJq28MWqvkCgrSTq82uPFM6rOed9Zg7nZdEfMTZeuDWaQ9alX8VmAqySPiIC2FryObjI1UWg5DnEdiXfuY0lNIJywH1hcchS66TT+RKAS5nEMVzCI7NkOLbnxUiLNm0eM2mGZ9P+Yfizug8hJIiIEnjHIbLGmZ1Z6oDchjCiZzU5otwhziyei6cGG9NMiZXTv6BdWIMoB23CPCA8FIz490b/sQXSs6Ywla4h/RRqsdKFnSlVW01etza6K+6q2wmKp48oazUOukd593hnRcIhw6eCAI3iZWIfUEAcv2i3zwmpxB2/1N3plmLFL3BgBJ9aTWZ75e8jFGWmuA/o9mBHwsTcUk9qE5/r0xPn6zb4x+b6XtoI=");
        postParams.add("encryptkey", "ZT4uHdhvEUteCH3jiSLwAL0geF9h/OwKR57qkrKaMoNxeIvdukkaV8p0iMrTFMlnWv7BeZWesAK1qnM/+IKvh0fS0hUOkxvvO9xnEp1LVFAymYuNkCIvvgr3ax3wriKBf/Muh4r1dTbO17zzf5SS+OmLUovd5qwhjbj26OfNWzI=");
        postParams.add("transtype", "8000001");

        String URL="http://222.172.223.141:10103/miepaytrans/MiepayService.do";
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(postParams, headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> responseEntity = restTemplate.postForEntity(URL, requestEntity, String.class);

        HttpStatus httpStatus = responseEntity.getStatusCode();
        if (200 != httpStatus.value()) {
            System.out.println("https请求状态：" + httpStatus.value());
        } else {
            System.out.println("http请求状态：" + httpStatus.value());
            String rspBody = responseEntity.getBody();
            System.out.println("响应的body:"+rspBody);
            Map resultMap = HttpClient.convertResultStringToMap(rspBody);
            //应答报文被加密，开始解密报文
            String encrypteddata = (String) resultMap.get("encrpteddata");
            byte[] dataSrc = Base64.decodeBase64(encrypteddata.getBytes());
            String decrypteddata = new String(DesDec.desDecrypt(dataSrc, "IM2Z7pVX".getBytes()));
            resultMap = BaseUtil.coverString2Map(decrypteddata);
            //应答报文解密完成，开始进行验签
            String signStr = (String) resultMap.get("pltfrmsignature");
            List<String> rmlist = new ArrayList();
            rmlist.add("pltfrmsignature");
            String srcStr = BaseUtil.coverMap2String(resultMap, rmlist);
            //平台公钥验签
            PublicKey platformPubKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\bst\\platform\\530000_SYS100266.cer");
            boolean validResult1 = SecureUtil.validateSignBySoft(platformPubKey, signStr, srcStr);
            if (validResult1) {
                System.out.println("验签处理成功");
            } else {
                System.out.println("验证失败");
            }
        }
        //httpClient
        PublicKey platformPubKey = CertUtil.getCertPublicKey("D:\\neusoft\\certs\\bst\\platform\\530000_SYS100266.cer");
        Map<String, String> map = BaseUtil.coverString2Map(str);
        String overtimestr = "120";
        int overtime = 120000;
        if (!BaseUtil.isEmpty(overtimestr)) {
            overtime = Integer.parseInt(overtimestr) * 1000;
        }
        HttpClient hc = new HttpClient(URL, overtime, overtime);
        //开始提交医保电子支付平台
        int status = 0;
        try {
            status = hc.send(map, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (200 == status) {
            String resultString = hc.getResult();
            //调用医保电子支付平台结束，开始解析应答报文
            if (resultString != null && !"".equals(resultString)) {
                Map resultMap = HttpClient.convertResultStringToMap(resultString);
                //应答报文被加密，开始解密报文
                String encrypteddata = (String) resultMap.get("encrpteddata");
                byte[] dataSrc = Base64.decodeBase64(encrypteddata.getBytes());
                String decrypteddata = new String(DesDec.desDecrypt(dataSrc, "8R68iujv".getBytes()));
                resultMap = BaseUtil.coverString2Map(decrypteddata);
                //应答报文解密完成，开始进行验签
                String signStr = (String) resultMap.get("pltfrmsignature");
                List<String> rmlist = new ArrayList();
                rmlist.add("pltfrmsignature");
                String srcStr = BaseUtil.coverMap2String(resultMap, rmlist);
                //平台公钥验签
                boolean validResult1 = SecureUtil.validateSignBySoft(platformPubKey, signStr, srcStr);
                if (validResult1) {
                    System.out.println("验签处理成功");
                } else {
                    System.out.println("验证失败");
                }

            } else {
                System.out.println("调用成功，返回报文异常...");
            }
        }
    }



}