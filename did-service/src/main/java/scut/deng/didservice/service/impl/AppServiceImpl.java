package scut.deng.didservice.service.impl;

import static scut.deng.didservice.pojo.constant.Constant.*;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.lang.Dict;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import jakarta.annotation.Resource;
import java.util.ArrayList;
import java.util.HashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import scut.deng.didservice.exception.MyException;
import scut.deng.didservice.pojo.DidDoc;
import scut.deng.didservice.pojo.Proof;
import scut.deng.didservice.pojo.PublicKey;
import scut.deng.didservice.pojo.constant.Constant;
import scut.deng.didservice.pojo.constant.ErrorCode;
import scut.deng.didservice.pojo.request.VerifyVCRequest;
import scut.deng.didservice.pojo.response.BaseResponse;
import scut.deng.didservice.service.AppService;
import scut.deng.didservice.util.EncUtil;
import scut.deng.didservice.util.MerkleTreeUtil;

/**
 *
 */
@Service
public class AppServiceImpl implements AppService {

  @Autowired public RestTemplate restTemplate;

  @Resource(name = "DIDdict") public Dict DIDdict;

  @Resource(name = "Enterprisedict") public Dict Enterprisedictdict;

  @Resource(name = "VCdict") public Dict VCdict;
  @Autowired public HashMap<String, Integer> hashMap;

  /**
   * 此函数从公链拿到对应DID文档，拿出公钥，生成一个随机数，用公钥加密后，
   * 拿去challenge客户端。
   */
  @Override
  public BaseResponse loginApp(String did) throws MyException {
    /*
     * 1. 在区块链上获得did文档
     * 2.
     * 取得did公钥，并且利用did公钥加密一段随机数，然后加密一段随机数发送回给客户端
     * 3. 客户端用私钥解密后再发发回
     * */

    ResponseEntity<String> entity = restTemplate.getForEntity(
        Constant.FABRIC_CLIENT + "getDoc?did={did}", String.class, did);

    if (entity.getStatusCodeValue() != 200 || entity.getBody() == null) {
      throw new MyException(ErrorCode.NO_DIDDOC, "请求fabric端接口失败");
    }

    DidDoc diddoc = JSONUtil.toBean(entity.getBody(), DidDoc.class);

    PublicKey publicKey = diddoc.getKeyList().get(0);
    String pk = publicKey.getKeyString();
    int nonce = RandomUtil.randomInt();
    String encodeMsg = EncUtil.encoderMsgUsePK(String.valueOf(nonce), pk);
    hashMap.put(did, nonce);

    return BaseResponse.success(encodeMsg);
  }

  /**
   * 验证VC用的。
   *
   * 应该是用户可以提供一个托管在云上的公开VC，来进行验证与登录。
   *
   * 不明白这有什么用。用户直接把challenge的那个nonce返回不就行了。这个机制挺怪的。
   */
  @Override
  public BaseResponse verifyVC(VerifyVCRequest encodeMsg) throws MyException {
    Integer oriNonce = hashMap.get(encodeMsg.getDid());
    String sk = DIDdict.getStr(KEY_1);
    String nonce = EncUtil.decodeMsgUsesk(encodeMsg.getEncodeMsg(), sk); /* nonce就是上面login生成的无厘头数字 */
    if (Integer.parseInt(nonce) != oriNonce) {
      throw new MyException(ErrorCode.ENC_ERROR,
                            "与公钥加密的原始密文不相同！");
    }
    if (!VCdict.containsKey(encodeMsg.getUuid())) {
      throw new MyException(ErrorCode.REQ_ERROR, "不存在该UUID对应的VC文档");
    }
    String VCStr = VCdict.getStr(encodeMsg.getUuid());
    /* 1. 从VCdict搞到用户用uuid指定的VC */
    JSONObject VC = JSONUtil.parseObj(VCStr, true, true);


    Proof proof = JSONUtil.toBean(VC.getJSONObject("proof"), Proof.class); /* VC.proof.creator */
    DidDoc issuer_doc = getDoc(proof.getCreator());
    String issuer_pk = issuer_doc.getKeyList().get(0).getKeyString(); /* VC.proof.creator的头一个kv pair的key部分 */
    VC.remove("proof");/* VC除掉proof */
    String VCString = JSONUtil.toJsonStr(BeanUtil.beanToMap(VC));
    /* 2. 签发方公钥去解proof的签名 */
    String VCString_decode =
        EncUtil.deDigestMsgUsePK(proof.getSignatureValue(), issuer_pk);

    /* 3. 看看proof用签发方公钥解开后，是否跟VC一致 */
    if (VCString_decode.equals(VCString)) {
      return BaseResponse.success(null, "验证通过，允许登录");
    }

    return new BaseResponse(999, "验证不通过，与摘要不同");
  }

  /**
   * 补充：VP简介
   *
   * VP，其实是Verifiable Presentations (VP). 可验证表达。
   *
   * LINK：
   * https://blog.csdn.net/u012084827/article/details/127218645
   *
   * 这个链接通过具体的毕业证书去说明各种概念。
   *
   * Verifiable presentation简称VP，可验证表达是VC持有者向验证者表名自己身份的数据。
   * 一般情况下，我们直接出示VC全文即可，但是在某些情况下，出于隐私保护的需要，
   * 我们并不需要出示完整的VC内容，只希望选择性披露某些属性，或者不披露任何属性，
   * 只需要证明某个断言即可。
   */

  /**
   * 此函数验证一个VP。
   *
   * 先验证用户的登录（用那个challenge）。
   * 再验证公安部DID。
   * 然后验证什么默克尔根。
   * 还有什么纰漏字段。
   *
   * 我觉得这个应该是用人单位使用的方法。用户给出一个VP的uuid，用人单位拿着这个uuid，去VP数据托管网站上搞到VP。
   * 然后，用人单位去链上找用户、签发方的DID DOC。用户DOC用来验证交流对方是不是用户。签发方DOC用来验证这VP是真的还是假的。
   * 至于这个默克尔路径认证，就不知道是啥意思了。 （😂）
   */
  @Override
  public BaseResponse verifyVP(VerifyVCRequest encodeMsg) throws MyException { /* encodeMsg夹带着此次challenge的运算结果，还有需要验证之VP的uuid */
    Integer oriNonce = hashMap.get(encodeMsg.getDid());
    String sk = DIDdict.getStr(KEY_1);
    String nonce = EncUtil.decodeMsgUsesk(encodeMsg.getEncodeMsg(), sk);
    if (Integer.parseInt(nonce) != oriNonce) {
      throw new MyException(ErrorCode.ENC_ERROR,
                            "与公钥加密的原始密文不相同！");
    }
    if (!VCdict.containsKey(encodeMsg.getUuid())) {
      throw new MyException(ErrorCode.REQ_ERROR, "不存在该UUID对应的VC文档");
    }
    JSONObject oriVP =
        (JSONObject)VCdict.get(encodeMsg.getUuid() + Constant.VP); /* 从VCdict里找此次的VP */
    JSONObject VP = JSONUtil.parseObj(oriVP, true, true);
    /*验证VP步骤:
     * 1.验证VP用户自身的签名是有效的
     * 2.获取到公安部的DID，验证公安部的did是有效的
     * 3.验证公安部的公钥对默克尔根的签名是否正确
     * 4.对纰漏字段验证*/

    //        阶段二
    Proof proof = JSONUtil.toBean(VP.getJSONObject("proof"), Proof.class);
    DidDoc user_doc = getDoc(proof.getCreator()); /* 调用实用方法找区块链要用户的DID Doc */
    String user_pk = user_doc.getKeyList().get(0).getKeyString();
    VP.remove("proof");
    String VPString = JSONUtil.toJsonStr(BeanUtil.beanToMap(VP));
    String VPString_decode =
        EncUtil.deDigestMsgUsePK(proof.getSignatureValue(), user_pk);
    if (!VPString_decode.equals(VPString)) {
      return new BaseResponse(999, "用户公钥验证不通过！！");
    }
    //        阶段三
    JSONObject credentialSubject = VP.getJSONObject("credentialSubject");/* 我们要验证merkleRoot和rootSignature对不对得上 */
    String root = credentialSubject.getStr("merkleRoot");
    String rootSignature = credentialSubject.getStr("rootSignature");
    DidDoc issuer_doc = getDoc(credentialSubject.getStr("signer")); /* 问区块链要DID Doc。可见credentialSubject.signer就是公安部 */
    String issuer_pk = issuer_doc.getKeyList().get(0).getKeyString(); /* 所谓issuer_pk就是公安部的公钥 */
    String decodeRoot = EncUtil.deDigestMsgUsePK(rootSignature, issuer_pk);
    if (!decodeRoot.equals(root)) {
      return new BaseResponse(999, "公钥验证不通过，默克尔根遭遇篡改。");
    }
    //        阶段四
    JSONArray propertiesArray = credentialSubject.getJSONArray("properties");
    ArrayList<String> attribute =
        (ArrayList<String>)VCdict.get(encodeMsg.getUuid() + ATTRIBUTE);
    for (int i = 0; i < propertiesArray.size(); i++) {
      JSONObject property = (JSONObject)propertiesArray.get(i);
      String[] merklePath =
          property.getJSONArray("merklePath").toArray(new String[0]);
      if (!MerkleTreeUtil.verifyPath(
              root,
              property.getStr(attribute.get(property.getInt("dataIndex") - 1)),
              attribute.size(), property.getInt("dataIndex"), merklePath)) {
        return new BaseResponse(999, "默克尔路径验证不通过，属性遭遇篡改");
      }
    }
    return BaseResponse.success(null, "验证通过，允许登录");
  }

  /**
   * 私有实用方法，用来去找区块链要DID相关的Doc。
   */
  public DidDoc getDoc(String issuer_did) throws MyException {
    ResponseEntity<String> entity = restTemplate.getForEntity(
        Constant.FABRIC_CLIENT + "getDoc?did={did}", String.class, issuer_did);
    if (entity.getStatusCodeValue() != 200 || entity.getBody() == null) {
      throw new MyException(ErrorCode.NO_DIDDOC,
                            "该VC中的证明proof对应的did无效");
    }
    DidDoc issuer_doc = JSONUtil.toBean(entity.getBody(), DidDoc.class);
    return issuer_doc;
  }
}
