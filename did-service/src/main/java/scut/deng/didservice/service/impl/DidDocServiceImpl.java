package scut.deng.didservice.service.impl;

import static scut.deng.didservice.pojo.constant.Constant.*;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.codec.Base32;
import cn.hutool.core.lang.Dict;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.digest.DigestUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import jakarta.annotation.Resource;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import scut.deng.didservice.exception.MyException;
import scut.deng.didservice.pojo.BaseDidDoc;
import scut.deng.didservice.pojo.DidDoc;
import scut.deng.didservice.pojo.Proof;
import scut.deng.didservice.pojo.constant.Constant;
import scut.deng.didservice.pojo.constant.EncryptType;
import scut.deng.didservice.pojo.constant.ErrorCode;
import scut.deng.didservice.pojo.response.BaseResponse;
import scut.deng.didservice.service.DidDocService;
import scut.deng.didservice.util.EncUtil;
import scut.deng.didservice.util.MerkleTreeUtil;


@Service
@Slf4j
public class DidDocServiceImpl implements DidDocService {

  @Resource(name = "DIDdict") public Dict DIDdict;
  @Resource(name = "Enterprisedict") public Dict Enterprisedict;
  @Resource(name = "VCdict") public Dict VCdict;
  @Autowired public RestTemplate restTemplate;

  /**
   * 创建DID
   */
  @Override
  public BaseResponse createDID(String type, String comment)
      throws MyException {
    /*
     * 1. 验证用户是否有资格创建
     * TODO
     * 2. 生成公私钥给用户，根据公私钥生成did标识
     * 3. 根据用户信息生成did文档，
     * 4. 返回did文档给用户
     * 5. 查询
     * */

    /*生成公私钥*/
    KeyPair pairMain = SecureUtil.generateKeyPair("RSA");
    String sk = EncUtil.keyToString(pairMain.getPrivate());
    String pk = EncUtil.keyToString(pairMain.getPublic());
    KeyPair pairRecover = SecureUtil.generateKeyPair("RSA");
    String pk_recover = EncUtil.keyToString(pairRecover.getPublic());
    String sk_recover = EncUtil.keyToString(pairRecover.getPrivate());

    /*生成did标识*/
    BaseDidDoc baseDidDoc =
        BaseDidDoc.setUpDoc(pk, pk_recover, EncryptType.RSA);
    String jsonStr = JSONUtil.toJsonStr(baseDidDoc);
    String mss = Base32.encode(
        DigestUtil.sha256(jsonStr)); /*mss是Method Specific String*/
    String did = StrUtil.join(":", Constant.SCHEME, type, mss);

    DidDoc newDID = DidDoc.createNewDID(did, baseDidDoc, sk);
    newDID.setType(type);
    newDID.setComment(comment);
    /*将私钥存储到本地*/
    storeInCache(type, sk, sk_recover, newDID.getDidID());

    /*再将did上传到区块链中*/
    Map<String, Object> params = new HashMap<>();
    params.put("did", newDID.getDidID());
    params.put("doc", JSONUtil.toJsonStr(newDID));
    ResponseEntity<String> response = restTemplate.postForEntity(
        FABRIC_CLIENT + "saveDoc", params, String.class);
    log.info("save the new didDoc, did is [{}]", newDID.getDidID());
    if (response.getStatusCodeValue() != 200) {
      log.info("save the new didDoc error, [{}]",
               response.getStatusCodeValue());
      return BaseResponse.failure(ErrorCode.REQUEST_ERROR);
    }

    return BaseResponse.success(newDID);
  }

  /**
   * 用did去找公链DID Doc
   */
  @Override
  public BaseResponse getDIDDoc(String did) {

    ResponseEntity<String> response = restTemplate.getForEntity(
        Constant.FABRIC_CLIENT + "getDoc?did={did}", String.class, did); /* 去找公链要DOC */
    if (response.getStatusCodeValue() != 200 || response.getBody() == null) {
      return BaseResponse.failure(ErrorCode.NO_DIDDOC);
    }
    JSONObject jsonObject = JSONUtil.parseObj(response.getBody(), false, true);
    return BaseResponse.success(jsonObject);
  }

  /**
   * 去找公链要所有DID Doc。应该只是用作演示作用。
   */
  @Override
  public BaseResponse getAllDoc() {
    ResponseEntity<String> response =
        restTemplate.getForEntity(FABRIC_CLIENT + "getAllDoc", String.class);
    if (response.getStatusCodeValue() != 200 || response.getBody() == "") {
      return BaseResponse.failure(ErrorCode.SYSTEM_ERROR);
    }
    JSONArray vec = JSONUtil.parseArray(response.getBody());
    JSONArray jsonArray = new JSONArray();
    vec.stream().forEach(
        e -> { jsonArray.add(JSONUtil.parseObj(e, false, true)); });
    return BaseResponse.success(jsonArray);
  }

  /**
   * 把VCdict的value转成json里的list，然后返回。
   */
  @Override
  public BaseResponse getMyVC() {
    JSONArray array = new JSONArray();
    VCdict.values().stream().forEach(e -> array.add(e));

    return BaseResponse.success(array);
  }

  /**
   * 扭曲地构造一个及其奇葩的Json对象 —— VC
   */
  @Override
  public BaseResponse applyForVP(String uuid, String[] indexVec)
      throws MyException {
    // 1.1 从VCdict里通过uuid找VC
    if (!VCdict.containsKey(uuid)) {
      return new BaseResponse(999, "无法查到该uuid对应的VC，请检查参数！");
    }

    // 1.2 再拿出uuid伴随的MERKLE，ATTRIBUTE子项, 和VC
    String VCStr = VCdict.getStr(uuid);
    String[] tree = (String[])VCdict.get(uuid + MERKLE); // merkle
    ArrayList<String> attributeList =
        (ArrayList<String>)VCdict.get(uuid + ATTRIBUTE); // attribute
    JSONObject VC = JSONUtil.parseObj(VCStr, true, true); // 主体弄出来，把revocation和proof拿掉
    VC.remove("revocation");
    VC.remove("proof");


    // 2. 把credentialSubject替换掉，为此构造newCredential
    JSONObject credentialSubject = VC.getJSONObject("credentialSubject");
    JSONObject newCredential = new JSONObject(true);

    // 2.1 新Cre里有array，需要填充一些Object进去
    JSONArray array = new JSONArray();
    newCredential.set("id", credentialSubject.getStr("id"));
    List<String> attribute = (List<String>)VCdict.get(uuid + ATTRIBUTE);
    for (String index : indexVec) {
      int i = Integer.parseInt(index) - 1;
      if (i >= attribute.size()) {
        return new BaseResponse(999, "传递认证的参数超出范围");
      }
      // 2.1.1 构造object，内含dataIndex，attribute, merklePath。并且加入array。
      JSONObject object = new JSONObject(true);
      object.set("dataIndex", Integer.parseInt(index));
      object.set(attribute.get(i), credentialSubject.getStr(attribute.get(i)));
      object.set("merklePath",
                 MerkleTreeUtil.getMerklePath(
                     attributeList.toArray(attribute.toArray(new String[0])),
                     tree, i));
      // 2.1.2 把object塞进array
      array.set(object);
    }
    // 2.2 把array塞进新Cre，把其他属性塞进新cre
    newCredential.set("properties", array);
    newCredential.set("merkleRoot", credentialSubject.getStr("merkleRoot"));
    newCredential.set("rootSignature",
                      credentialSubject.getStr("rootSignature"));
    newCredential.set("signer", credentialSubject.getStr("signer"));
    // 2.3 完成新Cre替换
    VC.replace("credentialSubject", newCredential);

    // 3. 去DIDdict里找
    /*取出用户的did用户加密*/
    /*取出学校DID的私钥用于加密*/
    if (!DIDdict.containsKey(KEY_1)) {
      throw new MyException("取出用户私钥异常，请再次确认！");
    }
    String sk = DIDdict.getStr(KEY_1);
    String did = DIDdict.getStr(DID);
    // 使用私钥将密文加密
    String docString = JSONUtil.toJsonStr(BeanUtil.beanToMap(VC));
    String encstring = EncUtil.digestMsgUseSK(docString, sk);

    // 4. 往VC里塞proof，内含type, creator, sign
    Proof proof = new Proof();
    proof.setType("rsa");
    proof.setCreator(did);
    proof.setSignatureValue(encstring);
    VC.set("proof", proof);

    VCdict.set(uuid + VP, VC); // 存储VP到内存

    return BaseResponse.success(VC);
  }

  /**
   * 将私钥存在本地，属于此类的private方法。
   */
  public void storeInCache(String type, String sk, String sk_recover,
                           String did) throws MyException {
    if (type.equals(ENTERPRISE)) {
      Enterprisedict.set(Constant.KEY_1, sk);
      Enterprisedict.set(Constant.KEY_2, sk_recover);
      Enterprisedict.set(Constant.DID, did);
    } else if (type.equals(USER)) {
      DIDdict.set(Constant.KEY_1, sk);
      DIDdict.set(Constant.KEY_2, sk_recover);
      DIDdict.set(Constant.DID, did);
    } else {
      throw new MyException("不是user用户或者enterprise用户");
    }
  }
}
