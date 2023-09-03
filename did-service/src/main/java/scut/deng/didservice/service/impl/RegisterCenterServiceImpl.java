package scut.deng.didservice.service.impl;

import static scut.deng.didservice.pojo.constant.Constant.ISSUER_CLIENT;

import cn.hutool.core.lang.Dict;
import cn.hutool.core.util.IdUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import jakarta.annotation.Resource;
import java.time.LocalDateTime;
import java.util.HashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import scut.deng.didservice.exception.MyException;
import scut.deng.didservice.pojo.constant.Constant;
import scut.deng.didservice.pojo.constant.ErrorCode;
import scut.deng.didservice.pojo.issue.DIDInfo;
import scut.deng.didservice.pojo.response.BaseResponse;
import scut.deng.didservice.service.RegisterCenterService;

@Service
public class RegisterCenterServiceImpl implements RegisterCenterService {
  @Resource(name = "web") public Dict dict;

  @Autowired public RestTemplate restTemplate;

  /**
   * 往这个黄页上放上DID相关信息。
   *
   * 企业提供DID。
   * 注册中心用DID去公链找对应的DOC。找到了就认为DID存在。所以DID DOC必须事先放在公链上。
   * 然后注册中心为其生成递增id，以及一个UUID。并且存到其黄页数据库上。
   *
   * 注意了，API的body：DIDInfo夹带了许多字段，可以起到黄页上信息的补充作用。
   * 所以黄页上的信息不只是公链上DOC的生搬硬套。事实上这里压根不会用到从公链上拿到的entity！
   */
  @Override
  public BaseResponse registerIssuer(DIDInfo data) throws MyException {

    /*
     * 1.获得目前id数量，然后递增加1
     * 2.填入对应的信息
     * 3.
     * */
    String did = data.getDid();
    ResponseEntity<Boolean> entity = restTemplate.getForEntity(
        Constant.FABRIC_CLIENT + "getIfDocExist?did={did}", Boolean.class, did);
    if (!entity.getBody()) {
      throw new MyException(ErrorCode.NO_DIDDOC,
                            "该企业的did不存在，无法进行注册");
    }

    JSONObject didInfo = JSONUtil.parseObj(data);

    Integer issuerNum = dict.getInt("issuerNum");

    didInfo.set("id", issuerNum + 1);
    String uuid = IdUtil.simpleUUID();
    didInfo.set("uuid", uuid);

    /*
     * didInfo包含：website\endpoint\Description\serviceType
     * */

    didInfo.set("deleted", false);
    didInfo.set("createTime", LocalDateTime.now().toString());
    didInfo.set("updateTime", LocalDateTime.now().toString());
    dict.replace("issuerNum", issuerNum + 1); /* 更新issurNum计数 */

    HashMap<String, JSONObject> webServicePoint =
        (HashMap<String, JSONObject>)dict.get("webServicePoint");
    /* 往web.webServicePoint这个dict<website, didInfo>加上新的值 */
    /* 需要注意，didInfo里面包含了许多字段，包括requestData */
    webServicePoint.put(didInfo.getStr("website"), didInfo);
    dict.replace("webServicePoint", webServicePoint);

    HashMap<String, Object> params = new HashMap<>(); /* 用 `POST /add` 往ISSUER服务器（注意不是fabric那个）上发送<uuid, issuerInfo> */
    params.put("uuid", uuid);
    params.put("issuerInfo", JSONUtil.toJsonStr(didInfo));
    ResponseEntity<String> response =
        restTemplate.postForEntity(ISSUER_CLIENT + "add", params, String.class);
    if (response.getStatusCodeValue() != 200) { /* 确保返回200 */
      return BaseResponse.failure(ErrorCode.REQUEST_ERROR);
    }

    return BaseResponse.success(didInfo);
  }

  /**
   * 通过website去web数据库里找Issuer的相关信息。
   */
  @Override
  public BaseResponse getIssuerInfo(String website) {
    HashMap<String, JSONObject> webServicePoint =
        (HashMap<String, JSONObject>)dict.get("webServicePoint");
    if (!webServicePoint.containsKey(website)) {
      return BaseResponse.failure(ErrorCode.REQ_ERROR);
    }
    JSONObject jsonObject = webServicePoint.get(website); /* 把web.webServicePoint[website]对应的endpoint和requesteData字段抽出来并返回 */
    String endpoint = (String)jsonObject.get("endpoint");
    Object requestData = jsonObject.get("requestData");
    JSONObject re = new JSONObject();
    re.set("endpoint", endpoint);
    re.set("requestData", requestData);
    return BaseResponse.success(re);
  }
}
