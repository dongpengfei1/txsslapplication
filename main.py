# -*- coding: utf-8 -*-
import json,sqlite3,configparser,os,ast
from datetime import datetime
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import (
    TencentCloudSDKException,
)
from tencentcloud.ssl.v20191205 import ssl_client, models


class ssl_api:

    def __init__(self, secretID, secrtKEY):
        self.secretID = secretID
        self.secrtKEY = secrtKEY
        self.cred = credential.Credential(self.secretID, self.secrtKEY)
        self.httpProfile = HttpProfile()
        self.httpProfile.endpoint = "ssl.tencentcloudapi.com"
        self.clientProfile = ClientProfile()
        self.clientProfile.httpProfile = self.httpProfile
        self.client = ssl_client.SslClient(self.cred, "", self.clientProfile)
        self._CAstatus = {
            0: "审核中",
            1: "已通过",
            2: "审核失败",
            3: "已过期",
            4: "验证方式为 DNS_AUTO 类型的证书， 已添加DNS记录",
            5: "企业证书，待提交",
            6: "订单取消中",
            7: "已取消",
            8: "已提交资料， 待上传确认函",
            9: "证书吊销中",
            10: "已吊销",
            11: "重颁发中",
            12: "待上传吊销确认函",
            13: "免费证书待提交资料状态",
            14: "已退款",
        }

    def ssl_apply(self, DomainName, Emain):
        try:
            req = models.ApplyCertificateRequest()
            params = {
                "DvAuthMethod": "DNS_AUTO",
                "DomainName": DomainName,
                "ContactEmail": Emain,
                "DeleteDnsAutoRecord": True,
            }
            req.from_json_string(json.dumps(params))

            resp = json.loads(self.client.ApplyCertificate(req).to_json_string())
            return {
                "证书ID": resp["CertificateId"],
                "请求iD": resp["RequestId"],
            }

        except TencentCloudSDKException as err:
            return err

    def get_ssl_list(self, limit=20):
        try:
            req = models.DescribeCertificatesRequest()
            params = {"Limit": limit}
            req.from_json_string(json.dumps(params))
            resp = json.loads(self.client.DescribeCertificates(req).to_json_string())
            domaininfo = []
            for j in resp["Certificates"]:
                k = {}
                k["证书ID"] = j["CertificateId"]
                k["域名"] = j["Domain"]
                k["域名状态"] = self._CAstatus[j["Status"]]
                k["域名过期时间"] = (
                    j["CertEndTime"] if j["CertEndTime"] else "9999-12-31 23:59:59"
                )
                domaininfo.append(k)
            return {"域名列表": domaininfo, "请求ID": resp["RequestId"]}

        except TencentCloudSDKException as err:
            return err

    def dowload_ssl(self, domain, certificateId, filePath=""):
        try:
            req = models.DownloadCertificateRequest()
            params = {"CertificateId": certificateId}
            req.from_json_string(json.dumps(params))

            resp = json.loads(self.client.DownloadCertificate(req).to_json_string())
            import base64

            with open(os.path.dirname(os.path.abspath(__file__))+"\ssl.zip", "wb") as f:
                f.write(base64.b64decode(resp["Content"]))

            import zipfile

            with zipfile.ZipFile(os.path.dirname(os.path.abspath(__file__))+"\ssl.zip", "r") as zipf:
                zipf.extractall(filePath, [f"{domain}.key", f"{domain}.pem"])

            return resp["RequestId"]

        except TencentCloudSDKException as err:
            return err

    def get_ssl_info(self, creatificateId):
        try:
            req = models.DescribeCertificateDetailRequest()
            params = {"CertificateId": creatificateId}
            req.from_json_string(json.dumps(params))
            resp = json.loads(
                self.client.DescribeCertificateDetail(req).to_json_string()
            )
            return {
                "域名": resp["Domain"],
                "证书ID": resp["CertificateId"],
                "证书状态": (
                    self._CAstatus[resp["Status"]]
                    if self._CAstatus[resp["Status"]]
                    else ""
                ),
                "域名过期时间": resp["CertEndTime"],
                "请求ID": resp["RequestId"],
            }
        except TencentCloudSDKException as err:
            return err

    def del_ssl(self, certificateId):
        try:
            req = models.DeleteCertificateRequest()
            params = {"CertificateId": certificateId}
            req.from_json_string(json.dumps(params))
            resp = json.loads(self.client.DeleteCertificate(req).to_json_string())
            return {"删除结果": resp["DeleteResult"], "请求ID": resp["RequestId"]}
        except TencentCloudSDKException as err:
            return err


class ssl_db:

    def __init__(self, dbPath=os.path.dirname(os.path.abspath(__file__))+'/.ca.db'):
        self.dbPath = dbPath

    def __enter__(self):
        self.connect = sqlite3.connect(self.dbPath)
        self.cursor = self.connect.cursor()
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS "main"."ssl_list" (
              "certificateId" text NOT NULL,
              "domain" text,
              "status" text,
              "certEndTime" text,
              "dlStatus" text,
              "newCA" TEXT,
              PRIMARY KEY ("certificateId"),
              CONSTRAINT "certificateId" UNIQUE ("certificateId" ASC) ON CONFLICT IGNORE
            );
            """
        )
        return self

    def select_ssl_list(self, certificateId):
        self.cursor.row_factory = sqlite3.Row
        self.cursor.execute(
            """
            select * from ssl_list where certificateId = ?
            """,
            (certificateId,),
        )
        ssl_list = self.cursor.fetchone()
        return dict(ssl_list)

    def insert_ssl(
        self, certificateId, domain, status, certEndTime, dlStatus="", newCA=""
    ):
        self.cursor.execute(
            """
            INSERT INTO ssl_list (certificateId,domain,status,certEndTime,dlStatus,newCA)
            VALUES (?,?,?,?,?,?)
            """,
            (certificateId, domain, status, certEndTime, dlStatus, newCA),
        )
        return True

    def update_ssl(self, certificateId, status, certEndTime, dlStatus, newCA):
        self.cursor.execute(
            """
            UPDATE ssl_list SET status=?,certEndTime=?,dlStatus=?,newCA=? WHERE certificateId=?
            """,
            (status, certEndTime, dlStatus, newCA, certificateId),
        )
        return True

    def delete_ssl(self, certificateId):
        self.cursor.execute(
            """
            DELETE FROM ssl_list WHERE certificateId=?
            """,
            (certificateId,),
        )
        return True

    def __exit__(self, exc_type, exc_val, exc_tb):

        self.connect.commit()
        self.connect.close()


if __name__ == "__main__":
    import configparser
    from main import ssl_api, ssl_db
    import time

    config = configparser.ConfigParser()
    ospath = os.path.dirname(os.path.abspath(__file__))
    config.read(ospath+"/config.ini",encoding="utf-8")
    secretID = config.get("ini", "secretID")
    secrtKEY = config.get("ini", "secrtKEY")
    filePath = config.get("ini", "filePath")
    mail = config.get("ini", "mail")
    ssl_api = ssl_api(secretID, secrtKEY)
    a = ssl_api.get_ssl_list(20)
    ssl_db = ssl_db()
    for i in a["域名列表"]:

        with ssl_db as ssl_db:
            ssl_db.insert_ssl(
                i["证书ID"],
                i["域名"],
                i["域名状态"],
                i["域名过期时间"],
            )
        DomainEndTime = datetime.strptime(i["域名过期时间"], "%Y-%m-%d %H:%M:%S")
        with ssl_db as ssl_db:
            dbinfo = ssl_db.select_ssl_list(i["证书ID"])
        if (DomainEndTime - datetime.now()).days < 7:
            if not dbinfo["newCA"]:
                newdomain = ssl_api.get_ssl_info(
                    ssl_api.ssl_apply(i["域名"], mail)["证书ID"]
                )
                time.sleep(10)
                with ssl_db as ssl_db:
                    ssl_db.insert_ssl(
                        newdomain["证书ID"],
                        newdomain["域名"],
                        newdomain["证书状态"],
                        newdomain["域名过期时间"],
                    )
                with ssl_db as ssl_db:
                    ssl_db.update_ssl(
                        dbinfo["certificateId"],
                        i["域名状态"],
                        dbinfo["certEndTime"],
                        dbinfo["dlStatus"],
                        "1",
                    )
            if (DomainEndTime - datetime.now()).days < 3:
                ssl_api.del_ssl(i["证书ID"])
                with ssl_db as ssl_db:
                    ssl_db.delete_ssl(i["证书ID"])
        

        with ssl_db as ssl_db:
            ssl_db.update_ssl(
                dbinfo["certificateId"],
                i["域名状态"],
                i["域名过期时间"],
                dbinfo["dlStatus"],
                dbinfo["newCA"],
            )
        if not dbinfo["dlStatus"] and dbinfo["status"] == "已通过":
            ssl_api.dowload_ssl(dbinfo["domain"], dbinfo["certificateId"], filePath)
            with ssl_db as ssl_db:
                ssl_db.update_ssl(
                    dbinfo["certificateId"],
                    dbinfo["status"],
                    dbinfo["certEndTime"],
                    "1",
                    dbinfo["newCA"],
                )
    cmdlist = ast.literal_eval(config.get("ini", "cmd"))
    for j in cmdlist:
        os.system(j) 
