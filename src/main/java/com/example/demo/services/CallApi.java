package com.example.demo.services;

import java.io.ByteArrayInputStream;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import com.example.demo.models.ApiResult;

import lombok.extern.slf4j.Slf4j;
@Slf4j
@Component
public class CallApi {
	public static final String KEY_STORE_TYPE = "PKCS12";
    public static final String TLS_VERSION = "TLSv1.2";

    private final String keyStoreBase64;
    private final String passwordKeyStore;
    private final String userAgent;
    private final String ip;
    private final String ip53;
    private final int port;
    private SSLContext sslContext;
    
    public CallApi(@Value("${api.keystore-base64}") String keyStoreBase64,
                   @Value("${api.keystore-password}") String passwordKeyStore,
                   @Value("${api.user-agent}") String userAgent,
                   @Value("${api.ip}")String ip,
                   @Value("${api.ip53}")String ip53,
                   @Value("${api.port}")int port) {
        this.keyStoreBase64 = keyStoreBase64;
        this.passwordKeyStore = passwordKeyStore;
        this.userAgent= userAgent;
        this.ip=ip;
        this.ip53=ip53;
        this.port=port;
    }

    private SSLContext getSSLContext(String ipServer, int port) throws Exception {
        if (sslContext != null) {
            return sslContext;
        }

        KeyStore keystore = KeyStore.getInstance(KEY_STORE_TYPE);
        byte[] keystoreBytes = Base64.getDecoder().decode(keyStoreBase64);
        keystore.load(new ByteArrayInputStream(keystoreBytes), passwordKeyStore.toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm(), "SunJSSE");
        keyManagerFactory.init(keystore, passwordKeyStore.toCharArray());

        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };

        SSLContext context = SSLContext.getInstance(TLS_VERSION);
        context.init(keyManagerFactory.getKeyManagers(), trustAllCerts, new SecureRandom());


        SSLSocketFactory sslSocketFactory = context.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(ipServer, port);
        sslSocket.startHandshake();

        SSLContext.setDefault(context);
        sslContext = context;
        return sslContext;
    }

    private CloseableHttpClient getHttpClient(String ipServer, int port) throws Exception {
        SSLContext sslContext = getSSLContext(ipServer, port);
        HostnameVerifier hostnameVerifier = (s, sslSession) -> true; // Bỏ qua xác thực hostname
        return HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLHostnameVerifier(hostnameVerifier)
                .build();
    }

    private JSONObject convertDataResponse(CloseableHttpResponse httpResponse) throws IOException {
        HttpEntity responseEntity = httpResponse.getEntity();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        responseEntity.writeTo(baos);
        String result = new String(baos.toByteArray());
        return new JSONObject(result);
    }

    public ApiResult<String> callApiGetToken(String username, String password, String deviceInfo) {


        JSONObject object = new JSONObject();
        object.put("rememberMe", true);
        object.put("auth_type", "SAP");
        object.put("device_id", deviceInfo);

        String userPass = username + ":" + password;
        String userPassEncoded = Base64.getEncoder().encodeToString(userPass.getBytes());

        try (CloseableHttpClient httpClient = getHttpClient(ip, port)) {
        	String url ="https://"+ ip + ":" + port + "/idp/users/auth/login";
        	log.info("Đã gọi api:"+url);
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Accept", "*/*");
            httpPost.setHeader("Content-encoding", "UTF-8");
            httpPost.setHeader("User-Agent", userAgent);
            httpPost.setHeader("Authorization", "Basic " + userPassEncoded);

            StringEntity entity = new StringEntity(object.toString(), "UTF-8");
            httpPost.setEntity(entity);

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                JSONObject jsonResult = convertDataResponse(response);
                int status = jsonResult.getInt("status_code");
                if (status == 0) {
                	return new ApiResult<>(status, "Lấy token thành công", jsonResult.getString("access_token"));
                } else {
                    System.err.println("Login failed: " + jsonResult.toString());
                    log.error("Login failed:{} ", jsonResult.toString());
                    return new ApiResult<>(status, "Lấy token thất bại", null);
                }
            }
        } catch (Exception e) {
        	log.error("Lỗi hệ thống:"+e.getMessage());
            return null;
        }
    }
    public String callApiGetCer(String token, String credentialID) {

        try (CloseableHttpClient httpClient = getHttpClient(ip, port)) {
        	String url ="https://" + ip + ":" + port + "/idp/certificates/list/" + credentialID;
        	log.warn("Đã gọi api:"+url);
            HttpGet httpGet = new HttpGet(url);
            httpGet.setHeader("Accept", "*/*");
            httpGet.setHeader("Content-encoding", "UTF-8");
            httpGet.setHeader("User-Agent", userAgent);
            httpGet.setHeader("Authorization", "Bearer " + token);

            try (CloseableHttpResponse httpResponse = httpClient.execute(httpGet)) {
                JSONObject jsonResult = convertDataResponse(httpResponse);
                int status = jsonResult.getInt("status_code");
                if (status == 0) {
                    JSONArray jsonArray = jsonResult.getJSONArray("Certificate");
                    JSONObject certObject = jsonArray.getJSONObject(0);
                    return certObject.getString("Certificate");
                } else {
                    System.err.println("Get certificate failed: " + jsonResult.toString());
                    log.error("Get certificate failed:{} ", jsonResult.toString());
                    return null;
                }
            }
        } catch (Exception e) {
        	log.error("Lỗi hệ thống:"+e.getMessage());
            return null;
        }
    }
    public String generateBase64Sha256(MultipartFile file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = file.getInputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        byte[] hashBytes = digest.digest();
        return Base64.getEncoder().encodeToString(hashBytes);
    }
    //dành cho file path
    public String generateBase64Sha256(String filePath) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = new FileInputStream(filePath)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        byte[] hashBytes = digest.digest();
        return Base64.getEncoder().encodeToString(hashBytes);
    }
    
    public ApiResult<Map<String, String>> getChallenge(List<String> hashes, String credentialID, String token) {


        try (CloseableHttpClient httpClient = getHttpClient(ip, port)) {

            log.info("Input - Hashes: {}, CredentialID: {}, Token: {}", hashes, credentialID, token);

            JSONObject object = new JSONObject();
            object.put("credentialID", credentialID);
            object.put("numSignatures", 1);
            object.put("hash", hashes);
            String url = "https://" + ip + ":" + port + "/idp/users/credentials/getSAD";
            log.info("Gọi api: {}", url);
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-encoding", "UTF-8");
            httpPost.setHeader("User-Agent", userAgent);
            httpPost.setHeader("Accept", "*/*");
            httpPost.setHeader("Authorization", "Bearer " + token);
            httpPost.setEntity(new StringEntity(object.toString(), "UTF-8"));

            try (CloseableHttpResponse httpResponse = httpClient.execute(httpPost)) {
                JSONObject jsonResult = convertDataResponse(httpResponse);
                log.info("Response từ getSAD: {}", jsonResult.toString());
                if (jsonResult.getInt("status_code") == 0) {


                    JSONObject notifyObj = new JSONObject();
                    notifyObj.put("flag", 1);
                    String url1 = "https://" + ip + ":" + port + "/idp/users/list/notify";
                    log.info("Gọi api: {}", url1);
                    HttpPost notifyPost = new HttpPost(url1);
                    notifyPost.setHeader("Content-encoding", "UTF-8");
                    notifyPost.setHeader("User-Agent", userAgent);
                    notifyPost.setHeader("Accept", "*/*");
                    notifyPost.setHeader("Authorization", "Bearer " + token);
                    notifyPost.setEntity(new StringEntity(notifyObj.toString(), "UTF-8"));

                    try (CloseableHttpClient httpClient2 = getHttpClient(ip, port);
                         CloseableHttpResponse notifyResponse = httpClient2.execute(notifyPost)) {
                        JSONObject notifyJson = convertDataResponse(notifyResponse);
                        log.info("Response từ notify: {}", notifyJson.toString());
                        if (notifyJson.getInt("status_code") == 0) {
                            JSONArray resultArr = notifyJson.getJSONArray("result");
                            JSONObject firstItem = resultArr.getJSONObject(0);
                            log.info("First item in result array: {}", firstItem.toString());
                            
                            Map<String, String> result = new HashMap<>();
                            String challenge = firstItem.optString("challenge");
                            String requestId = firstItem.optString("requestId");
                            String requestIdAlt = firstItem.optString("request_id");
                            
                            result.put("challenge", challenge);
                            result.put("requestId", requestId.isEmpty() ? requestIdAlt : requestId);
                            
                            if (challenge.isEmpty() || result.get("requestId").isEmpty()) {
                                log.error("Challenge hoặc requestId rỗng: {}", firstItem.toString());
                                return new ApiResult<>(500, "Challenge hoặc requestId không hợp lệ", null);
                            }
                            
                            return new ApiResult<>(notifyJson.getInt("status_code"), "Lấy challenge thành công", result);
                        } else {
                            log.error("Notify failed: {}", notifyJson.toString());
                            return new ApiResult<>(notifyJson.getInt("status_code"), "Lấy challenge thất bại", null);
                        }
                    }
                } else {
                    log.error("getChallenge failed: {}", jsonResult.toString());
                    return new ApiResult<>(jsonResult.getInt("status_code"), "Lấy challenge thất bại", null);
                }
            }
        } catch (Exception e) {
            log.error("Lỗi hệ thống: {}", e.getMessage(), e);
            return new ApiResult<>(500, "Lỗi hệ thống", null);
        }
    }
    
    
    public ApiResult<String> commitChallenge(String requestAuth, String challenge, String token) {

        JSONObject object = new JSONObject();
        object.put("request_auth", requestAuth);
        object.put("challenge_response", challenge);
        object.put("comfirm", true);
        object.put("keyPass", "123456a@A");

        try (CloseableHttpClient httpClient = getHttpClient(ip, port)) {
        	String url="https://" + ip + ":" + port + "/idp/challenges/commit";
            log.info("Gọi api: "+url);
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-encoding", "UTF-8");
            httpPost.setHeader("User-Agent", userAgent);
            httpPost.setHeader("Accept", "*/*");
            httpPost.setHeader("Authorization", "Bearer " + token);

            StringEntity entity = new StringEntity(object.toString(), "UTF-8");
            httpPost.setEntity(entity);

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                JSONObject jsonResult = convertDataResponse(response);
                int status = jsonResult.getInt("status_code");
                if (status == 0) {
                    return new ApiResult<>(status, "Xác thực challenge thành công", jsonResult.getString("SAD"));
                } else {
                    System.err.println("Commit failed: " + jsonResult.toString());
                    log.error("Commit failed:{} ", jsonResult.toString());
                    return new ApiResult<>(status, "Xác thực challenge thất bại", null);
                }
            }
        } catch (Exception e) {
        	log.error("Lỗi hệ thống:"+e.getMessage());
            return null;
        }
    }
    
    public ApiResult<byte[]> callApiSignHash(List<String> dataHash, String token, String sad, String credentialID) {


        JSONObject object = new JSONObject();
        object.put("credentialID", credentialID);
        object.put("signAlgo", "1.2.840.113549.1.1.1"); // RSA
        object.put("hashAlgo", "2.16.840.1.101.3.4.2.1"); // SHA-256
        object.put("hash", dataHash);
        object.put("SAD", sad);

        try (CloseableHttpClient httpClient = getHttpClient(ip, port)) {
        	String url="https://" + ip53 + ":" + port + "/sca/signatures/signHash";
            log.info("Gọi api: "+url);
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Accept", "*/*");
            httpPost.setHeader("Content-encoding", "UTF-8");
            httpPost.setHeader("User-Agent", userAgent);
            httpPost.setHeader("Authorization", "Bearer " + token);

            StringEntity entity = new StringEntity(object.toString(), "UTF-8");
            httpPost.setEntity(entity);

            try (CloseableHttpResponse httpResponse = httpClient.execute(httpPost)) {
                JSONObject jsonResult = convertDataResponse(httpResponse);
                int status = jsonResult.getInt("status_code");
                if (status == 0) {
                    JSONArray jsonArray = jsonResult.getJSONArray("signatures");
                    String signatureBase64 = jsonArray.getString(0);
                    byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
                    return new ApiResult<>(status, "Ký hash thành công", signatureBytes);
                } else {
                    System.err.println("Sign hash failed: " + jsonResult);
                    log.error("Sign hash failed:{}", jsonResult);
                    return new ApiResult<>(status, "Ký hash thất bại", null);
                }
            }
        } catch (Exception e) {
        	log.error("Lỗi hệ thống:"+e.getMessage());
            return null;
        }
    }
}
