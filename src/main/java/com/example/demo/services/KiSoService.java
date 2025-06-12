package com.example.demo.services;

import java.util.List;
import java.util.Map;
import java.util.Scanner;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import com.example.demo.models.ApiResult;
import com.example.demo.models.KiSoModel;


import lombok.extern.slf4j.Slf4j;
@Slf4j
@Service
public class KiSoService {
	@Autowired
	private CallApi callApi;
	
	public ApiResult<String> KiSo(@RequestBody KiSoModel kiSoModel) {
        try {
            log.info("Bắt đầu ký số cho user: {}", kiSoModel.getUsername());

            ApiResult<String> tokenResult = callApi.callApiGetToken(kiSoModel.getUsername(), kiSoModel.getPassword(), kiSoModel.getDeviceID());
            if (tokenResult == null || tokenResult.getStatusCode() != 0) {
                return new ApiResult<>(tokenResult.getStatusCode(), "Không lấy được token", null);
            }
            String token = tokenResult.getData();

            String fileHash = callApi.generateBase64Sha256(kiSoModel.getFile());

            ApiResult<Map<String, String>> challengeResult = callApi.getChallenge(List.of(fileHash), kiSoModel.getCredentialID(), token);
            if (challengeResult == null || challengeResult.getStatusCode() != 0) {
                return new ApiResult<>(challengeResult.getStatusCode(), "Không lấy được challenge", null);
            }
            Map<String, String> challengeData = challengeResult.getData();
            String challenge = challengeData.get("challenge");
            String requestId = challengeData.get("requestId");

            log.info("Giá trị challenge: {}", challenge);
            System.out.println("Challenge từ hệ thống: " + challenge);
            System.out.print("Nhập challenge sau khi được giải mã: ");
            Scanner scanner = new Scanner(System.in);
            String challengeResponse = scanner.nextLine();

            ApiResult<String> sadResult = callApi.commitChallenge(requestId, challengeResponse, token);
            if (sadResult == null || sadResult.getStatusCode() != 0) {
                return new ApiResult<>(sadResult.getStatusCode(), "Commit challenge thất bại", null);
            }
            String sad = sadResult.getData();

            ApiResult<byte[]> signResult = callApi.callApiSignHash(
                    List.of(fileHash), token, sad, kiSoModel.getCredentialID());
            if (signResult == null || signResult.getStatusCode() != 0) {
                return new ApiResult<>(signResult.getStatusCode(), "Ký số thất bại", null);
            }
            log.info("Kí số thành công");

            // Trả kết quả dạng base64 chữ ký
            String signatureBase64 = java.util.Base64.getEncoder().encodeToString(signResult.getData());
            return new ApiResult<>(0, "Ký số thành công", signatureBase64);

        } catch (Exception e) {
            log.error("Lỗi hệ thống trong quá trình ký số: {}", e.getMessage(), e);
            return new ApiResult<>(500, "Lỗi hệ thống: " + e.getMessage(), null);
        }
    }

}
