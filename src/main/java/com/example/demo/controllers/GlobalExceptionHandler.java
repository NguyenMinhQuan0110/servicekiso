package com.example.demo.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import com.example.demo.models.ApiResult;

@ControllerAdvice
public class GlobalExceptionHandler {
	 @ExceptionHandler(MaxUploadSizeExceededException.class)
	    public ResponseEntity<ApiResult<String>> handleMaxSizeException(MaxUploadSizeExceededException exc) {
	        return ResponseEntity
	                .status(HttpStatus.PAYLOAD_TOO_LARGE) 
	                .body(new ApiResult<>(413, "File quá lớn, vui lòng upload file nhỏ hơn 4MB", null));
	    }

	    @ExceptionHandler(Exception.class)
	    public ResponseEntity<ApiResult<String>> handleOtherExceptions(Exception exc) {
	        return ResponseEntity
	                .status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(new ApiResult<>(500, "Lỗi hệ thống: " + exc.getMessage(), null));
	    }
}
