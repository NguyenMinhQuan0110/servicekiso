package com.example.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.web.bind.annotation.RestController;

import com.example.demo.models.ApiResult;
import com.example.demo.models.KiSoModel;
import com.example.demo.services.KiSoService;

import lombok.extern.slf4j.Slf4j;
	@Slf4j
	@RestController
	@RequestMapping("/api/kiso")
	public class KiSoController {
		@Autowired
		private KiSoService kiSoService;
		
		@PostMapping
		public ApiResult<String> kiso(@RequestBody KiSoModel kiSoModel) {
		    try {
		        return kiSoService.KiSo(kiSoModel);
		    } catch (Exception e) {
		        log.error("Lỗi hệ thống: {}", e.getMessage(), e);
		        return new ApiResult<>(1, "Lỗi hệ thống: " + e.getMessage(), null);
		    }
		}
}
