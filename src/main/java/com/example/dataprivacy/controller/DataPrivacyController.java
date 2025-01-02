package com.example.dataprivacy.controller;

import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * HOW IS THIS CONSIDERED AN API??
 * 
 * 1. It Exposes and Endpoint - the GET ("/api/welcome") is an endpoint- an
 * accesible URL that the client (Postman) can call. - This endpoint responds
 * with data, specifically the string that is assigned to it.
 * 
 * 2. It Follows API Design Principles - The @RestController annotation in
 * Spring Boot ensures the class serves HTTP-based API request. -
 * the @RequestMapping("/api") defines the base path for the API(/api). -
 * The @GetMapping("/welcome") specifies the endpoint for GET request.
 * 
 * 3. It Allows Communication - Clients can interact with this endpoint by
 * sending a request to ( Http://localhost:8080/api/welcome). - The server
 * responds, enabling communication between client and server.
 */

/**
 * ABOUT THE CONTROLLER:
 * This controller handles file upload functionality for the Data Privacy System.
 * It accepts files via HTTP POST requests, saves them temporarily on the server,
 * and prepares them for processing.
 */


@RestController
@RequestMapping("/api")
public class DataPrivacyController { // REST Controller for REST API.

	@GetMapping("/welcome")
	public String welcome() {

		return "Welcome to the Data Privacy and Security System";
	}

	
	/**
	 * Handles file uploads from clients.
	 * Accepts a single file, saves it to a temporary directory, and responds with the file's path.
	 *
	 * @param file - The file uploaded by the client (via HTTP POST).
	 * @return ResponseEntity with a success message or an error message if something fails.
	 */
	
	// Adding File Upload Functionality
	@PostMapping("/upload")
	public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) { // This line binds the uploaded
																							// file to the MultipartFile
																							// object.

		// Check and see if the uploaded file is empty
		if (file.isEmpty()) {
			// Return a bad request response if no file is uploaded
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("File is empty");
		}
		try {
			 // Define the directory where files will be temporarily saved
			String uploadDir = "uploads/";
			File directory = new File(uploadDir);
			
			// Ensure the directory exists; create it if it does not
			if (!directory.exists()) {
				directory.mkdir(); 
			}

			
			File destinationFile = new File(uploadDir + file.getOriginalFilename()); // getOriginalFilename gets the orignal filename in the clients system
			file.transferTo(destinationFile);

			return ResponseEntity.status(HttpStatus.OK)
					.body("File uploaded successfully: " + destinationFile.getAbsolutePath());

		} catch (IOException e) {

			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error uploading file");

		}
	}
}
