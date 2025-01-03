package com.example.dataprivacy.controller;

import org.springframework.web.multipart.MultipartFile;

import com.example.dataprivacy.entity.ScanResult;
import com.example.dataprivacy.entity.ScanResultRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.transaction.Transactional;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
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
 * ABOUT THE CONTROLLER: This controller handles file upload/scan functionality
 * for the Data Privacy System. It accepts files via HTTP POST requests, saves
 * them temporarily on the server, and prepares them for processing.
 */

@RestController
@RequestMapping("/api")
public class DataPrivacyController { // REST Controller for REST API.

	@GetMapping("/welcome")
	public String welcome() {

		return "Welcome to the Data Privacy and Security System";
	}

	/**
	 * Handles file uploads from clients. Accepts a single file, saves it to a
	 * temporary directory, and responds with the file's path.
	 *
	 * @param file - The file uploaded by the client (via HTTP POST).
	 * @return ResponseEntity with a success message or an error message if
	 *         something fails.
	 */

	// Adding File Upload Functionality
	@PostMapping("/upload")
	public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {

		// Check and see if the uploaded file is empty
		if (file.isEmpty()) {
			// Return a bad request response if no file is uploaded
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("File is empty");
		}
		try {
			// Define the directory where files will be temporarily saved
			String uploadDir = System.getProperty("user.dir") + "/uploads/";
			File directory = new File(uploadDir);

			// Ensure the directory exists; create it if it does not
			if (!directory.exists()) {
				directory.mkdir();
			}

			// Create a destination file using the original filename
			File destinationFile = new File(uploadDir + file.getOriginalFilename());

			// Save the file to the destination directory
			file.transferTo(destinationFile);

			// Return success response with the absolute file path
			System.out.println("Saving file to: " + destinationFile.getAbsolutePath());
			return ResponseEntity.status(HttpStatus.OK)
					.body("File uploaded successfully: " + destinationFile.getAbsolutePath());

		} catch (IOException e) {

			// Log the error for debugging purposes
			e.printStackTrace();

			// Return an internal server error response if an exception occurs
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error uploading file");

		}
	}

	/**
	 * Handles the file Scanning from client uploaded documents Reads the accepted
	 * file, and then scans the file contents for sensitive data. It then presents a
	 * message saying if it found any or not.
	 * 
	 * 
	 * @param file
	 * @return ResponseEntity with a message idf it was succesful or not.
	 * 
	 * 
	 *         NOTES ON HOW THE CODE FUNCTIONS
	 * 
	 *         This is how the scanner knows what it is looking for.
	 * 
	 *         Pattern.compile(); - Creates a regex pattern that can be used to find
	 *         matches in text
	 * 
	 *         Pattern.matcher(line); - Creates a matcher object to find matches for
	 *         the pattern in the current line.
	 * 
	 * 
	 */

	@Autowired
    private ScanResultRepository scanResultRepository;

	@Transactional
	@PostMapping("/scan")
	public ResponseEntity<Map<String, Object>> scanFile(@RequestParam("file") MultipartFile file) {
	    try {
	        // Step 1: Save the uploaded file temporarily
	        String uploadDir = System.getProperty("user.dir") + "/uploads/";
	        File uploadDirFile = new File(uploadDir);
	        if (!uploadDirFile.exists()) {
	            uploadDirFile.mkdirs(); // Ensure the directory exists
	        }

	        File uploadedFile = new File(uploadDir + file.getOriginalFilename());
	        file.transferTo(uploadedFile);

	        // Step 2: Perform scanning logic
	        Pattern ssnPattern = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"); // SSN pattern
	        Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"); // Email pattern
	        Pattern creditCardPattern = Pattern.compile("\\b(?:\\d{4}-){3}\\d{4}\\b"); // Credit card pattern

	        Map<String, List<String>> classifiedData = new HashMap<>();
	        classifiedData.put("SSNs", new ArrayList<>());
	        classifiedData.put("Emails", new ArrayList<>());
	        classifiedData.put("CreditCards", new ArrayList<>());

	        try (BufferedReader reader = new BufferedReader(new FileReader(uploadedFile))) {
	            String line;
	            while ((line = reader.readLine()) != null) {
	                // Match SSNs
	                Matcher ssnMatcher = ssnPattern.matcher(line);
	                while (ssnMatcher.find()) {
	                    classifiedData.get("SSNs").add(ssnMatcher.group());
	                }

	                // Match Emails
	                Matcher emailMatcher = emailPattern.matcher(line);
	                while (emailMatcher.find()) {
	                    classifiedData.get("Emails").add(emailMatcher.group());
	                }

	                // Match Credit Cards
	                Matcher creditCardMatcher = creditCardPattern.matcher(line);
	                while (creditCardMatcher.find()) {
	                    classifiedData.get("CreditCards").add(creditCardMatcher.group());
	                }
	            }
	        }

	        // Step 3: Convert results to JSON
	        ObjectMapper mapper = new ObjectMapper();
	        String jsonResults = mapper.writeValueAsString(classifiedData);

	        // Step 4: Save the scan results to the database
	        scanResultRepository.saveScanResult(file.getOriginalFilename(), jsonResults, LocalDateTime.now());

	        // Step 5: Prepare response
	        Map<String, Object> response = new HashMap<>();
	        response.put("fileName", file.getOriginalFilename());
	        response.put("scanResults", classifiedData);
	        response.put("scannedAt", LocalDateTime.now());

	        return ResponseEntity.ok(response);

	    } catch (Exception e) {
	        e.printStackTrace();
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(Map.of("Error", "File upload or processing failed: " + e.getMessage()));
	    }
	}
}