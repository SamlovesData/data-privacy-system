package com.example.dataprivacy.controller;

import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * ABOUT THE CONTROLLER: This controller handles file upload/scan functionality for
 * the Data Privacy System. It accepts files via HTTP POST requests, saves them
 * temporarily on the server, and prepares them for processing.
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
			String uploadDir = "C:/Users/Samuel Alston/Postman/files/TestTextFile.txt";
			File directory = new File(uploadDir);

			// Ensure the directory exists; create it if it does not
			if (!directory.exists()) {
				directory.mkdir();
			}

			// Create a destination file using the original filename
			File destinationFile = new File(uploadDir + file.getOriginalFilename());

			// Save the file to the destination directory
			System.out.println("Saving file to: " + destinationFile.getAbsolutePath());
			file.transferTo(destinationFile);

			// Return success response with the absolute file path
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

	// Adding File Scanning Functionality.
	// This line expects the Client to pass the name of the file to be scanned.
		public ResponseEntity<Map<String, List<String>>> scanFile(@RequestParam("fileName") String fileName) {
		

			// Directory where the file are stored
			String uploadDir = "uploads/";
			// Combines the directory path wiht the file name to locate the file
			File file = new File(uploadDir + fileName);

			// If the file does not exist the server responds with a 400 Bad Request status
			if (!file.exists()) {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST) .body(Map.of("Error", List.of("File not found: " + fileName))); //How does this ResponseEntity work and what does it mean? 
			}
			
			
			Map<String, List<String>> results = new HashMap<>();
		    results.put("SSN", new ArrayList<>());
		    results.put("Email", new ArrayList<>());
		    results.put("CreditCard", new ArrayList<>());

			try (BufferedReader reader = new BufferedReader(new FileReader(file))) {

				String line;

				// Patterns to scan for
				Pattern ssnPattern = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"); // 3 digits, followed by a dash, 2
																					// digits, a dash, and 4 digits( e.g.,
																					// 123-45-6789)
				Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"); // Matches valid
																											// email formats
																											// like
																											// test@example.com
				Pattern creditCardPattern = Pattern.compile("\\b(?:\\d{4}-){3}\\d{4}|\\d{16}\\b"); // Matches CreditCard
																									// numbers in the format
																									// ( 1111-2222-3333-4444
																									// )

				while ((line = reader.readLine()) != null) {

					// Scan each line
					// Match pattern in each line
					Matcher ssnMatcher = ssnPattern.matcher(line);
					Matcher emailMatcher = emailPattern.matcher(line);
					Matcher creditCardMatcher = creditCardPattern.matcher(line);

					while (ssnMatcher.find()) {
		                results.get("SSN").add(ssnMatcher.group());
		            }
		            while (emailMatcher.find()) {
		                results.get("Email").add(emailMatcher.group());
		            }
		            while (creditCardMatcher.find()) {
		                results.get("CreditCard").add(creditCardMatcher.group());
		            }

				}

				return ResponseEntity.ok(results);

				
			} catch (Exception e) {
				e.printStackTrace();
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
						.body(Map.of("Error", List.of("Error scanning file: " + e.getMessage())));
			}
	
	
	}
}
