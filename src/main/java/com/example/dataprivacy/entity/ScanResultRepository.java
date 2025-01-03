package com.example.dataprivacy.entity;

import java.time.LocalDateTime;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param; 

public interface ScanResultRepository  extends JpaRepository<ScanResult, Long> {

	 @Modifying
	    @Query(value = "INSERT INTO scan_results (file_name, scan_results, scanned_at) VALUES (:fileName, CAST(:scanResults AS JSONB), :scannedAt)", nativeQuery = true)
	    void saveScanResult(@Param("fileName") String fileName, @Param("scanResults") String scanResults, @Param("scannedAt") LocalDateTime scannedAt);
}
