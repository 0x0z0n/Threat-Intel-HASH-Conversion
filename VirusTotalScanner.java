import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.json.JSONObject;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.regex.Pattern;

public class VirusTotalScanner {

    // --- CONFIGURATION ---
    private static final String API_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"; 
    private static final String OUTPUT_FILENAME = "UniversalScanOutput.xlsx";
    
    // API Endpoints
    private static final String VT_FILE_URL = "https://www.virustotal.com/vtapi/v2/file/report";
    private static final String VT_IP_URL = "https://www.virustotal.com/vtapi/v2/ip-address/report";
    private static final String VT_URL_URL = "https://www.virustotal.com/vtapi/v2/url/report";

    // Regex for Detection
    private static final Pattern IP_PATTERN = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern HASH_PATTERN = Pattern.compile("^[a-fA-F0-9]{32,64}$");

    public static void main(String[] args) {
        if (API_KEY.isEmpty()) {
            System.err.println("Error: Please paste your VirusTotal API Key in the code.");
            System.exit(1);
        }

        if (args.length < 1) {
            System.out.println("Usage: java VirusTotalScanner <input_file.xlsx>");
            System.exit(1);
        }

        String inputFile = args[0];
        System.out.println("Opening " + inputFile + "...");

        try (FileInputStream fis = new FileInputStream(inputFile);
             Workbook inputWorkbook = new XSSFWorkbook(fis);
             Workbook outputWorkbook = new XSSFWorkbook()) {

            Sheet inputSheet = inputWorkbook.getSheetAt(0);
            Sheet outputSheet = outputWorkbook.createSheet("Scan Results");

            // Write Headers
            Row headerRow = outputSheet.createRow(0);
            String[] headers = {
                "Input Data", "Type", "Company/Owner", "Detections", 
                "Total Engines", "Status", "MD5/Details", "SHA-1", "SHA-256"
            };
            
            for (int i = 0; i < headers.length; i++) {
                headerRow.createCell(i).setCellValue(headers[i]);
            }

            // --- SSL BYPASS SETUP ---
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            
            HttpClient client = HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .build();
            // ------------------------

            int rowCount = 0;
            int totalRows = inputSheet.getLastRowNum();
            int outputRowNum = 1;

            Iterator<Row> rowIterator = inputSheet.iterator();
            
            while (rowIterator.hasNext()) {
                Row currentRow = rowIterator.next();
                Cell cell = currentRow.getCell(0);
                if (cell == null) continue;
                
                String inputData = cell.toString().trim();
                if (inputData.isEmpty()) continue;

                // 1. IDENTIFY TYPE
                String type = "URL"; // Default
                String apiUrl = VT_URL_URL;
                String resourceParam = "resource"; // Usually 'resource' or 'url'

                if (IP_PATTERN.matcher(inputData).matches()) {
                    type = "IP";
                    apiUrl = VT_IP_URL;
                    resourceParam = "ip";
                } else if (HASH_PATTERN.matcher(inputData).matches()) {
                    type = "File";
                    apiUrl = VT_FILE_URL;
                    resourceParam = "resource";
                }

                // 2. BUILD REQUEST
                String requestUrl = apiUrl + "?apikey=" + API_KEY + "&" + resourceParam + "=" + inputData;
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(requestUrl))
                        .GET()
                        .build();

                try {
                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                    if (response.statusCode() == 204) {
                        System.out.println("(!) Limit Exceeded. Waiting 60s...");
                        Thread.sleep(60000); 
                        continue; 
                    }

                    JSONObject data = new JSONObject(response.body());
                    int responseCode = data.optInt("response_code", 0);
                    Row outputRow = outputSheet.createRow(outputRowNum++);

                    // Fill Input and Type
                    outputRow.createCell(0).setCellValue(inputData);
                    outputRow.createCell(1).setCellValue(type);

                    if (responseCode == 1) {
                        // --- EXTRACT DATA BASED ON TYPE ---
                        
                        String company = "-";
                        int positives = 0;
                        int total = 0;
                        String status = "Found";
                        String md5 = "-";
                        String sha1 = "-";
                        String sha256 = "-";

                        if (type.equals("IP")) {
                            // IP Reports don't have "positives" in V2, they have "as_owner" and "country"
                            company = data.optString("as_owner", "Unknown");
                            String country = data.optString("country", "Unknown");
                            status = "Located (" + country + ")";
                            
                            // Check for malicious URLs hosted on this IP (optional logic)
                            int detectedUrls = data.optJSONArray("detected_urls") != null ? data.optJSONArray("detected_urls").length() : 0;
                            positives = detectedUrls; 
                            // Note: For IP, "positives" here represents count of malicious URLs hosted there
                            
                        } else {
                            // Files and URLs
                            company = "-";
                            positives = data.optInt("positives", 0);
                            total = data.optInt("total", 0);
                            status = (positives > 0) ? "Malicious" : "Clean";
                            
                            if (type.equals("File")) {
                                md5 = data.optString("md5", "-");
                                sha1 = data.optString("sha1", "-");
                                sha256 = data.optString("sha256", "-");
                            }
                        }

                        // Write to Excel
                        outputRow.createCell(2).setCellValue(company);
                        outputRow.createCell(3).setCellValue(positives);
                        outputRow.createCell(4).setCellValue(total);
                        outputRow.createCell(5).setCellValue(status);
                        outputRow.createCell(6).setCellValue(md5);
                        outputRow.createCell(7).setCellValue(sha1);
                        outputRow.createCell(8).setCellValue(sha256);

                        System.out.printf("[%d] %s [%s]: %s%n", rowCount, type, inputData, status);

                    } else {
                        // Not Found
                        outputRow.createCell(5).setCellValue("Not Found / No Data");
                        System.out.printf("[%d] %s [%s]: Not Found%n", rowCount, type, inputData);
                    }

                } catch (Exception e) {
                    System.err.println("Error processing " + inputData + ": " + e.getMessage());
                }

                rowCount++;

                // Save periodically
                if (rowCount % 10 == 0) {
                    try (FileOutputStream fos = new FileOutputStream(OUTPUT_FILENAME)) {
                        outputWorkbook.write(fos);
                    }
                }

                // Sleep (VT Free API requires 15s between requests)
                Thread.sleep(16000); 
            }

            // Final Save
            try (FileOutputStream fos = new FileOutputStream(OUTPUT_FILENAME)) {
                outputWorkbook.write(fos);
            }
            System.out.println("\nCompleted. Data saved to " + OUTPUT_FILENAME);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}