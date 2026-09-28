public with sharing class FlowAESDataUnmaskingAction {

    // Same 32-byte Base64 Encoded AES Key used for encryption
    private static final String DEFAULT_AES_KEY = 'YOUR_GENERATED_BASE64_KEY_HERE';

    public class UnmaskRequest {
        @InvocableVariable(required=true label='Object' description='Collection of records to unmask')
        public List<SObject> recordsToUnmask;
        
        @InvocableVariable(required=true label='Log Field' description='API Name of the field storing the audit log')
        public String encryptedLogFieldName;
        
        @InvocableVariable(required=true label='Checkbox Field' description='API Name of the checkbox status field to reset')
        public String statusCheckboxFieldName;
    }

    public class UnmaskResult {
        @InvocableVariable(label='Success Flag')
        public Boolean isSuccess;
        
        @InvocableVariable(label='Message')
        public String message;
    }

    @InvocableMethod(label='Unmask and Decrypt Record Fields' description='Reads the encrypted audit log, decrypts fields, restores original values, and clears the log.')
    public static List<UnmaskResult> processRecords(List<UnmaskRequest> requests) {
        List<UnmaskResult> results = new List<UnmaskResult>();
        Blob keyBlob = EncodingUtil.base64Decode(DEFAULT_AES_KEY);

        for (UnmaskRequest req : requests) {
            UnmaskResult res = new UnmaskResult();
            try {
                if (req.recordsToUnmask == null || req.recordsToUnmask.isEmpty()) {
                    res.isSuccess = false;
                    res.message = 'No records provided in the collection.';
                    results.add(res);
                    continue;
                }

                Id firstId = req.recordsToUnmask[0].Id;
                Schema.SObjectType sObjectType = firstId.getSObjectType();
                String objectName = sObjectType.getDescribe().getName();
                Map<String, Schema.SObjectField> fieldMap = sObjectType.getDescribe().fields.getMap();

                Set<Id> recordIds = new Set<Id>();
                for (SObject sObj : req.recordsToUnmask) {
                    recordIds.add(sObj.Id);
                }

                String encField = req.encryptedLogFieldName.trim();
                String statusField = req.statusCheckboxFieldName.trim();

                // Query live records including the log field
                String soql = 'SELECT Id, ' + encField + ' FROM ' + objectName + ' WHERE Id IN :recordIds';
                List<SObject> queriedRecords = Database.query(soql);
                
                // Collect all unique fields we need to query and update
                Set<String> allParsedFields = new Set<String>();
                Map<Id, Map<String, String>> recordToValMap = new Map<Id, Map<String, String>>();

                for (SObject record : queriedRecords) {
                    String logContent = (String) record.get(encField);
                    if (String.isBlank(logContent)) continue;

                    Map<String, String> decryptedFieldValues = new Map<String, String>();
                    
                    // Parse multiline format: FieldName: EncryptedBase64String
                    List<String> lines = logContent.split('\n');
                    for (String line : lines) {
                        List<String> parts = line.split(': ');
                        if (parts.size() == 2) {
                            String fName = parts[0].trim();
                            String b64Cipher = parts[1].trim();

                            try {
                                Blob encryptedBlob = EncodingUtil.base64Decode(b64Cipher);
                                Blob decryptedBlob = Crypto.decryptWithManagedIV('AES256', keyBlob, encryptedBlob);
                                String originalVal = decryptedBlob.toString();

                                decryptedFieldValues.put(fName, originalVal);
                                allParsedFields.add(fName);
                            } catch (Exception decryptEx) {
                                // Skip line if decryption fails
                            }
                        }
                    }
                    recordToValMap.put(record.Id, decryptedFieldValues);
                }

                if (allParsedFields.isEmpty()) {
                    res.isSuccess = false;
                    res.message = 'No valid encrypted logs found to decrypt.';
                    results.add(res);
                    continue;
                }

                // Query the actual target fields that were found in the logs
                allParsedFields.add(encField);
                allParsedFields.add(statusField);
                String fullSoql = 'SELECT Id, ' + String.join(new List<String>(allParsedFields), ', ') + 
                                  ' FROM ' + objectName + ' WHERE Id IN :recordIds';
                
                List<SObject> fullRecords = Database.query(fullSoql);
                List<SObject> recordsToUpdate = new List<SObject>();

                for (SObject record : fullRecords) {
                    Id recId = record.Id;
                    if (!recordToValMap.containsKey(recId)) continue;

                    Map<String, String> fieldVals = recordToValMap.get(recId);
                    for (String fName : fieldVals.keySet()) {
                        if (fieldMap.containsKey(fName.toLowerCase())) {
                            record.put(fName, fieldVals.get(fName));
                        }
                    }

                    // Clear the log and reset status checkbox
                    record.put(encField, null);
                    record.put(statusField, false);

                    recordsToUpdate.add(record);
                }

                if (!recordsToUpdate.isEmpty()) {
                    update recordsToUpdate;
                }

                res.isSuccess = true;
                res.message = 'SUCCESS: Unmasked ' + recordsToUpdate.size() + ' records.';

            } catch (Exception e) {
                res.isSuccess = false;
                res.message = 'ERROR: ' + e.getMessage();
            }
            results.add(res);
        }

        return results;
    }
}