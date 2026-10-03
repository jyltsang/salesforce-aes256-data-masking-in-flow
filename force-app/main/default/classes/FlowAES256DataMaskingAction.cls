public with sharing class FlowAES256DataMaskingAction {

    public class MaskRequest {
        @InvocableVariable(required=true label='Object' description='Collection of records to mask')
        public List<SObject> recordsToMask;
        
        @InvocableVariable(required=true label='Fields Name' description='Collection of field API names to encrypt and mask')
        public List<String> fieldNamesCollection;
        
        @InvocableVariable(required=true label='Log Field' description='API Name of the field to store the audit log')
        public String encryptedLogFieldName;
        
        @InvocableVariable(required=true label='Checkbox Field' description='API Name of the checkbox status field')
        public String statusCheckboxFieldName;
    }

    public class MaskResult {
        @InvocableVariable(label='Success Flag')
        public Boolean isSuccess;
        
        @InvocableVariable(label='Message')
        public String message;
    }

    @InvocableMethod(label='AES256 Encrypt and Mask Record Fields' description='Encrypts field values into a log using Custom Metadata AES key, then wipes target fields on a collection of records.')
    public static List<MaskResult> processRecords(List<MaskRequest> requests) {
        List<MaskResult> results = new List<MaskResult>();

        // Retrieve AES key dynamically from Custom Metadata Type
        Symmetric_Key_Config__mdt config = Symmetric_Key_Config__mdt.getInstance('Default_Key');
        if (config == null || String.isBlank(config.AES_Key__c)) {
            for (MaskRequest req : requests) {
                MaskResult err = new MaskResult();
                err.isSuccess = false;
                err.message = 'ERROR: Symmetric Key Custom Metadata record (Default_Key) missing or blank.';
                results.add(err);
            }
            return results;
        }

        Blob keyBlob = EncodingUtil.base64Decode(config.AES_Key__c.trim());

        for (MaskRequest req : requests) {
            MaskResult res = new MaskResult();
            try {
                if (req.recordsToMask == null || req.recordsToMask.isEmpty()) {
                    res.isSuccess = false;
                    res.message = 'No records provided in the collection.';
                    results.add(res);
                    continue;
                }

                Id firstId = req.recordsToMask[0].Id;
                Schema.SObjectType sObjectType = firstId.getSObjectType();
                String objectName = sObjectType.getDescribe().getName();
                Map<String, Schema.SObjectField> fieldMap = sObjectType.getDescribe().fields.getMap();

                // Resolve compound fields from collection
                List<String> targetFields = resolveFieldNames(req.fieldNamesCollection);

                Set<Id> recordIds = new Set<Id>();
                for (SObject sObj : req.recordsToMask) {
                    recordIds.add(sObj.Id);
                }

                Set<String> queryFields = new Set<String>(targetFields);
                queryFields.add('Id');
                
                String encField = req.encryptedLogFieldName.trim();
                String statusField = req.statusCheckboxFieldName.trim();
                
                String soql = 'SELECT ' + String.join(new List<String>(queryFields), ', ') + 
                              ' FROM ' + objectName + ' WHERE Id IN :recordIds';
                
                List<SObject> queriedRecords = Database.query(soql);
                List<SObject> recordsToUpdate = new List<SObject>();

                for (SObject record : queriedRecords) {
                    List<String> logLines = new List<String>();

                    for (String fieldName : targetFields) {
                        String cleanName = fieldName.trim();
                        if (!fieldMap.containsKey(cleanName.toLowerCase())) continue;

                        Schema.DescribeFieldResult fieldDescribe = fieldMap.get(cleanName.toLowerCase()).getDescribe();
                        if (!fieldDescribe.isUpdateable()) continue;

                        Object rawVal = record.get(cleanName);
                        
                        if (rawVal != null) {
                            Blob cipherText = Crypto.encryptWithManagedIV('AES256', keyBlob, Blob.valueOf(String.valueOf(rawVal)));
                            String base64Encrypted = EncodingUtil.base64Encode(cipherText);
                            logLines.add(cleanName + ': ' + base64Encrypted);
                        }

                        if (!fieldDescribe.isNillable() && !fieldDescribe.isDefaultedOnCreate()) {
                            record.put(cleanName, '*****');
                        } else {
                            record.put(cleanName, null);
                        }
                    }

                    record.put(encField, String.join(logLines, '\n'));
                    record.put(statusField, true);
                    
                    recordsToUpdate.add(record);
                }

                if (!recordsToUpdate.isEmpty()) {
                    update recordsToUpdate;
                }

                res.isSuccess = true;
                res.message = 'SUCCESS: Processed ' + recordsToUpdate.size() + ' records.';

            } catch (Exception e) {
                res.isSuccess = false;
                res.message = 'ERROR: ' + e.getMessage();
            }
            results.add(res);
        }

        return results;
    }

    private static List<String> resolveFieldNames(List<String> fieldNames) {
        List<String> resolved = new List<String>();
        if (fieldNames == null) return resolved;

        for (String f : fieldNames) {
            if (String.isBlank(f)) continue;
            String lower = f.trim().toLowerCase();

            if (lower == 'mailingaddress') {
                resolved.addAll(new List<String>{'MailingStreet', 'MailingCity', 'MailingState', 'MailingPostalCode', 'MailingCountry'});
            } else if (lower == 'billingaddress') {
                resolved.addAll(new List<String>{'BillingStreet', 'BillingCity', 'BillingState', 'BillingPostalCode', 'BillingCountry'});
            } else if (lower == 'shippingaddress') {
                resolved.addAll(new List<String>{'ShippingStreet', 'ShippingCity', 'ShippingState', 'ShippingPostalCode', 'ShippingCountry'});
            } else if (lower == 'otheraddress') {
                resolved.addAll(new List<String>{'OtherStreet', 'OtherCity', 'OtherState', 'OtherPostalCode', 'OtherCountry'});
            } else {
                resolved.add(f.trim());
            }
        }
        return resolved;
    }
}