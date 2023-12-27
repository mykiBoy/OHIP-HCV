<?php

// initialize with input parameters to this API
global $healthcard, $versionCode, $serviceCode;
$healthcard = '9287170261';
$versionCode = 'DK';
$serviceCode = 'A110';
global $MOH_ID, $username, $password;
$MOH_ID = '621300';
$username = 'confsu+427@gmail.com';
$password = 'Password2!';
global $privatekey;
// load external script which imports $privatekey
include 'loadkeystore.php';

// create responseObj to as the output of this API
$responseObj = new stdClass();
global $responseObj;

function loadbody($healthcard,$versionCode,$serviceCode) {

$rawbody = <<<EOT
<soapenv:Body wsu:Id="id-5">
    <hcv:validate>
       <requests>
          <!--1 to 100 repetitions:-->
          <hcvRequest>
             <healthNumber>$healthcard</healthNumber>
             <versionCode>$versionCode</versionCode>
             <!--0 to 5 repetitions:-->
             <feeServiceCodes>$serviceCode</feeServiceCodes>
          </hcvRequest>
       </requests>
       <!--Optional:-->
       <locale>en</locale>
    </hcv:validate>
 </soapenv:Body>
EOT;

  return $rawbody;
}

function loadtimestamp() {
  // Create the first timestamp
  $firstTimestamp = new DateTime('now', new DateTimeZone('UTC'));
  $firstTimestampStr = $firstTimestamp->format('Y-m-d\TH:i:s.v\Z');

  // Create the second timestamp (10 minutes after the first one)
  $secondTimestamp = clone $firstTimestamp;
  $secondTimestamp->add(new DateInterval('PT10M')); // Add 10 minutes
  $secondTimestampStr = $secondTimestamp->format('Y-m-d\TH:i:s.v\Z');

$timestamp = <<<EOT
<wsu:Timestamp wsu:Id="id-3"><wsu:Created>$firstTimestampStr</wsu:Created><wsu:Expires>$secondTimestampStr</wsu:Expires></wsu:Timestamp>
EOT;
  return $timestamp;
}

function loadEBS() {
// generate uuid without external library because my server doesn't have composer
$uuid = vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex(random_bytes(16)), 4) );

// hardcode conformance key here, as it will be permanent
$EBS = <<<EOT
      <ebs:EBS wsu:Id="id-1">
         <SoftwareConformanceKey>86239993-0451-4b0d-ba89-094bac6656b7</SoftwareConformanceKey>
         <AuditId>$uuid</AuditId>
      </ebs:EBS>
EOT;
  return $EBS;
}

function loadIDP($MOH_ID) {
$IDP = <<<EOT
      <idp:IDP wsu:Id="id-2">
         <ServiceUserMUID>$MOH_ID</ServiceUserMUID>
      </idp:IDP>
EOT;
  return $IDP;
}

function loadUsernameToken($username,$password) {
$usernameToken = <<<EOT
<wsse:UsernameToken wsu:Id="id-4"><wsse:Username>$username</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">$password</wsse:Password></wsse:UsernameToken>
EOT;
  return $usernameToken;
}

// given xml input, digestxml will canonicalize xml then hash it with SHA256, returning a hash value as digest string
function digestxml($xml) {
  // Create a DOMDocument
  $dom = new DOMDocument();

  // Load the XML content into the DOMDocument
  $dom->loadXML($xml);

  // Canonicalize the document using C14N version 1.0
  $canonicalizedXML = $dom->C14N();

  // Output the canonicalized XML
  // echo $canonicalizedXML."\n\n";

  // Calculate SHA-256 hash, set hash func binary option to true
  $digestvalue = base64_encode(hash('sha256', $canonicalizedXML, true));
  return $digestvalue;
}

function loadxmltemplate() {

$root_namespaces = <<<EOT
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ebs="http://ebs.health.ontario.ca/" xmlns:hcv="http://hcv.health.ontario.ca/" xmlns:idp="http://idp.ebs.health.ontario.ca/" xmlns:msa="http://msa.ebs.health.ontario.ca/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
EOT;

// must declare var global to be able to use global var from outside the function
global $healthcard,$versionCode,$serviceCode;
$body = loadbody($healthcard, $versionCode, $serviceCode);
// insert namespace definition from all parent nodes into the xml part to be canonicalized. this is required, otherwise soapenv namespace would be undefined.
$modifiedbody = substr_replace($body, $root_namespaces, strpos($body, '<soapenv:Body') + strlen('<soapenv:Body'), 0);
// echo $body."\n\n"; //for debugging
$digestvalue5 = digestxml($modifiedbody);
// echo $digestvalue5."\n\n"; //for debugging

$timestamp = loadtimestamp();
$modtimestamp = substr_replace($timestamp, $root_namespaces, strpos($timestamp, '<wsu:Timestamp') + strlen('<wsu:Timestamp'), 0);
// echo $modtimestamp."\n\n"; //for debugging
$digestvalue3 = digestxml($modtimestamp);
// echo $digestvalue3."\n\n"; //for debugging

$EBS = loadEBS();
$modifiedEBS = substr_replace($EBS, $root_namespaces, strpos($EBS, '<ebs:EBS') + strlen('<ebs:EBS'), 0);
$digestvalue1 = digestxml($modifiedEBS);

global $MOH_ID;
$IDP = loadIDP($MOH_ID);
$modifiedIDP = substr_replace($IDP, $root_namespaces, strpos($IDP, '<idp:IDP') + strlen('<idp:IDP'), 0);
$digestvalue2 = digestxml($modifiedIDP);

global $username,$password;
$usernameToken = loadUsernameToken($username,$password);
$modusernameToken = substr_replace($usernameToken, $root_namespaces, strpos($usernameToken, '<wsse:UsernameToken') + strlen('<wsse:UsernameToken'), 0);
$digestvalue4 = digestxml($modusernameToken);

$signedInfo = <<<EOT
<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="ebs hcv idp msa soapenv wsu" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#id-5"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="ebs hcv idp msa" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>$digestvalue5</ds:DigestValue></ds:Reference><ds:Reference URI="#id-1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="hcv idp msa soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>$digestvalue1</ds:DigestValue></ds:Reference><ds:Reference URI="#id-2"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="ebs hcv msa soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>$digestvalue2</ds:DigestValue></ds:Reference><ds:Reference URI="#id-3"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="wsse ebs hcv idp msa soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>$digestvalue3</ds:DigestValue></ds:Reference><ds:Reference URI="#id-4"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces PrefixList="ebs hcv idp msa soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>$digestvalue4</ds:DigestValue></ds:Reference></ds:SignedInfo>
EOT;
//insert namespace from all parent nodes before canonicalization
$modsignedInfo = substr_replace($signedInfo, $root_namespaces, strpos($signedInfo, '<ds:SignedInfo') + strlen('<ds:SignedInfo'), 0);

  // Create a DOMDocument to prep for C14N canonicalization
  $dom = new DOMDocument();
  // Load the XML content into the DOMDocument
  $dom->loadXML($modsignedInfo);
  // Canonicalize the document using C14N version 1.0
  $canonicalizedXML = $dom->C14N();
  // Calculate SHA-1 hash of $signedInfo
  // The second parameter 'true' outputs raw binary data
  $digest = sha1($canonicalizedXML, true);

  // Calculate SHA-256 hash of $signedInfo
  // $digest = hash('sha256', $signedInfo, true);

global $privatekey;
// Sign the SHA-1 hash using private key and PKCS1 padding
openssl_sign($digest, $signature, $privatekey, OPENSSL_ALGO_SHA1);
// Signature is now in $signature
$signature=base64_encode($signature);
// echo 'Signature: ', base64_encode($signature), "\n\n"; //for debug
  
$rawxml = <<<EOT
<soapenv:Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ebs="http://ebs.health.ontario.ca/" xmlns:hcv="http://hcv.health.ontario.ca/" xmlns:idp="http://idp.ebs.health.ontario.ca/" xmlns:msa="http://msa.ebs.health.ontario.ca/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
   <soapenv:Header><wsse:Security soapenv:mustUnderstand="1"><wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="X509-28C9CE93E0A1F26FD917013530402403">MIICdTCCAd6gAwIBAgIJAIgq6l1JzkMMMA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMRAwDgYDVQQHEwdUb3JvbnRvMREwDwYDVQQKEwhsaWdodEVNUjERMA8GA1UECxMIT0hJUCBFQlMxEjAQBgNVBAMTCUxpZ2h0IEVNUjAeFw0yMzExMzAwMzUzNTJaFw00MzExMjUwMzUzNTJaMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMRAwDgYDVQQHEwdUb3JvbnRvMREwDwYDVQQKEwhsaWdodEVNUjERMA8GA1UECxMIT0hJUCBFQlMxEjAQBgNVBAMTCUxpZ2h0IEVNUjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAuTOk0wQTfR5gkaprZ2bk/sIR5UEHV+TQhuUXCnoBgykoM+FOiumHxeZobIYLanFZ7VPxZyXIYB/uPD6NJ5YOd3UhbD7RFgpS7TQiF2Y+Ndu9wwYkXpJSVfd7q+R+xG/zpEVedm8/vJLFLmeHMKELqxKrjmObRyn5BJd0UrhGtzcCAwEAAaMhMB8wHQYDVR0OBBYEFFB8aN77G0N7cC/zkKR9vWrHEycdMA0GCSqGSIb3DQEBCwUAA4GBAKlcecHQkrLz2F033QK3bYn9cJ+Qf3we+VDCr8Wbrp+Bh4wFYs6k57EITm5h/MpAIWO9lc0xaw6wKDlHhrl6fGs7Sxjk/AN7Sm5Bi9hzAyzCSPMhxr3njIDVZr5h0ekzoRnaoPAByM2e4ZKc288DAtE3sirNxmHswrnyZEO7BGa2</wsse:BinarySecurityToken>$usernameToken$timestamp<ds:Signature Id="SIG-28C9CE93E0A1F26FD917013530402876">$signedInfo<ds:SignatureValue>$signature</ds:SignatureValue><ds:KeyInfo Id="KI-28C9CE93E0A1F26FD917013530402454"><wsse:SecurityTokenReference wsu:Id="STR-28C9CE93E0A1F26FD917013530402475"><wsse:Reference URI="#X509-28C9CE93E0A1F26FD917013530402403" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/></wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature></wsse:Security>

$EBS
$IDP
   </soapenv:Header>
   $body
</soapenv:Envelope>
EOT;
  return $rawxml;
}

$rawxml = loadxmltemplate();
// echo $rawxml."\n\n"; //for debugging

function sendrequest($xmlPayload) {
  $url = 'https://ws.conf.ebs.health.gov.on.ca:1444/HCVService/HCValidationService';

  $headers = [
      'Content-Type: text/xml;charset=UTF-8',
      'Connection: Keep-Alive',
  ];

  // Initialize cURL session
  $ch = curl_init($url);

  // Set cURL options
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $xmlPayload);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
  // visit endpoint url in chrome, download certificates from chrome
  // including Certificate Authority G2, intermediate L1K and server certificate
  // open all three in notepad and paste together, save as cacert.pem
  curl_setopt($ch, CURLOPT_CAINFO, 'cacert.pem');
  // set option to track request header in curl_getinfo
  curl_setopt($ch, CURLINFO_HEADER_OUT, true);
  // set option to include response header in $response
  curl_setopt($ch, CURLOPT_HEADER, true);

  // Execute cURL session
  $response = curl_exec($ch);

  // Check for cURL errors
  if (curl_errno($ch)) {
      echo 'Curl error: ' . curl_error($ch);
  }

  // print_r(curl_getinfo($ch)); //for debug
  $serverStatus = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // request headers
  
  // Create and open a file for writing verbose output
  $httpLogFile = fopen('httplog.txt', 'a');
  // Delete all contents of the log file
  file_put_contents('httplog.txt', '');
  // Write request headers to the log file
  fwrite($httpLogFile, curl_getinfo($ch, CURLINFO_HEADER_OUT));
  fwrite($httpLogFile, $xmlPayload."\n\n\n");

  // Extract body from the response
  $body = substr($response, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
  fwrite($httpLogFile, $response);
  // Close the file handle for http log
  fclose($httpLogFile);
  
  // Close cURL session
  curl_close($ch);

  // Output the response
  return [$serverStatus,$body];
}


$response = sendrequest($rawxml);

// echo out the response to console
// echo $response[0]."\n\n\n"; //for debugging
// echo $response[1]; // for debugging

if ($response[0] <300) {
  $decryptedResult = decryptResponse($response[1]);
  // echo $decryptedResult; //for debugging
  buildresponseObj($decryptedResult);
} else {
  errorhandling($response[0], $response[1]);
}

function decryptResponse($responseXML) {
  // input encrypted response XML, output decrypted result XML
  // Create SimpleXML object
  $xml = simplexml_load_string($responseXML);

  // Register the 'xenc' namespace
  $xml->registerXPathNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');

  // Use XPath to select the CipherValue
  $cipherValues = $xml->xpath('//xenc:CipherValue');

  // Check if CipherValues were found
  if (!empty($cipherValues)) {
      // Decrypt using private key
      global $privatekey;
      openssl_private_decrypt(base64_decode($cipherValues[0]), $decryptedAesKey, $privatekey, OPENSSL_PKCS1_PADDING);
      // echo "AES key: ",base64_encode($decryptedAesKey),"\n\n";
    // Extract the initialization vector required for AES decryption
    $iv = substr(base64_decode($cipherValues[1]), 0, 16);
    // Decrypt using AES with CBC mode, PKCS5 padding, and the extracted IV
    $decryptedData = openssl_decrypt($cipherValues[1], 'aes-128-cbc', $decryptedAesKey, 0, $iv);
      $responseXML = substr($decryptedData, 16);
      return $responseXML;
  } else {
      global $responseObj;
      //set error flag to true
      $responseObj->error = true;
      $responseObj->errorMsg = "Ciphervalue not found";
  }
}

function errorhandling($serverStatus,$response){
  global $responseObj;
  //set error flag to true
  $responseObj->error = true;
  $responseObj->errorMsg = "Server Error: ".$serverStatus.". ";
  $xml = simplexml_load_string($response);
  // Register namespaces
  $xml->registerXPathNamespace('soapenv', 'http://schemas.xmlsoap.org/soap/envelope/');
  $xml->registerXPathNamespace('ns1', 'http://ebs.health.ontario.ca/');
  // Use XPath to extract <code> and <message> elements
  $errorcodes = $xml->xpath('//soapenv:Fault/code | //ns1:EBSFault/code');
  $errormsgs = $xml->xpath('//ns1:EBSFault/message');

  // Concatenate values
  $errormsg = "Error: ".implode(', ', $errorcodes). ' - ' . implode(', ', $errormsgs);
  $responseObj->errorMsg = $responseObj->errorMsg.$errormsg;
}

function buildresponseObj($decryptedResult) {
  // Parse the XML
  $xml = simplexml_load_string($decryptedResult);

  global $responseObj;

  // Store properties in $responseObj
  $responseObj->auditUID = (string)$xml->auditUID;
  $responseObj->dateOfBirth = (string)$xml->results->dateOfBirth;
  $responseObj->expiryDate = (string)$xml->results->expiryDate;
  $responseObj->firstName = (string)$xml->results->firstName;
  $responseObj->gender = (string)$xml->results->gender;
  $responseObj->healthNumber = (string)$xml->results->healthNumber;
  $responseObj->lastName = (string)$xml->results->lastName;
  $responseObj->responseAction = (string)$xml->results->responseAction;
  $responseObj->responseCode = (string)$xml->results->responseCode;
  $responseObj->responseDescription = (string)$xml->results->responseDescription;
  $responseObj->responseID = (string)$xml->results->responseID;
  $responseObj->secondName = (string)$xml->results->secondName;
  $responseObj->versionCode = (string)$xml->results->versionCode;

  // Fee Service Details
  $responseObj->feeServiceCode = (string)$xml->results->feeServiceDetails->feeServiceCode;
  $responseObj->feeServiceDate = (string)$xml->results->feeServiceDetails->feeServiceDate;
  $responseObj->feeServiceResponseCode = (string)$xml->results->feeServiceDetails->feeServiceResponseCode;
  $responseObj->feeServiceResponseDescription = (string)$xml->results->feeServiceDetails->feeServiceResponseDescription;

  $responseObj->error = false;
}
// echo "\n\n";
// print_r($responseObj); // for debugging
echo json_encode($responseObj);