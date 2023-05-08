# WEB APPLICATION SECURITY CASE STUDY 

Group Name - **ITNAN**<br>

Group Member Details and our Tasks:

NAME                          |MATRIC NO                      | TASK                    |
-------------------------------|-----------------------------|-----------------------------|
JAMA SABIRIN SAAD         |1835578          |Introduction, Server OS, Re-examine Cache Control |
ANIS ASILA BINTI OTHMAN          |    1914782         |Objectives, JS Library, Cross-Domain Javascript        |
NUR ALIA BINTI MUHAMMAD   |2010884 |CSP, .Htaccess Information Leak, User Controllable(Potential XSS) |
NURUL SHAHIRAH BINTI AHMAD FIKRI|2013890  |Information Disclosure, Strict-Transport-Security, X-Content-Type  |

## Tables of Content
**[Introduction](#introduction)**<br>
**[Ojectives](#objectives)**<br>
**[Alerts & Vulnerabilities](#alerts-and-vulnerabilities)**<br>

## Introduction
In this case study, we were able to examine and analyse the Malaysian government website by identifying all of its vulnerabilities and level of risk. The overall level of risk obtained was measured by assigning ranks such as high, low, or medium, and we obtained solutions to minimise the risk and overcome the threats it would face.We acknowledge that by recognising all of the alerts identified on this website while using Zap application, we were able to identify solutions to reduce risks and develop web applications that have high performance and security.


## Objectives
The case study is designed to evaluate our problem-solving skills and teamwork toward the given case. The  web application vulnerabilities that we have to identify are Malaysia Government website. 

## Alerts And Vulnerabilities

<details><summary>Server OS</summary>
  
  * Level of the risk - Low
  * Classification of threat - CWE ID 829
` * Identification:
  By examining header X-Content-Type-Options alert which is designed to protect web applications from MIME type sniffing attacks.This alert provided details about the web server used, which is apache and operates on the Windows operating system. Furthermore, the Cross-Domain JavaScript Source File Inclusion alert specifies the server-side scripting language utilized, which is javascript with.js extension, thereby allowing javascript to be executed on the server.

 * Evaluation :
  The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff', which allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body. This enables attackers to execute malicious code on the website by tricking the browser into interpreting a file as a different MIME type other than the MIME type that the file is actually intended to be. The website used one or more javascript files from a third-party domain where this parties can collect data of users. Moreover this vulnerability allows attackers to inject javascript file from different domain giving them the ability to get users information and credentials 
  
  * Prevention :
    1.Developers must ensure that the X-Content-Type-Options header is set to 'nosniff' for all web pages while also setting the content type for the website to text/html. Moreover, all the users must use web browsers, such as Google Chrome, Firefox, internet Explorer or any other browser that do not perform MIME-sniffing 

    2.Allow JavaScript source files to be loaded from only trusted sources by evaluating these parties based on their performance before allowing, and ensuring that the sources cannot be managed by application end users.

    3.Use HTTPS protocol to increase the security of the site and prevent attackers from obtaining user credentials. 


</details>

<details><summary>JS Library</summary>
  
  * Level of the risk - Medium
  * Classification of threat - CWE ID 829
  * Identification:
    JavaScript libraries are collections of pre-written JavaScript code that provide specific functionalities and features. They are designed to make it easier for developers to build web applications by providing ready-to-use functions and components. The risk associated with CWE ID 829 is that the untrusted functionality can introduce security vulnerabilities or enable malicious actions within the software. The untrusted code may have unintended or malicious behaviors that could compromise the integrity, confidentiality, or availability of the system.
    
  * Evaluation:
    During an evaluation, it shows that library jquery, version 3.3.1 is vulnerable. It can lead to exploitation of known vulnerabilities, code execution, data breaches and Denial-of-Service (DoS) Attack. The vulnerable versions of jQuery File Upload had a remote code execution vulnerability that allowed attackers to execute arbitrary code on the server hosting the application. This vulnerability was related to the insecure handling of user-supplied file names.
   
  * Prevention:
1. Validate Inputs: Always validate and sanitize any inputs from untrusted sources to prevent injection attacks or unexpected behavior.

2. Code Reviews and Audits: Perform regular code reviews and security audits to identify any potential vulnerabilities or risks introduced by the integration of untrusted functionality.

3. Least Privilege: Limit the permissions and privileges granted to the untrusted code to reduce the potential damage it can cause if compromised.

4. Update and Patch: Keep all software components, including the untrusted functionality, up to date with the latest security patches and updates to mitigate known vulnerabilities.    
  
</details>

<details><summary>Cross-Domain Javascript</summary>
  
  * Level of the risk - Low
  * Classification of threat - CWE ID 829
  * Identification :
    Cross-domain JavaScript source file inclusion is a security warning that can affect a web application that runs one or more Javascript files from a third-party domain. It has been identified that the page includes one or more script files from a third-party domain. Cross-Origin Resource Sharing standard are used and it works by adding new HTTP headers that let servers describe which origins are permitted to read that information from a web browser. The website are exposed to, if the third-party intentionally or unintentionally holds a malicious content, it can be added and executed on the victim’s web application. This possibility occurs when the external Javascript is not validated.
  
  * Evaluation :
  During an evaluation, there is a possible execution of malicious javascript and also possible user data manipulation and leakage. For example, when a user sends a request, the script will be updated with the response message. If the response is stored in global variables, everyone can read it. If the sensitive information is included in a JSONP response, the executed function can be overridden to get the sensitive information. This trick can be used for global functions as well. Instead of overriding the executed functions, we may use custom-coded callback functions for global functions.
  
  * Prevention :
 1. Avoid placing sensitive information inside javascript files or JSONP.

2. Always try to sanitize user entries that are stored in JSON files.

3. Use subresource integrity. It helps browsers to check whether the fetched resources are unnecessarily manipulated or not.

4. Enable Content Security Policy (CSP).
  
</details>

<details><summary>CSP</summary>
  
  * Level of the risk - Medium 
  * Classification of threat - CWE ID 693
  * Identification :
   The Content Security Policy (CSP) is designed to offer supplementary security by identifying and resolving certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks, which are commonly employed for activities such as website defacement, malware dissemination, and data theft. This security measure utilizes a standardized set of HTTP headers, enabling website owners to designate authorised sources of content. According to the Common Weakness Enumeration (CWE) website, the website in question lacks sufficient protection and requires additional defensive measures due to the absence of a protective mechanism against a particular class of attack.

  * Evaluation :
  During a website evaluation, it was revealed that the website's headers were misconfigured, creating security gaps that could be exploited by attackers. The vulnerabilities were identified in the website's portal index and a text document under robots. This situation is concerning since it leaves the website open to attack, allowing malicious actors to take advantage of the vulnerabilities and gain entry with ease.

* Prevention : 
1. Ensure that the website's headers are correctly configured and that they conform to established best practices. This can be done using tools such as security scanners, which can identify potential issues and provide recommendations for addressing them.

2. Implement HTTPS encryption to protect sensitive data in transit and prevent attackers from intercepting or modifying communications between the website and its users.

3. Train website developers and administrators on secure coding practices and the latest security threats, so they can stay informed and take proactive measures to protect the website from attacks.

</details>

<details><summary>.Htaccess Information Leak</summary>
  
  * Level of the risk - Medium
  * Classification of threat - CWE ID 94
  * Identification : Htaccess files have the ability to modify the configuration of Apache Web Server, enabling users to enable or disable additional functionalities and features. According to CWE, a user's input containing code syntax can alter the intended control flow of the product, leading to arbitrary code execution. Injection problems cover a wide range of issues and require different mitigation methods. All injection issues share a commonality in that they allow control plane data to be injected into the user-controlled data plane, making them injection vulnerabilities.
  
  * Evaluation : During the evaluation, it was discovered that the .htaccess file was publicly accessible, which poses a significant security risk as sensitive information related to the website's configuration can be exposed to malicious actors. The .htaccess file is used to set configuration directives for a specific document directory and its subdirectories within the Apache Web Server. Therefore, if it falls into the wrong hands, it can be used to modify the server's behavior or expose sensitive information, leading to potential attacks such as website defacement or data theft.
  
* Prevention : 
1. Use server configuration files instead: Use server configuration files instead of .htaccess files, as server configuration files offer more security and control.
  
2. Regularly monitor and review files: Review all files, including .htaccess files, on a regular basis for any unauthorized changes.
  
3. Implement access controls: Implement access controls, such as firewalls and password protection, to limit access to the website and its files to only authorized users and cannot be accessible.
  
</details>

<details><summary>Strict-Transport-Security Header Not Set</summary>

* Level of the risk - Low

* Classification of threat - CWE ID 319

* Identification : Strict-Transport-Security Header Not Set has a vulnerability that allows a man-in-the-middle (MITM) attack to be used to intercept communication between a user's web browser and the server. Sensitive data theft, including the theft of login credentials or personal information, may result from this. A user's web browser might not be aware to always use a secure HTTPS connection when interacting with the server without the Strict-Transport-Security header. This may make the connection open to data theft and interception.

* Evaluation: During an evaluation, it shows that 

* Prevention: 
1. Strict-Transport-Security (HSTS) headers should be used: In order to require the user's web browser to only use HTTPS connections, set the Strict-Transport-Security header in all HTTP responses. By instructing the browser to use HTTPS for all upcoming requests to the domain, this header reduces the possibility of protocol downgrade attacks.

2. Use HTTPS for all connections. Ensure that HTTP is never used when connecting to your web application. By doing this, MITM and session hijacking attacks will be reduced.

3. Use certificate pinning: To ensure that the web browser only accepts trusted SSL/TLS certificates. By confirming that the certificate displayed during the connection is the expected one, this will help prevent MITM attacks.

4. Observe traffic and access logs: Carefully monitor traffic and access logs to spot any suspicious activity that might point to an ongoing attack. Respond right away to found vulnerabilities and put in place the required defences to stop attacks.

</details>

<details><summary>X-Content-Type-Options Header Missing</summary>

* Level of the risk - Low

* Classification of threat - CWE ID 693

* Identification : The X-Content-Type-Options header is a security header that directs web browsers not to override the response content-type header. This is significant because some web browsers may try to sniff the content type of a response to determine the manner in which to deal with it. For instance, if a response is marked as text/html but actually contains JavaScript code, a browser may still try to run the JavaScript code, which could cause security problems. A server could be vulnerable to attacks like content spoofing, where an attacker could change the response content-type to deceive a browser into running malicious code, by leaving out the X-Content-Type-Options header. X-Content-Type-Options Header Missing is a vulnerability where a web server fails to include the X-Content-Type-Options header in its HTTP responses, which corresponds to CWE. By tricking a web browser into thinking a response is a different content type, an attacker can use MIME sniffing attacks, which are mitigated by this header. A web server may be vulnerable to content spoofing, MIME sniffing, cross-site scripting (XSS), and clickjacking attacks without the X-Content-Type-Options header.

* Evaluation:

* Prevention: 
1. Implement the X-Content-Type-Options header in HTTP responses: This header's value ought to be nosniff. By doing this, the web server instructs web browsers to only comprehend the response's content according to the response content-type header.

2. Set the web application frameworks: The X-Content-Type-Options header can be set using built-in options in web application frameworks like ASP.NET and Ruby on Rails. By turning on this feature, MIME sniffing attacks can be avoided.

3. Use a content delivery network (CDN): By delivering content with the appropriate MIME type and ensuring that the X-Content-Type-Options header is set in HTTP responses, a CDN can assist in preventing MIME sniffing attacks.

4. Scan for vulnerabilities frequently: Regular vulnerability scans can help locate any X-Content-Type-Options headers that are missing from a security protocol.

5. Maintain software updates: To prevent known vulnerabilities related to the X-Content-Type-Options header, make sure that the web server and all of its software components are up to date with the most recent security patches and updates.

</details>

<details><summary>Information Disclosure</summary>

* Level of the risk - Informational

* Classification of threat - CWE ID 200

* Identification : Information disclosure can be exploited by attackers in a variety of ways. Suspicious comments, which could be shared on a website or within a JavaScript file like the one in the URL, might be used by attackers to reveal confidential information such as usernames, passwords, or other personal data. This information could be used by attackers to carry out additional attacks, such as phishing or identity theft. Attackers could also use information disclosure as a form of monitoring, gathering information about a target or system in order to plan a more sophisticated attack. If suspicious comments indicate sensitive or private information to unauthorised parties, they may be classified as an information leak vulnerability under CWE-200. Such comments might include information that attackers might utilise to gain unauthorized access to a system or conduct other malicious activities.

* Evaluation:

* Prevention: 
1. Secure coding practices: Developers should adhere to secure coding practices and use code review tools to identify and eliminate any suspicious comments. They should also be acquainted with best practices for security and kept up-to-date on the latest security threats and vulnerabilities.

2. Sanitise user inputs and activate access controls: To prevent unauthorized access to sensitive data, applications should sanitize user inputs and implement access controls.

3. Encrypt and hash sensitive data: To prevent unauthorized access and data leaks, sensitive data should be encrypted and hashed.

4. Limit sensitive data exposure: Developers should limit sensitive data exposure by only maintaining it when necessary and keeping it concealed from potential hackers.

5. Regularly monitoring system logs: It can aid in the detection of suspicious activity and the prevention of data leaks. This can include employing intrusion detection and prevention systems as well as monitoring network traffic for indications of attacks.

6. Educate users: Users should be educated on the importance of keeping their personal information secure and the manner in which to avoid phishing scams and other common attacks that can lead to information disclosure.

</details>

<details><summary>User Controllable HTML Element Attribute (Potential XSS)</summary>

 * Level of the risk - Low
  * Classification of threat - CWE ID 20
  * Identification : The aim of the security check is to examine user-provided input in query string parameters and POST data to locate instances where specific HTML attribute values can be manipulated. The objective of this check is to identify possible hot-spots for cross-site scripting (XSS) attacks, which necessitate further review by a security analyst to determine their exploitability. If software fails to validate input correctly, an attacker can generate input that is unexpected by the application. According to the CWE website, this can result in unintended input being delivered to parts of the system, which may lead to altered control flow, arbitrary control of a resource, or arbitrary code execution.
  
  * Evaluation : During the website evaluation, it was discovered that there were issues with input validation in query parameters located in the language function of the portal index. This vulnerability allowed for user-controlled HTML attribute values, which could be exploited by injecting special characters to test for potential cross-site scripting (XSS) attacks. This vulnerability is highly concerning since it could allow an attacker to inject malicious code into the website, confusing visitors and leading to unwanted situations such as scams.

  * Prevention : 
  1. Ensure that any user-supplied data is sanitized and validated before being used by the application. This can include validating input data type, length, and format, as well as restricting input to only allow certain characters or patterns. 
  
  2. Implementing a Content Security Policy (CSP) with appropriate HTTP headers can help prevent XSS attacks by restricting the sources of content that can be loaded on the website and regular security assessments and testing can also help identify and address any vulnerabilities before they can be exploited by attackers.
  
</details>

<details><summary>Re-examine Cache-control</summary>

 * Level of the risk - Low
  * Classification of threat - CWE ID 525
  * Identification :   Cache controls are browser headers that indicate the server- and client-side catching policies. This policy gives the website the ability to control how pages and resources are cached. Caching allows websites to increase their performance, but if it is not implemented correctly, it can endanger the website and expose critical information to unauthorized users. Cache-control directives are set in the HTTP response header to acquire information from client and the server side on how to cache and store the response.

  * Evaluation : While reviewing the web application, it was discovered that some configurations on the catche-control header were not correctly configured or were missing, and in this vulnerability, if the attacker modifies contents from third parties, it may affect the web application. Before sending a request to the server, review the cached data to ensure that no sensitive data is captured. 

  * Prevention : 
  1. To ensure high security, make sure the cache-control HTTP header is set to "no-cache," which requires the browser to confirm the resource with the server whether the catched resource has been updated or modified.  The cache-control HTTP header should be set to "no-store" which can be used when dealing with sensitive information. 
  
  2. For any asset resource such as images should be set to public where by that resource can cached by any cache, and setting the "max-age" as well where it determines the amount of time the response can be used from the time it was requested.

  
</details>



