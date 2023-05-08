# WEB APPLICATION SECURITY CASE STUDY 

Group Name - **ITNAN**<br>

Group Member Details and our Tasks:

NAME                          |MATRIC NO                      | TASK                    |
-------------------------------|-----------------------------|-----------------------------|
JAMA SABIRIN SAAD         |1835578          |Introduction, Server OS, Re-examine Cache Control |
ANIS ASILA BINTI OTHMAN          |    1914782         |Objectives, JS Library, Cross-Domain Javascript        |
NUR ALIA BINTI MUHAMMAD   |2010884 |CSP, .Htaccess Information Leak, User Controllable(Potential XSS) |
NURUL SHAHIRAH BINTI AHMAD FIKRI|2013890  |Information Disclosure, Strict-Transport-Secutity, X-Content-Type  |

## Tables of Content
**[Introduction](#introduction)**<br>
**[Ojectives](#objectives)**<br>
**[Alerts & Vulnerabilities](#alerts-and-vulnerabilities)**<br>

<details><summary>List of Figures</summary>
  
 write text here
  
</details>

<details><summary>List of Tables</summary>
  
  Write text here
  
</details>

<details><summary>References</summary>
  
  Write text here
  
</details>

## Introduction

## Objectives

## Alerts And Vulnerabilities

<details><summary>Server OS</summary>
  
  * Level of the risk - **text**
  * Classification of threat - 
  * Prevent the vulnerabilities
  
</details>

<details><summary>JS Library</summary>
  
  * Level of the risk - **text**
  * Classification of threat - 
  * Prevent the vulnerabilities
  
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

<details><summary>Information Disclosure </summary>

* Level of the risk - Informational
* Classification of threat - CWE ID 200
* Identification : 

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



