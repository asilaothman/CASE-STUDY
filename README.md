# WEB APPLICATION SECURITY CASE STUDY 

Group Name - **ITNAN**<br>

Group Member Details:

NAME                          |MATRIC NO                      |
-------------------------------|-----------------------------|
JAMA SABIRIN SAAD         |1835578          |
ANIS ASILA BINTI OTHMAN          |    1914782         |
NUR ALIA BINTI MUHAMMAD   |2010884 |
NURUL SHAHIRAH BINTI AHMAD FIKRI|2013890  |

## Assigned Task
NAME                          |TASK                    |
-------------------------------|-----------------------------|
JAMA SABIRIN SAAD         |Introduction, Server OS, Re-examine Cache Control |
ANIS ASILA BINTI OTHMAN          |Objectives, JS Library, Cross-Domain Javascript        |
NUR ALIA BINTI MUHAMMAD   |CSP, .Htaccess Information Leak, Potential XSS |
NURUL SHAHIRAH BINTI AHMAD FIKRI|Information Disclosure, Strict-Transport-Secutity, X-Content-Type  |

## Tables of Content
**[Introduction](#introduction)**<br>
**[Ojectives](#objectives)**<br>
**[Alerts & Vulnerabilities](#alerts-and-vulnerabilities)**<br>


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
  * Identification : 
  * Evaluation :
  * Prevention
  
</details>

<details><summary>Information Disclosure </summary>

write text here

</details>

<details><summary>List of Figures</summary>
  
 write text here
  
</details>

<details><summary>List of Tables</summary>
  
  Write text here
  
</details>

<details><summary>References</summary>
  
  Write text here
  
</details>
