---
title: "The Billion Laughs Bomb"
seoTitle: "Prevent XXE Attacks in XML: Full Guide with Code and Fixes"
seoDescription: "Learn how to identify, exploit, and prevent XXE vulnerabilities with real examples, secure code, and step-by-step attacker insights."
datePublished: Thu Apr 17 2025 02:16:00 GMT+0000 (Coordinated Universal Time)
cuid: cm9kqb2ds000509k0ewab6dyf
slug: the-billion-laughs-bomb
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1744856064980/e9433258-65eb-4765-9a00-83fdae9028aa.jpeg
tags: xml, web-development, security, webdev, cybersecurity-1, xxe

---

## **Introduction**

XML External Entity (XXE) attacks are not just theoretical, they're dangerously real. If your application processes XML in any way, API, file upload, or SOAP, you may already be vulnerable. And many developers don’t even know it.

In this article, I’ll walk you through how XXE attacks work, how attackers exploit them step-by-step, real-world examples, and how to secure your stack. This is your field guide to surviving the XXE wilderness.

---

## **Understanding XXE Injection: The Fundamentals**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1744852695979/270b128b-1c90-498a-8a99-74068011c3cc.png align="center")

### **What is XXE?**

An **XML External Entity (XXE)** attack targets vulnerable XML parsers. It leverages the `<DOCTYPE>` declaration and *entities* to access restricted files, perform internal HTTP requests, or even cause a Denial of Service.

If your XML parser allows external entities (enabled by default in many platforms), attackers can use payloads like:

```python
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

**Impact?** Your server could unknowingly leak sensitive data, query internal services, or crash entirely.

---

### **Key XML Concepts**

* **Document Type Definition (DTD):** Declares rules and entities for the XML doc.
    
* **Entities:**
    
    * **Internal:** Text substitution within XML.
        
    * **External:** References to outside files or URLs (the core of XXE attacks).
        
    * **Parameter Entities:** Used inside DTDs, key to advanced and blind XXE.
        

### **The Real Problem: Weak Parsers**

Many parsers default to resolving DTDs. That’s like leaving the vault door ajar because the manual says it’s “a feature.”

---

## **Types of XXE Attacks and Their Impacts**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1744853175152/504ceccb-2025-4157-92d8-71ecbb97aa26.png align="center")

### **1\. File Disclosure**

```python
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

> **Impact:** Attacker reads OS, app configs, credentials, or SSH keys.

---

### **2\. Server-Side Request Forgery (SSRF)**

```python
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

> **Impact:** Access cloud instance metadata (AWS, Azure), scan internal services.

---

### **3\. Denial of Service (DoS)**

**Billion Laughs Payload:**

```python
<!ENTITY lol "lol"> ... <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;">
```

> **Impact:** Crashes parser with exponential entity expansion.

---

### **4\. Blind XXE (OOB or Error-Based)**

* **Out-of-Band (OOB):** Reads file, sends contents to `http://attacker.com`
    
* **Error-based:** Triggers an error message that leaks the content
    

---

## **How Hackers Exploit XXE – Step-by-Step**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1744853944328/3244e0ed-872f-4448-bbff-812093fde50d.png align="center")

### **Step 1: Locate XML Inputs**

* Upload portals (.xml, .docx, .svg)
    
* SOAP APIs
    
* Hidden fields processed as XML
    

---

### **Step 2: Test the Waters**

Inject a simple payload:

```python
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>&xxe;</test>
```

Look for reflected data, errors, or strange delays (DoS).

---

### **Step 3: Craft Exploits**

* File read: `file:///etc/shadow`
    
* SSRF: `http://localhost:8080/admin`
    
* Blind XXE: Use external DTDs or DNS
    

---

### **Step 4: Data Exfiltration**

* Capture via attacker-controlled URL
    
* Observe logs for OOB requests
    
* Decode errors for leaked values
    

---

## **Real-World Incidents**

* **IBM WebSphere**: XXE enabled access to server-side files.
    
* **SharePoint & DotNetNuke**: File upload paths led to XXE vectors.
    
* **PostgreSQL**: Affected through XML import features.
    

Even mature systems are vulnerable when DTD processing is left enabled.

---

## **Vulnerable vs. Secure Code Snippets**

### **Java (Bad)**

```python
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
Document doc = factory.newDocumentBuilder().parse(input);
```

### **Java (Good)**

```python
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

---

### **PHP (Bad)**

```python
$xml = simplexml_load_string($xmlInput);
```

### **PHP (Good)**

```python
libxml_disable_entity_loader(true);
```

---

## **Mitigation Strategies**

[![Mitigation Strategies](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fwclr7wduuq5cfyfhmzfx.png align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fwclr7wduuq5cfyfhmzfx.png)

✅ **Disable DTDs and external entity resolution**

✅ **Use schema validation (XSD)**

✅ **Sanitize XML input**

✅ **Patch your libraries regularly**

✅ **Use Web Application Firewalls and RASP**

✅ **Run apps with least privileges**

---

## **Conclusion**

XXE is not a bug—it’s a misuse of an XML feature. Most vulnerabilities arise from insecure defaults and developer unawareness.

The fix? Proactively disable external entity parsing. Understand your parser. Test aggressively.

Secure your apps before attackers secure your data.

---

## **Disclaimer**

This blog is intended solely for **educational and ethical learning** purposes. Do not attempt to exploit systems without legal authorization. Always use these techniques in safe lab environments.

---

## **Further Reading**

1. [OWASP XXE Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
    
2. [PortSwigger Web Security Academy – XXE](https://portswigger.net/web-security/xxe)
    
3. [Synack: Deep Dive into XXE](https://www.synack.com/blog/a-deep-dive-into-xxe-injection/)
    
4. [Cobalt: Executing XXE Attacks](https://www.cobalt.io/blog/how-to-execute-an-xml-external-entity-injection-xxe)
    
5. [OWASP: XXE in Real-World Scenarios](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_\(XXE\)_Processing)