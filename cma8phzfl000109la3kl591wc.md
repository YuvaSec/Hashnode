---
title: "When Servers Talk to Strangers: SSRF"
seoTitle: "What is SSRF (Server-Side Request Forgery)? Explained Simply"
seoDescription: "Learn what SSRF is, how it works, and why it's dangerous. A beginner-friendly guide with stories, visuals, real-world examples, and prevention tips."
datePublished: Sat May 03 2025 20:59:52 GMT+0000 (Coordinated Universal Time)
cuid: cma8phzfl000109la3kl591wc
slug: when-servers-talk-to-strangers-ssrf
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1746305269533/8bc3795a-bf3e-463c-b7c1-c4e1eba19e8c.jpeg
tags: hacking, cyber, vulnerability, cybersecurity-1, ssrf

---

## **Introduction**

Imagine sending a letter to your friend, but instead, the mailman reads it and delivers it to someone else without your knowledge. This misdirection is akin to what happens in a Server-Side Request Forgery (SSRF) attack.

In the vast landscape of cybersecurity threats, SSRF stands out as a subtle yet potent vulnerability. It allows attackers to manipulate servers into making unintended requests, potentially exposing sensitive internal systems. Understanding SSRF is crucial, especially as our reliance on interconnected web services grows.

---

## **What is SSRF?**

**Server-Side Request Forgery (SSRF)** is a security vulnerability where an attacker tricks a server into making requests on their behalf. This can lead to unauthorized access to internal systems, sensitive data, or even control over the server itself.

[![What is SSRF?](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fraks6ll7w3w7nxqp1gim.jpeg align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fraks6ll7w3w7nxqp1gim.jpeg)

**Example:**  
*A mischievous child wanted to know what was inside a locked room. They couldn't enter, but they convinced the castle's messenger to fetch items from the room for them. The messenger, trusting the child, unknowingly helped them access secrets they shouldn't have.*

---

## **How Does SSRF Work?**

Attackers find functionalities in web applications that fetch data from URLs provided by users. By supplying malicious URLs, they can make the server access internal resources.

[![How Does SSRF Work?<br>
](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fn2ib8fhw7talkbjz31s6.jpeg align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fn2ib8fhw7talkbjz31s6.jpeg)

**Example**  
*In a grand library, visitors could request books from any shelf. A trickster wrote down a secret shelf number, and the librarian, following protocol, fetched a forbidden book, revealing hidden knowledge.*

---

## **Types of SSRF Attacks**

* Accessing Internal Systems
    
* Bypassing Authentication
    
* Blind SSRF
    

### **1\. Accessing Internal Systems**

Attackers can access internal services by making the server request internal URLs.

[![Accessing Internal Systems](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fs7mcf2qd2ih7pblhwtxr.jpeg align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fs7mcf2qd2ih7pblhwtxr.jpeg)

**Example:**  
*A visitor asked the castle's gardener to fetch a rare flower from the hidden garden. The gardener, unaware of the rules, complied, revealing the secret garden's existence.*

---

### **2\. Bypassing Authentication**

Some internal services trust requests from the server itself. Attackers exploit this trust to bypass authentication.

[![Bypassing Authentication](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Faxgt1y54vpmth0iho0hj.jpeg align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Faxgt1y54vpmth0iho0hj.jpeg)

**Example:**  
*A town had a rule: any letter from the mayor's office would be honored without question. A clever individual forged a letter, and the guards, seeing the official seal, allowed them access to restricted areas.*

---

### **3\. Blind SSRF**

In blind SSRF, attackers don't see the response but infer success through indirect means.

[![Blind SSRF](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2F6agrbdzgxqb7ll8uggg2.jpeg align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2F6agrbdzgxqb7ll8uggg2.jpeg)

**Example:**  
*A child shouted into a tunnel, and though they couldn't see the end, they listened for echoes to understand its length and structure.*

---

## **SSRF vs. CSRF: Not the Same Beast**

* **SSRF**: The server is fooled.
    
* **CSRF**: The user is fooled.
    

[![RF vs. CSRF](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fdorct3evim4b2et8g65d.jpeg align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fdorct3evim4b2et8g65d.jpeg)

**Example:**  
**SSRF:** You forge a delivery slip so the school janitor picks up your friend’s test from the teacher’s office.  
  
**CSRF:** You trick your friend into clicking a link that submits their homework late—under their name, without them realizing.

---

## **Real-World Exploits**

SSRF isn’t just a theory—it’s happening. In 2025, over **400 IPs** exploited SSRF vulnerabilities in **Zimbra, GitLab, Ivanti**, and even **OpenAI**. Despite medium severity ratings, thousands of attack attempts were logged. Some led to **remote code execution**—a full compromise.

[![Real-World Exploits](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fo828x7lahl47c8dota9x.jpeg align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Fo828x7lahl47c8dota9x.jpeg)

**Example:**  
It was like a bank drive-thru allowing a customer to say “Hey, can you open the vault and hand me whatever’s inside?” And the bank *did it*, because they trusted the internal request.

---

## **How Attackers Pull it Off**

1. The attacker finds a website feature that fetches something for the user (like “Upload profile picture from a URL”).
    
2. They insert a malicious URL (like [`http://localhost/admin`](http://localhost/admin)).
    
3. The server says “Sure!” and requests that private internal address.
    
4. The attacker gets access to sensitive data or services not meant to be public.
    

[![How Attackers Pull it Off](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2F448xotpnc40b6k2n6hhn.jpeg align="left")](https://media2.dev.to/dynamic/image/width=800%2Cheight=%2Cfit=scale-down%2Cgravity=auto%2Cformat=auto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2F448xotpnc40b6k2n6hhn.jpeg)

**Example:**  
It’s like a pizza app that lets you send pizzas to any address. But instead of your house, you type “Fire Station Locker Room.” The pizza guy (server) walks right into a restricted place just because he trusts the address.

---

## **Prevention or Solutions**

🔒 **At the Application Level:**

* Use **whitelists** for URLs or IPs, not blacklists.
    
* Block or disable unused URL schemes like [`file://`](file://), `ftp://`, `gopher://`.
    
* Enforce **authentication** for all internal services.
    
* Avoid showing raw responses to users.
    
* Disable HTTP redirects unless absolutely necessary.
    

🔐 **At the Network Level:**

* Segment your networks—internal systems should not be directly reachable.
    
* Use “**deny by default**” firewall policies.
    
* Monitor and alert on unexpected outbound requests.
    

---

## **Conclusion**

SSRF is like letting someone borrow your phone—and they secretly use it to call the bank and reset your passwords. It’s sneaky, powerful, and can bypass your best defenses. By validating inputs, restricting access, and monitoring requests, we can ensure our servers talk only to who they’re supposed to.