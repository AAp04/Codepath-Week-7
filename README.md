# Project 7 - WordPress Pen Testing

Time spent: **X** hours spent in total

> Objective: Find, analyze, recreate, and document **five vulnerabilities** affecting an old version of WordPress

## Pen Testing Report

### 1. (Required) Vulnerability Name or ID
  - [x] Summary:
    - Vulnerability types: XSS (CVE-2015-5714)
    - Tested in version: 4.2 (affects versions 4.0 - 4.3
    - Fixed in version: 4.2.5
  - GIF Walkthrough: ![Authenticated Persistent XSS](https://github.com/AAp04/Codepath-Week-7/blob/main/One.gif)


  - [x] Steps to recreate:
      - Sign in as an administrator
      - Create a new Post
      - Switch from Visual editing mode to Text (HTML) editing mode
      - Insert the malicious caption code

        `[caption width="1" caption='<a href="' ">]</a><a href=" onmouseover='alert("exploit!")' ">Click!</a>`
  - [x] References:
      - https://wpvulndb.com/vulnerabilities/8186
      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5714
      - https://wordpress.org/news/2015/09/wordpress-4-3-1/
      - http://blog.checkpoint.com/2015/09/15/finding-vulnerabilities-in-core-wordpress-a-bug-hunters-trilogy-part-iii-ultimatum/
      - http://blog.knownsec.com/2015/09/wordpress-vulnerability-analysis-cve-2015-5714-cve-2015-5715/

  
### 2. Persistent XSS as an authenticated user (variation of CVE-2015-3440)
  - Summary: 
    - Vulnerability types: Persistent XSS
    - Tested in version: 4.2
    - Fixed in version: Unknown
  - GIF Walkthrough: ![Authenticated Persistent XSS](https://github.com/AAp04/Codepath-Week-7/blob/main/two.gif)
  - Steps to recreate: 
    - Created a new account with editor privileges named moderator which was used for the user enumeration walkthrough.
    - Logged into moderator and navigated to the "Example front page" post.
    - Generated 65563 random bytes by issuing the following command in the terminal of Kali Linux: `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 65536`
    - Entered the following code into the `<a href=" onmouseover=alert(unescape(/xss/.source)) {enter more data here to make the overall length of the comment 64kb(65536 bytes/characters) long or greater}"`
    - Note that there is no closing bracket for the opening anchor tag nor is there a closing anchor tag.
  -  Affected source code:
    - [Klikki's exploit code](https://klikki.fi/adv/wordpress2.html)
      - [Exploit-db 36844](https://www.exploit-db.com/exploits/36844/)

### 3. User Enumeration <= 4.7.1 (CVE-2017-5487)
 - Summary: 
    - Vulnerability types: User Enumeration
    - Tested in version: 4.2
    - Fixed in version: 4.7.2
  - GIF Walkthrough: ![User Enumeration](https://github.com/AAp04/Codepath-Week-7/blob/main/three.gif)
  - Steps to recreate: 
    - Create new user(s).
    - Enter a known username such as admin or moderator in my case followed by an invalid password for that account.
    - A detailed error message appears letting a user or attacker know that there is infact an account named admin, moderator, etc.
    - Theoretically, all they would have to do is use the nifty built-in password cracker/brute-forcer via the wpscan tool in Kali by using the --wordlist option and feeding it a dictionary text or list file and one of the now known usernames (--username option).

### 4. (Required) Vulnerability Name or ID
  - [x] Summary:
    - Vulnerability types: XSS (CVE-2015-5714)
    - Tested in version: 4.2 (affects versions 4.0 - 4.3
    - Fixed in version: 4.2.5
  - GIF Walkthrough: ![User Enumeration](https://github.com/AAp04/Codepath-Week-7/blob/main/four.gif)
    ![Walkthrough exploit 3]
  - [x] Steps to recreate:
      - Sign in as an administrator
      - Create a new Post
      - Switch from Visual editing mode to Text (HTML) editing mode
      - Insert the malicious caption code

        `[caption width="1" caption='<a href="' ">]</a><a href=" onmouseover='alert("exploit!")' ">Click!</a>`
  - [x] References:
      - https://wpvulndb.com/vulnerabilities/8186
      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5714
      - https://wordpress.org/news/2015/09/wordpress-4-3-1/
      - http://blog.checkpoint.com/2015/09/15/finding-vulnerabilities-in-core-wordpress-a-bug-hunters-trilogy-part-iii-ultimatum/
      - http://blog.knownsec.com/2015/09/wordpress-vulnerability-analysis-cve-2015-5714-cve-2015-5715/


### 5. (Required) WordPress 3.6.0-4.7.2 - Authenticated Cross-Site Scripting via Media File Metadata
  - [x] Summary:
    - Vulnerability types:	XSS
    - Tested in version: 	4.2 (Released on 04/23/2015)
    - Fixed in version:		4.7.3
  - GIF Walkthrough: ![User Enumeration](https://github.com/AAp04/Codepath-Week-7/blob/main/five.gif)
  - [x] Steps to recreate:	
  	- Upload a media file containing exploit in form of Metadata.
	- If it doesn't contain Metadata already, we can add it in description of the media file on admin console.
	- Add "filename </noscript><script>alert("Exploit 3 Successful");</script>" in the description including quotes.
	- View attachment page and our alert box will pop up.


## Assets

List any additional assets, such as scripts or files

## Resources

- [WordPress Source Browser](https://core.trac.wordpress.org/browser/)
- [WordPress Developer Reference](https://developer.wordpress.org/reference/)

GIFs created with  ...
<!-- Recommended GIF Tools:
[Kap](https://getkap.co/) for macOS
[ScreenToGif](https://www.screentogif.com/) for Windows
[peek](https://github.com/phw/peek) for Linux. -->

## Notes

This was one of teh hardest project.

## License

    Copyright [yyyy] [name of copyright owner]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
