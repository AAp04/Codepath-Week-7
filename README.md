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

### 3. (Required) Vulnerability Name or ID

- [ ] Summary: 
  - Vulnerability types:
  - Tested in version:
  - Fixed in version: 
- [ ] GIF Walkthrough: 
- [ ] Steps to recreate: 
- [ ] Affected source code:
  - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php)

### 4. (Required) Vulnerability Name or ID
  - [x] Summary:
    - Vulnerability types: XSS (CVE-2015-5714)
    - Tested in version: 4.2 (affects versions 4.0 - 4.3
    - Fixed in version: 4.2.5
  - [x] GIF Walkthrough:

    ![Walkthrough exploit 3](https://i.imgur.com/f9XWOUo.gif)
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


### 5. (Optional) Vulnerability Name or ID

- [ ] Summary: 
  - Vulnerability types:
  - Tested in version:
  - Fixed in version: 
- [ ] GIF Walkthrough: 
- [ ] Steps to recreate: 
- [ ] Affected source code:
  - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php) 

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
